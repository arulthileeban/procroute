package daemon

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

// Sweeper watches for epoch changes and kills stale TCP connections
type Sweeper struct {
	interval         time.Duration
	internalPrefixV4 *ebpf.Map
	cgroupToApp      *ebpf.Map
	appAllowV4       *ebpf.Map
	authEpoch        *ebpf.Map
	lastEpoch        uint64
}

func NewSweeper(interval time.Duration, intPfx, cgToApp, appAllow, authEpoch *ebpf.Map) *Sweeper {
	return &Sweeper{
		interval:         interval,
		internalPrefixV4: intPfx,
		cgroupToApp:      cgToApp,
		appAllowV4:       appAllow,
		authEpoch:        authEpoch,
		lastEpoch:        0,
	}
}


func (s *Sweeper) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	if s.authEpoch != nil {
		var key uint32
		var cur uint64
		if err := s.authEpoch.Lookup(&key, &cur); err == nil {
			s.lastEpoch = cur
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if !s.epochChanged() {
				continue
			}
			killed, err := s.sweep()
			if err != nil {
				fmt.Fprintf(os.Stderr, "sweeper: %v\n", err)
			}
			if killed > 0 {
				fmt.Fprintf(os.Stderr, "sweeper: terminated %d stale socket(s)\n", killed)
			}
		}
	}
}


func (s *Sweeper) epochChanged() bool {
	if s.authEpoch == nil {
		return true // no epoch map, always sweep (fallback)
	}
	var key uint32
	var cur uint64
	if err := s.authEpoch.Lookup(&key, &cur); err != nil {
		return false
	}
	if cur != s.lastEpoch {
		s.lastEpoch = cur
		return true
	}
	return false
}

func (s *Sweeper) SweepOnce() (int, error) {
	return s.sweep()
}

// sweep scans /proc/net/tcp and kills connections to internal prefixes
func (s *Sweeper) sweep() (int, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return 0, fmt.Errorf("opening /proc/net/tcp: %w", err)
	}
	defer f.Close()

	killed := 0
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // skip header
		}

		line := scanner.Text()
		entry, err := parseProcNetTCP(line)
		if err != nil {
			continue
		}

		if entry.state != 1 {
			continue
		}

		if !s.isInternal(entry.remoteAddr) {
			continue
		}

		// Check if this socket's connection is still authorized
		// We use inode -> cgroup -> app -> grant check
		// TODO: resolve cgroup and re-check BPF maps instead of killing blindly
		dst := fmt.Sprintf("%s:%d", entry.remoteAddr, entry.remotePort)
		cmd := exec.Command("ss", "--kill", "state", "established",
			"dst", dst)
		if err := cmd.Run(); err != nil {
			// ss --kill may fail if socket already closed
			continue
		}
		killed++
	}

	return killed, scanner.Err()
}


func (s *Sweeper) isInternal(addr netip.Addr) bool {
	if !addr.Is4() {
		return false // PoC: IPv4 only
	}
	a4 := addr.As4()
	key := LPMKeyV4{PrefixLen: 32, Addr: a4}
	var val uint8
	err := s.internalPrefixV4.Lookup(&key, &val)
	return err == nil
}

type procNetTCPEntry struct {
	localAddr  netip.Addr
	localPort  uint16
	remoteAddr netip.Addr
	remotePort uint16
	state      int
	inode      uint64
}

func parseProcNetTCP(line string) (procNetTCPEntry, error) {
	var e procNetTCPEntry
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return e, fmt.Errorf("too few fields")
	}

	laddr, lport, err := parseHexAddr(fields[1])
	if err != nil {
		return e, err
	}
	e.localAddr = laddr
	e.localPort = lport

	raddr, rport, err := parseHexAddr(fields[2])
	if err != nil {
		return e, err
	}
	e.remoteAddr = raddr
	e.remotePort = rport

	st, err := strconv.ParseInt(fields[3], 16, 32)
	if err != nil {
		return e, err
	}
	e.state = int(st)

	if len(fields) > 9 {
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err == nil {
			e.inode = inode
		}
	}

	return e, nil
}

func parseHexAddr(s string) (netip.Addr, uint16, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return netip.Addr{}, 0, fmt.Errorf("invalid addr:port %q", s)
	}

	// IP is in little-endian hex (reversed byte order on x86)
	ipHex := parts[0]
	if len(ipHex) != 8 {
		return netip.Addr{}, 0, fmt.Errorf("invalid IP hex length %d", len(ipHex))
	}
	b, err := parseHexBytes(ipHex)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	// /proc/net/tcp stores IPv4 in host byte order (little-endian on x86)
	addr := netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]})

	portNum, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("invalid port %q: %w", parts[1], err)
	}

	return addr, uint16(portNum), nil
}

func parseHexBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex string length")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		v, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		b[i/2] = byte(v)
	}
	return b, nil
}

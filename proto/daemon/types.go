package daemon

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// BPF struct mirrors -- keep in sync with common.h
type LPMKeyV4 struct {
	PrefixLen uint32
	Addr      [4]byte // network byte order
}

type LPMKeyV6 struct {
	PrefixLen uint32
	Addr      [16]byte // network byte order
}

type AppLPMKeyV4 struct {
	PrefixLen uint32
	AppIndex  uint32
	Addr      [4]byte // network byte order
}

type AppLPMKeyV6 struct {
	PrefixLen uint32
	AppIndex  uint32
	Addr      [16]byte // network byte order
}

type AllowRule struct {
	PortLo   uint16
	PortHi   uint16
	Protocol uint8
	_        [3]byte
}

type DenyEvent struct {
	TimestampNS uint64
	CgroupID    uint64
	PID         uint32
	UID         uint32
	Comm        [16]byte
	AF          uint8
	Proto       uint8
	DstPort     uint16
	DstAddr     [16]byte // v4 uses first 4 bytes
	AppIndex    uint32
}

func (e *DenyEvent) DstIP() netip.Addr {
	if e.AF == 2 { // AF_INET
		return netip.AddrFrom4([4]byte{e.DstAddr[0], e.DstAddr[1], e.DstAddr[2], e.DstAddr[3]})
	}
	return netip.AddrFrom16(e.DstAddr)
}

func (e *DenyEvent) ProtoString() string {
	switch e.Proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("%d", e.Proto)
	}
}

func (e *DenyEvent) CommString() string {
	n := 0
	for i, b := range e.Comm {
		if b == 0 {
			break
		}
		n = i + 1
	}
	return string(e.Comm[:n])
}

func PrefixToLPMKeyV4(p netip.Prefix) LPMKeyV4 {
	a4 := p.Addr().As4()
	return LPMKeyV4{
		PrefixLen: uint32(p.Bits()),
		Addr:      a4,
	}
}

func PrefixToLPMKeyV6(p netip.Prefix) LPMKeyV6 {
	a16 := p.Addr().As16()
	return LPMKeyV6{
		PrefixLen: uint32(p.Bits()),
		Addr:      a16,
	}
}

func PrefixToAppLPMKeyV4(appIndex uint32, p netip.Prefix) AppLPMKeyV4 {
	a4 := p.Addr().As4()
	return AppLPMKeyV4{
		PrefixLen: 32 + uint32(p.Bits()), // 32 bits for app_index + prefix bits
		AppIndex:  appIndex,
		Addr:      a4,
	}
}

func PrefixToAppLPMKeyV6(appIndex uint32, p netip.Prefix) AppLPMKeyV6 {
	a16 := p.Addr().As16()
	return AppLPMKeyV6{
		PrefixLen: 32 + uint32(p.Bits()), // 32 bits for app_index + prefix bits
		AppIndex:  appIndex,
		Addr:      a16,
	}
}

func ParseCIDR(cidr string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		// Try net.ParseCIDR for formats netip doesn't handle
		_, ipnet, err2 := net.ParseCIDR(cidr)
		if err2 != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		ones, _ := ipnet.Mask.Size()
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("invalid IP in CIDR %q", cidr)
		}
		p = netip.PrefixFrom(addr.Unmap(), ones)
	}
	return p.Masked(), nil
}

func ProtoNumber(proto string) uint8 {
	switch proto {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "any", "":
		return 0
	default:
		return 0
	}
}

func HostToNetShort(v uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return binary.NativeEndian.Uint16(b)
}

type ExecHashValue struct {
	Hash [32]byte
}

type ExecEvent struct {
	TimestampNS uint64
	CgroupID    uint64
	TGID        uint32
	AppIndex    uint32
	Comm        [16]byte
}

func (e *ExecEvent) CommString() string {
	n := 0
	for i, b := range e.Comm {
		if b == 0 {
			break
		}
		n = i + 1
	}
	return string(e.Comm[:n])
}

type GatewayDenyEvent struct {
	TimestampNS uint64
	SrcIP       uint32 // network byte order
	DstIP       uint32 // network byte order
	SrcPort     uint16 // host byte order
	DstPort     uint16 // host byte order
	AppIndex    uint32
	Proto       uint8
	_           [7]byte
}

func (e *GatewayDenyEvent) SrcAddr() netip.Addr {
	b := [4]byte{
		byte(e.SrcIP), byte(e.SrcIP >> 8),
		byte(e.SrcIP >> 16), byte(e.SrcIP >> 24),
	}
	return netip.AddrFrom4(b)
}

func (e *GatewayDenyEvent) DstAddr() netip.Addr {
	b := [4]byte{
		byte(e.DstIP), byte(e.DstIP >> 8),
		byte(e.DstIP >> 16), byte(e.DstIP >> 24),
	}
	return netip.AddrFrom4(b)
}

func (e *GatewayDenyEvent) ProtoString() string {
	switch e.Proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("%d", e.Proto)
	}
}

type GatewayDenyEventV6 struct {
	TimestampNS uint64
	SrcIP       [16]byte // network byte order
	DstIP       [16]byte // network byte order
	SrcPort     uint16   // host byte order
	DstPort     uint16   // host byte order
	AppIndex    uint32
	Proto       uint8
	_           [7]byte
}

func (e *GatewayDenyEventV6) SrcAddr() netip.Addr {
	return netip.AddrFrom16(e.SrcIP)
}

func (e *GatewayDenyEventV6) DstAddr() netip.Addr {
	return netip.AddrFrom16(e.DstIP)
}

func (e *GatewayDenyEventV6) ProtoString() string {
	switch e.Proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("%d", e.Proto)
	}
}

const (
	HookLatBuckets  = 22
	HookLatOutcomes = 3
	HookLatMapSize  = HookLatOutcomes*HookLatBuckets + HookLatOutcomes

	OutcomeExtMiss  = 0
	OutcomeIntAllow = 1
	OutcomeIntDeny  = 2
)

func ParseExecHash(s string) ([32]byte, error) {
	var h [32]byte
	if !strings.HasPrefix(s, "sha256:") {
		return h, fmt.Errorf("exec_hash must start with \"sha256:\", got %q", s)
	}
	hexStr := strings.TrimPrefix(s, "sha256:")
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return h, fmt.Errorf("invalid hex in exec_hash: %w", err)
	}
	if len(b) != 32 {
		return h, fmt.Errorf("exec_hash must be 32 bytes (64 hex chars), got %d bytes", len(b))
	}
	copy(h[:], b)
	return h, nil
}

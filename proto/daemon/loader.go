package daemon

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Loader struct {
	objs  *procrouteObjects
	links []link.Link
}

func NewLoader() *Loader {
	return &Loader{}
}

func (l *Loader) Load() error {
	l.objs = &procrouteObjects{}
	if err := loadProcrouteObjects(l.objs, nil); err != nil {
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	return nil
}

// Attach hooks + tracepoints to the given cgroup.
func (l *Loader) Attach(cgroupPath string) error {
	f, err := os.Open(cgroupPath)
	if err != nil {
		return fmt.Errorf("opening cgroup %s: %w", cgroupPath, err)
	}
	defer f.Close()

	type progInfo struct {
		name string
		prog *ebpf.Program
		typ  ebpf.AttachType
	}

	progs := []progInfo{
		{"connect4", l.objs.ProcrouteConnect4, ebpf.AttachCGroupInet4Connect},
		{"connect6", l.objs.ProcrouteConnect6, ebpf.AttachCGroupInet6Connect},
		{"sendmsg4", l.objs.ProcrouteSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{"sendmsg6", l.objs.ProcrouteSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
	}

	for _, p := range progs {
		lnk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  p.typ,
			Program: p.prog,
		})
		if err != nil {
			return fmt.Errorf("attaching %s to %s: %w", p.name, cgroupPath, err)
		}
		l.links = append(l.links, lnk)
		fmt.Fprintf(os.Stderr, "attached %s to %s\n", p.name, cgroupPath)
	}

	type tpInfo struct {
		group string
		name  string
		prog  *ebpf.Program
	}
	tracepoints := []tpInfo{
		{"sched", "sched_process_exec", l.objs.ProcrouteExec},
		{"sched", "sched_process_exit", l.objs.ProcrouteExit},
	}
	for _, tp := range tracepoints {
		lnk, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint %s/%s: %w", tp.group, tp.name, err)
		}
		l.links = append(l.links, lnk)
		fmt.Fprintf(os.Stderr, "attached tracepoint %s/%s\n", tp.group, tp.name)
	}

	return nil
}

// AttachTagOnly is like Attach but non-enforcing.
func (l *Loader) AttachTagOnly(cgroupPath string) error {
	f, err := os.Open(cgroupPath)
	if err != nil {
		return fmt.Errorf("opening cgroup %s: %w", cgroupPath, err)
	}
	defer f.Close()

	type progInfo struct {
		name string
		prog *ebpf.Program
		typ  ebpf.AttachType
	}
	progs := []progInfo{
		{"tag_connect4", l.objs.ProcrouteTagConnect4, ebpf.AttachCGroupInet4Connect},
		{"tag_connect6", l.objs.ProcrouteTagConnect6, ebpf.AttachCGroupInet6Connect},
		{"tag_sendmsg4", l.objs.ProcrouteTagSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{"tag_sendmsg6", l.objs.ProcrouteTagSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, p := range progs {
		lnk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  p.typ,
			Program: p.prog,
		})
		if err != nil {
			return fmt.Errorf("attaching %s: %w", p.name, err)
		}
		l.links = append(l.links, lnk)
	}

	// same tracepoints as Attach
	type tpInfo struct {
		group, name string
		prog        *ebpf.Program
	}
	tracepoints := []tpInfo{
		{"sched", "sched_process_exec", l.objs.ProcrouteExec},
		{"sched", "sched_process_exit", l.objs.ProcrouteExit},
	}
	for _, tp := range tracepoints {
		lnk, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			return fmt.Errorf("tracepoint %s/%s: %w", tp.group, tp.name, err)
		}
		l.links = append(l.links, lnk)
	}

	return nil
}

func (l *Loader) PopulateInternalPrefixes(v4 []netip.Prefix, v6 []netip.Prefix) error {
	val := uint8(1)

	for _, p := range v4 {
		key := PrefixToLPMKeyV4(p)
		if err := l.objs.InternalPrefixesV4.Put(&key, &val); err != nil {
			return fmt.Errorf("inserting internal prefix %s: %w", p, err)
		}
	}

	for _, p := range v6 {
		key := PrefixToLPMKeyV6(p)
		if err := l.objs.InternalPrefixesV6.Put(&key, &val); err != nil {
			return fmt.Errorf("inserting internal prefix %s: %w", p, err)
		}
	}

	return nil
}

func (l *Loader) PopulateCgroupToApp(inodes map[string]uint64, appIndices map[string]uint32) error {
	for appID, inode := range inodes {
		idx, ok := appIndices[appID]
		if !ok {
			return fmt.Errorf("no app index for %s", appID)
		}
		if err := l.objs.CgroupToApp.Put(&inode, &idx); err != nil {
			return fmt.Errorf("inserting cgroup->app mapping for %s (inode %d -> idx %d): %w",
				appID, inode, idx, err)
		}
	}
	return nil
}

func (l *Loader) PopulateAppAllowRules(pol *Policy, appIndices map[string]uint32) error {
	for _, app := range pol.Applications {
		idx := appIndices[app.AppID]

		for _, rule := range app.Allow {
			proto := ProtoNumber(rule.Protocol)

			// Determine port ranges to insert
			type portRange struct {
				lo, hi uint16
			}
			var ranges []portRange

			if len(rule.Ports) == 0 {
				// All ports: lo=0, hi=0 signals "any" in BPF
				ranges = append(ranges, portRange{0, 0})
			} else {
				for _, pv := range rule.Ports {
					lo, hi, err := pv.PortRange()
					if err != nil {
						return fmt.Errorf("app %s: %w", app.AppID, err)
					}
					ranges = append(ranges, portRange{lo, hi})
				}
			}

			for _, cidr := range rule.Prefixes {
				prefix, err := ParseCIDR(cidr)
				if err != nil {
					return fmt.Errorf("app %s: %w", app.AppID, err)
				}

				// PoC: use first port range; widen if multiple (see below)
				ar := AllowRule{
					PortLo:   ranges[0].lo,
					PortHi:   ranges[0].hi,
					Protocol: proto,
				}

				if prefix.Addr().Is4() {
					key := PrefixToAppLPMKeyV4(idx, prefix)
					if err := l.objs.AppAllowV4.Put(&key, &ar); err != nil {
						return fmt.Errorf("inserting app allow v4 %s %s: %w",
							app.AppID, prefix, err)
					}
				} else {
					key := PrefixToAppLPMKeyV6(idx, prefix)
					if err := l.objs.AppAllowV6.Put(&key, &ar); err != nil {
						return fmt.Errorf("inserting app allow v6 %s %s: %w",
							app.AppID, prefix, err)
					}
				}
			}

			// multiple port ranges on same prefix: widen to cover all
			if len(ranges) > 1 {
				// Widen to cover all ranges
				lo := ranges[0].lo
				hi := ranges[0].hi
				for _, r := range ranges[1:] {
					if r.lo < lo {
						lo = r.lo
					}
					if r.hi > hi {
						hi = r.hi
					}
				}
				ar := AllowRule{
					PortLo:   lo,
					PortHi:   hi,
					Protocol: proto,
				}
				for _, cidr := range rule.Prefixes {
					prefix, _ := ParseCIDR(cidr)
					if prefix.Addr().Is4() {
						key := PrefixToAppLPMKeyV4(idx, prefix)
						l.objs.AppAllowV4.Put(&key, &ar)
					} else {
						key := PrefixToAppLPMKeyV6(idx, prefix)
						l.objs.AppAllowV6.Put(&key, &ar)
					}
				}
			}
		}
	}
	return nil
}

func (l *Loader) PopulateExemptPorts(ports []int) error {
	val := uint8(1)
	for _, p := range ports {
		port := uint16(p)
		if err := l.objs.ExemptPorts.Put(&port, &val); err != nil {
			return fmt.Errorf("inserting exempt port %d: %w", p, err)
		}
	}
	return nil
}

// PopulateAppExecHashes loads exec hashes for apps that have them.
func (l *Loader) PopulateAppExecHashes(pol *Policy, appIndices map[string]uint32) error {
	for _, app := range pol.Applications {
		if app.Match.ExecHash == "" {
			continue
		}
		hash, err := ParseExecHash(app.Match.ExecHash)
		if err != nil {
			return fmt.Errorf("app %s: %w", app.AppID, err)
		}
		idx := appIndices[app.AppID]
		val := ExecHashValue{Hash: hash}
		if err := l.objs.AppExecHash.Put(&idx, &val); err != nil {
			return fmt.Errorf("inserting exec hash for app %s (idx %d): %w",
				app.AppID, idx, err)
		}
		fmt.Fprintf(os.Stderr, "loaded exec_hash for app %s (idx %d)\n", app.AppID, idx)
	}
	return nil
}

// Map/program accessors
func (l *Loader) DenyEventsMap() *ebpf.Map         { return l.objs.DenyEvents }
func (l *Loader) ExecEventsMap() *ebpf.Map         { return l.objs.ExecEvents }
func (l *Loader) TaskVerifiedMap() *ebpf.Map       { return l.objs.TaskVerified }
func (l *Loader) AppExecHashMap() *ebpf.Map        { return l.objs.AppExecHash }
func (l *Loader) InternalPrefixesV4Map() *ebpf.Map { return l.objs.InternalPrefixesV4 }
func (l *Loader) CgroupToAppMap() *ebpf.Map        { return l.objs.CgroupToApp }
func (l *Loader) AppAllowV4Map() *ebpf.Map         { return l.objs.AppAllowV4 }
func (l *Loader) HookLatencyMap() *ebpf.Map        { return l.objs.HookLatency }
func (l *Loader) AuthEpochMap() *ebpf.Map          { return l.objs.AuthEpoch }
func (l *Loader) SocketAuthMap() *ebpf.Map         { return l.objs.SocketAuth }
func (l *Loader) RevokeEventsMap() *ebpf.Map       { return l.objs.RevokeEvents }
func (l *Loader) SocketToAppMap() *ebpf.Map        { return l.objs.SocketToApp }
func (l *Loader) WgTagEgressProgram() *ebpf.Program { return l.objs.ProcrouteWgTagEgress }

// AttachTCEgress hooks TC egress on the given interface (needs TCX, kernel >= 6.6).
func (l *Loader) AttachTCEgress(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifaceName, err)
	}

	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   l.objs.ProcrouteWgTagEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attaching tc egress to %s (ifindex %d): %w",
			ifaceName, iface.Index, err)
	}
	l.links = append(l.links, lnk)
	fmt.Fprintf(os.Stderr, "attached tc egress tagger to %s (ifindex %d)\n", ifaceName, iface.Index)
	return nil
}

// AttachTCIngress hooks TC ingress on the given interface.
func (l *Loader) AttachTCIngress(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifaceName, err)
	}

	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   l.objs.ProcrouteWgEnforceIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attaching tc ingress to %s (ifindex %d): %w",
			ifaceName, iface.Index, err)
	}
	l.links = append(l.links, lnk)
	fmt.Fprintf(os.Stderr, "attached tc ingress enforcer to %s (ifindex %d)\n", ifaceName, iface.Index)
	return nil
}

func (l *Loader) AttachTCEgressV6(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifaceName, err)
	}

	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   l.objs.ProcrouteWgTagEgressV6,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		return fmt.Errorf("attaching tc egress v6 to %s (ifindex %d): %w",
			ifaceName, iface.Index, err)
	}
	l.links = append(l.links, lnk)
	fmt.Fprintf(os.Stderr, "attached tc egress v6 tagger to %s (ifindex %d)\n", ifaceName, iface.Index)
	return nil
}

func (l *Loader) AttachTCIngressV6(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifaceName, err)
	}

	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   l.objs.ProcrouteWgEnforceIngressV6,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attaching tc ingress v6 to %s (ifindex %d): %w",
			ifaceName, iface.Index, err)
	}
	l.links = append(l.links, lnk)
	fmt.Fprintf(os.Stderr, "attached tc ingress v6 enforcer to %s (ifindex %d)\n", ifaceName, iface.Index)
	return nil
}

func (l *Loader) GwDenyEventsMap() *ebpf.Map   { return l.objs.GwDenyEvents }
func (l *Loader) FlowCacheV6Map() *ebpf.Map    { return l.objs.FlowCacheV6 }
func (l *Loader) GwDenyEventsV6Map() *ebpf.Map { return l.objs.GwDenyEventsV6 }
func (l *Loader) FlowCacheMap() *ebpf.Map      { return l.objs.FlowCache }
func (l *Loader) FlowCacheConfigMap() *ebpf.Map { return l.objs.FlowCacheConfig }
func (l *Loader) FlowCacheStatsMap() *ebpf.Map  { return l.objs.FlowCacheStats }


func (l *Loader) SetFlowCacheEnabled(enabled bool) error {
	var key uint32 = 0
	var val uint8 = 0
	if enabled {
		val = 1
	}
	if err := l.objs.FlowCacheConfig.Put(&key, &val); err != nil {
		return fmt.Errorf("setting flow cache config: %w", err)
	}
	return nil
}

// ReadFlowCacheStats aggregates per-CPU flow cache counters.
func (l *Loader) ReadFlowCacheStats() (hits, misses, inserts uint64, err error) {
	for i := uint32(0); i < 3; i++ {
		var perCPU []uint64
		if err = l.objs.FlowCacheStats.Lookup(&i, &perCPU); err != nil {
			return 0, 0, 0, fmt.Errorf("reading flow cache stats[%d]: %w", i, err)
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		switch i {
		case 0:
			hits = total
		case 1:
			misses = total
		case 2:
			inserts = total
		}
	}
	return hits, misses, inserts, nil
}

// IncrementEpoch bumps the epoch and returns the new value.
func (l *Loader) IncrementEpoch() (uint64, error) {
	var key uint32 = 0
	var cur uint64
	if err := l.objs.AuthEpoch.Lookup(&key, &cur); err != nil {
		cur = 0 // first use
	}
	next := cur + 1
	if err := l.objs.AuthEpoch.Put(&key, &next); err != nil {
		return 0, fmt.Errorf("incrementing epoch: %w", err)
	}
	return next, nil
}

func (l *Loader) Close() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	if l.objs != nil {
		l.objs.Close()
	}
}

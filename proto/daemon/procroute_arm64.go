// Identical to procroute_amd64.go -- provides the same types and loader
// for arm64 builds.  See procroute_amd64.go for details.

package daemon

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// procrouteObjects contains all BPF objects after loading.
type procrouteObjects struct {
	procroutePrograms
	procrouteMaps
}

type procroutePrograms struct {
	ProcrouteConnect4    *ebpf.Program `ebpf:"procroute_connect4"`
	ProcrouteConnect6    *ebpf.Program `ebpf:"procroute_connect6"`
	ProcrouteSendmsg4    *ebpf.Program `ebpf:"procroute_sendmsg4"`
	ProcrouteSendmsg6    *ebpf.Program `ebpf:"procroute_sendmsg6"`
	ProcrouteTagConnect4 *ebpf.Program `ebpf:"procroute_tag_connect4"`
	ProcrouteTagConnect6 *ebpf.Program `ebpf:"procroute_tag_connect6"`
	ProcrouteTagSendmsg4 *ebpf.Program `ebpf:"procroute_tag_sendmsg4"`
	ProcrouteTagSendmsg6 *ebpf.Program `ebpf:"procroute_tag_sendmsg6"`
	ProcrouteWgTagEgress      *ebpf.Program `ebpf:"procroute_wg_tag_egress"`
	ProcrouteWgEnforceIngress *ebpf.Program `ebpf:"procroute_wg_enforce_ingress"`
	ProcrouteWgTagEgressV6      *ebpf.Program `ebpf:"procroute_wg_tag_egress_v6"`
	ProcrouteWgEnforceIngressV6 *ebpf.Program `ebpf:"procroute_wg_enforce_ingress_v6"`
	ProcrouteExec             *ebpf.Program `ebpf:"procroute_exec"`
	ProcrouteExit             *ebpf.Program `ebpf:"procroute_exit"`
}

type procrouteMaps struct {
	InternalPrefixesV4 *ebpf.Map `ebpf:"internal_prefixes_v4"`
	InternalPrefixesV6 *ebpf.Map `ebpf:"internal_prefixes_v6"`
	CgroupToApp        *ebpf.Map `ebpf:"cgroup_to_app"`
	AppAllowV4         *ebpf.Map `ebpf:"app_allow_v4"`
	AppAllowV6         *ebpf.Map `ebpf:"app_allow_v6"`
	DenyEvents         *ebpf.Map `ebpf:"deny_events"`
	AppExecHash        *ebpf.Map `ebpf:"app_exec_hash"`
	TaskVerified       *ebpf.Map `ebpf:"task_verified"`
	ExecEvents         *ebpf.Map `ebpf:"exec_events"`
	AuthEpoch          *ebpf.Map `ebpf:"auth_epoch"`
	SocketAuth         *ebpf.Map `ebpf:"socket_auth"`
	RevokeEvents       *ebpf.Map `ebpf:"revoke_events"`
	HookLatency        *ebpf.Map `ebpf:"hook_latency"`
	SocketToApp        *ebpf.Map `ebpf:"socket_to_app"`
	FlowCache          *ebpf.Map `ebpf:"flow_cache"`
	GwDenyEvents       *ebpf.Map `ebpf:"gw_deny_events"`
	FlowCacheV6        *ebpf.Map `ebpf:"flow_cache_v6"`
	GwDenyEventsV6     *ebpf.Map `ebpf:"gw_deny_events_v6"`
	FlowCacheConfig    *ebpf.Map `ebpf:"flow_cache_config"`
	FlowCacheStats     *ebpf.Map `ebpf:"flow_cache_stats"`
	ExemptPorts        *ebpf.Map `ebpf:"exempt_ports"`
}

func (o *procrouteObjects) Close() error {
	return _procrouteClose(
		&o.procroutePrograms,
		&o.procrouteMaps,
	)
}

func _procrouteClose(closers ...interface{ Close() error }) error {
	for _, c := range closers {
		c.Close()
	}
	return nil
}

func (p *procroutePrograms) Close() error {
	progs := []*ebpf.Program{
		p.ProcrouteConnect4,
		p.ProcrouteConnect6,
		p.ProcrouteSendmsg4,
		p.ProcrouteSendmsg6,
		p.ProcrouteTagConnect4,
		p.ProcrouteTagConnect6,
		p.ProcrouteTagSendmsg4,
		p.ProcrouteTagSendmsg6,
		p.ProcrouteWgTagEgress,
		p.ProcrouteWgEnforceIngress,
		p.ProcrouteWgTagEgressV6,
		p.ProcrouteWgEnforceIngressV6,
		p.ProcrouteExec,
		p.ProcrouteExit,
	}
	for _, prog := range progs {
		if prog != nil {
			prog.Close()
		}
	}
	return nil
}

func (m *procrouteMaps) Close() error {
	maps := []*ebpf.Map{
		m.InternalPrefixesV4,
		m.InternalPrefixesV6,
		m.CgroupToApp,
		m.AppAllowV4,
		m.AppAllowV6,
		m.DenyEvents,
		m.AppExecHash,
		m.TaskVerified,
		m.ExecEvents,
		m.AuthEpoch,
		m.SocketAuth,
		m.RevokeEvents,
		m.HookLatency,
		m.SocketToApp,
		m.FlowCache,
		m.GwDenyEvents,
		m.FlowCacheV6,
		m.GwDenyEventsV6,
		m.FlowCacheConfig,
		m.FlowCacheStats,
		m.ExemptPorts,
	}
	for _, mp := range maps {
		if mp != nil {
			mp.Close()
		}
	}
	return nil
}

// loadProcrouteObjects loads BPF programs and maps from the compiled ELF.
func loadProcrouteObjects(obj *procrouteObjects, opts *ebpf.CollectionOptions) error {
	spec, err := loadProcroute()
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(obj, opts)
}

// loadProcroute loads the BPF collection spec from the embedded ELF.
func loadProcroute() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(procrouteELFPath())
	if err != nil {
		return nil, fmt.Errorf("loading BPF ELF: %w", err)
	}
	return spec, nil
}

// procrouteELFPath returns the path to the compiled BPF ELF object.
// When bpf2go is used, this is embedded. For the PoC, we load from disk.
func procrouteELFPath() string {
	return "bpf/procroute.o"
}

// Ensure link package is imported (used by loader.go).
var _ = link.AttachCgroup

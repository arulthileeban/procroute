package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Run() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "daemon":
		runDaemon()
	case "launch":
		runLaunch()
	case "wg-client":
		runWgClient()
	case "wg-gateway":
		runWgGateway()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: procroute <command> [options]

Commands:
  daemon      Load BPF programs, enforce policy, stream deny logs
  launch      Move into an app cgroup and exec a command
  wg-client   Tag-only mode for WireGuard client: tag sockets + tc egress
  wg-gateway  Gateway enforcement: tc ingress policy on WireGuard interface

Daemon options:
  --policy <path>    Path to policy YAML file (required)
  --mode <mode>      Enforcement mode: "enforce" (default) or "tag-only"
                     tag-only: tag sockets with app identity without blocking

WG-client options:
  --policy <path>    Path to policy YAML file (required)
  --iface <name>     WireGuard interface to attach tc egress tagger (required)

WG-gateway options:
  --policy <path>    Path to policy YAML file (required)
  --iface <name>     WireGuard interface to attach tc ingress enforcer (required)
  --no-flow-cache    Disable the flow cache (forces slow-path on every packet)

Launch options:
  --app <app_id>     Application ID to run as (required)
  --policy <path>    Path to policy YAML file (required)
  -- <cmd> [args]    Command to execute
`)
}

func runDaemon() {
	policyPath := ""
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--policy" && i+1 < len(os.Args) {
			policyPath = os.Args[i+1]
			i++
		}
	}

	if policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --policy is required")
		os.Exit(1)
	}

	pol, err := LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "loaded policy: %d internal prefixes, %d applications\n",
		len(pol.InternalPrefixes), len(pol.Applications))

	v4Prefixes, v6Prefixes, err := pol.ParsedInternalPrefixes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing prefixes: %v\n", err)
		os.Exit(1)
	}

	inodes, err := EnsureCgroupHierarchy(pol.Applications)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating cgroups: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "created cgroup hierarchy with %d app cgroups\n", len(inodes))

	// 1-based; 0 = unassigned
	appIndices := make(map[string]uint32)
	for i, app := range pol.Applications {
		appIndices[app.AppID] = uint32(i + 1)
	}

	loader := NewLoader()
	if err := loader.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "error loading BPF: %v\n", err)
		os.Exit(1)
	}
	defer loader.Close()
	fmt.Fprintln(os.Stderr, "BPF programs loaded")

	if err := loader.PopulateInternalPrefixes(v4Prefixes, v6Prefixes); err != nil {
		fmt.Fprintf(os.Stderr, "error populating internal prefixes: %v\n", err)
		os.Exit(1)
	}

	if err := loader.PopulateCgroupToApp(inodes, appIndices); err != nil {
		fmt.Fprintf(os.Stderr, "error populating cgroup->app map: %v\n", err)
		os.Exit(1)
	}

	if err := loader.PopulateAppAllowRules(pol, appIndices); err != nil {
		fmt.Fprintf(os.Stderr, "error populating allow rules: %v\n", err)
		os.Exit(1)
	}

	if err := loader.PopulateAppExecHashes(pol, appIndices); err != nil {
		fmt.Fprintf(os.Stderr, "error populating exec hashes: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "BPF maps populated")

	cgroupPath := CgroupBasePath()
	if err := loader.Attach(cgroupPath); err != nil {
		fmt.Fprintf(os.Stderr, "error attaching BPF programs: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "BPF programs attached to %s\n", cgroupPath)

	for appID, inode := range inodes {
		fmt.Fprintf(os.Stderr, "  %s -> cgroup inode %d, app_index %d\n",
			appID, inode, appIndices[appID])
	}

	epoch, err := loader.IncrementEpoch()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: initializing epoch: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "authorization epoch initialized to %d\n", epoch)
	}

	fmt.Fprintln(os.Stderr, "daemon ready -- streaming deny events (JSON to stdout)")

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	hv := NewHashVerifier(loader.TaskVerifiedMap(), loader.AppExecHashMap())
	go func() {
		if err := hv.StreamExecEvents(ctx, loader.ExecEventsMap()); err != nil {
			fmt.Fprintf(os.Stderr, "error streaming exec events: %v\n", err)
		}
	}()

	sw := NewSweeper(1*time.Second, loader.InternalPrefixesV4Map(),
		loader.CgroupToAppMap(), loader.AppAllowV4Map(), loader.AuthEpochMap())
	go func() {
		if err := sw.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "sweeper error: %v\n", err)
		}
	}()

	if err := StreamDenyEvents(ctx, loader.DenyEventsMap()); err != nil {
		fmt.Fprintf(os.Stderr, "error streaming events: %v\n", err)
	}

	fmt.Fprintln(os.Stderr, "\nshutting down...")
	loader.Close()
	CleanupCgroups(pol.Applications)
	fmt.Fprintln(os.Stderr, "done")
}

func runWgClient() {
	policyPath := ""
	ifaceName := ""
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--policy":
			if i+1 < len(os.Args) {
				policyPath = os.Args[i+1]
				i++
			}
		case "--iface":
			if i+1 < len(os.Args) {
				ifaceName = os.Args[i+1]
				i++
			}
		}
	}

	if policyPath == "" || ifaceName == "" {
		fmt.Fprintln(os.Stderr, "error: --policy and --iface are required")
		fmt.Fprintln(os.Stderr, "usage: procroute wg-client --policy <path> --iface <wg_iface>")
		os.Exit(1)
	}

	pol, err := LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "loaded policy: %d internal prefixes, %d applications\n",
		len(pol.InternalPrefixes), len(pol.Applications))

	v4Prefixes, v6Prefixes, err := pol.ParsedInternalPrefixes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad prefix: %v\n", err)
		os.Exit(1)
	}

	inodes, err := EnsureCgroupHierarchy(pol.Applications)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating cgroups: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "created cgroup hierarchy with %d app cgroups\n", len(inodes))

	// 1-based; 0 = unassigned
	appIndices := make(map[string]uint32)
	for i, app := range pol.Applications {
		appIndices[app.AppID] = uint32(i + 1)
	}

	loader := NewLoader()
	if err := loader.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "error loading BPF: %v\n", err)
		os.Exit(1)
	}
	defer loader.Close()
	fmt.Fprintln(os.Stderr, "BPF loaded")

	if err := loader.PopulateInternalPrefixes(v4Prefixes, v6Prefixes); err != nil {
		fmt.Fprintf(os.Stderr, "populating prefixes: %v\n", err)
		os.Exit(1)
	}

	if err := loader.PopulateCgroupToApp(inodes, appIndices); err != nil {
		fmt.Fprintf(os.Stderr, "error populating cgroup->app map: %v\n", err)
		os.Exit(1)
	}

	if err := loader.PopulateAppExecHashes(pol, appIndices); err != nil {
		fmt.Fprintf(os.Stderr, "error populating exec hashes: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "maps ready")

	cgroupPath := CgroupBasePath()
	if err := loader.AttachTagOnly(cgroupPath); err != nil {
		fmt.Fprintf(os.Stderr, "error attaching tag-only programs: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "tag-only programs attached to %s\n", cgroupPath)

	if err := loader.AttachTCEgressV6(ifaceName); err != nil {
		fmt.Fprintf(os.Stderr, "error attaching tc egress v6: %v\n", err)
		os.Exit(1)
	}

	epoch, err := loader.IncrementEpoch()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: initializing epoch: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "authorization epoch initialized to %d\n", epoch)
	}

	for appID, inode := range inodes {
		fmt.Fprintf(os.Stderr, "  %s -> cgroup inode %d, app_index %d\n",
			appID, inode, appIndices[appID])
	}

	fmt.Fprintf(os.Stderr, "wg-client ready -- tagging on %s (Ctrl-C to stop)\n", ifaceName)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	hv := NewHashVerifier(loader.TaskVerifiedMap(), loader.AppExecHashMap())
	go func() {
		if err := hv.StreamExecEvents(ctx, loader.ExecEventsMap()); err != nil {
			fmt.Fprintf(os.Stderr, "error streaming exec events: %v\n", err)
		}
	}()

	// SIGUSR2 handler: bump authorization epoch
	sigCh2 := make(chan os.Signal, 1)
	signal.Notify(sigCh2, syscall.SIGUSR2)
	go func() {
		for range sigCh2 {
			epoch, err := loader.IncrementEpoch()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error incrementing epoch: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "epoch bumped to %d\n", epoch)
			}
		}
	}()

	<-ctx.Done()

	fmt.Fprintln(os.Stderr, "stopping")
	loader.Close()
	CleanupCgroups(pol.Applications)
}

func runWgGateway() {
	policyPath := ""
	ifaceName := ""
	noFlowCache := false
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--policy":
			if i+1 < len(os.Args) {
				policyPath = os.Args[i+1]
				i++
			}
		case "--iface":
			if i+1 < len(os.Args) {
				ifaceName = os.Args[i+1]
				i++
			}
		case "--no-flow-cache":
			noFlowCache = true
		}
	}

	if policyPath == "" || ifaceName == "" {
		fmt.Fprintln(os.Stderr, "error: --policy and --iface are required")
		fmt.Fprintln(os.Stderr, "usage: procroute wg-gateway --policy <path> --iface <wg_iface> [--no-flow-cache]")
		os.Exit(1)
	}

	pol, err := LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "loaded policy: %d internal prefixes, %d applications\n",
		len(pol.InternalPrefixes), len(pol.Applications))

	v4Prefixes, v6Prefixes, err := pol.ParsedInternalPrefixes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "prefix parse error: %v\n", err)
		os.Exit(1)
	}

	// 1-based; 0 = unassigned
	appIndices := make(map[string]uint32)
	for i, app := range pol.Applications {
		appIndices[app.AppID] = uint32(i + 1)
	}

	loader := NewLoader()
	if err := loader.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "BPF load failed: %v\n", err)
		os.Exit(1)
	}
	defer loader.Close()
	fmt.Fprintln(os.Stderr, "loaded BPF")


	if err := loader.PopulateInternalPrefixes(v4Prefixes, v6Prefixes); err != nil {
		fmt.Fprintf(os.Stderr, "prefix map: %v\n", err)
		os.Exit(1)
	}

	if err := loader.PopulateAppAllowRules(pol, appIndices); err != nil {
		fmt.Fprintf(os.Stderr, "allow rules: %v\n", err)
		os.Exit(1)
	}

	if len(pol.ExemptPorts) > 0 {
		if err := loader.PopulateExemptPorts(pol.ExemptPorts); err != nil {
			fmt.Fprintf(os.Stderr, "error populating exempt ports: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "exempt ports: %v\n", pol.ExemptPorts)
	}
	fmt.Fprintln(os.Stderr, "maps populated")

	if err := loader.AttachTCIngressV6(ifaceName); err != nil {
		fmt.Fprintf(os.Stderr, "error attaching tc ingress v6: %v\n", err)
		os.Exit(1)
	}

	epoch, err := loader.IncrementEpoch()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: initializing epoch: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "authorization epoch initialized to %d\n", epoch)
	}

	if err := loader.SetFlowCacheEnabled(!noFlowCache); err != nil {
		fmt.Fprintf(os.Stderr, "error setting flow cache config: %v\n", err)
		os.Exit(1)
	}
	if noFlowCache {
		fmt.Fprintln(os.Stderr, "flow cache disabled")
	} else {
		fmt.Fprintln(os.Stderr, "flow cache enabled")
	}

	for _, app := range pol.Applications {
		fmt.Fprintf(os.Stderr, "  %s -> app_index %d\n",
			app.AppID, appIndices[app.AppID])
	}

	fmt.Fprintf(os.Stderr, "wg-gateway ready -- enforcing on %s (Ctrl-C to stop)\n", ifaceName)

	// SIGUSR1 handler: dump flow cache stats as JSON to stderr
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1)
	go func() {
		for range sigCh {
			hits, misses, inserts, err := loader.ReadFlowCacheStats()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading flow cache stats: %v\n", err)
				continue
			}
			var hitRate float64
			if hits+misses > 0 {
				hitRate = float64(hits) / float64(hits+misses) * 100.0
			}
			stats := map[string]interface{}{
				"hits":         hits,
				"misses":       misses,
				"inserts":      inserts,
				"hit_rate_pct": hitRate,
			}
			b, _ := json.Marshal(stats)
			fmt.Fprintf(os.Stderr, "flow_cache_stats: %s\n", string(b))
		}
	}()

	// SIGUSR2 handler: bump authorization epoch
	sigCh2 := make(chan os.Signal, 1)
	signal.Notify(sigCh2, syscall.SIGUSR2)
	go func() {
		for range sigCh2 {
			epoch, err := loader.IncrementEpoch()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error incrementing epoch: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "epoch bumped to %d\n", epoch)
			}
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := StreamGwDenyEventsV6(ctx, loader.GwDenyEventsV6Map()); err != nil {
		fmt.Fprintf(os.Stderr, "error streaming gw deny events: %v\n", err)
	}

	fmt.Fprintln(os.Stderr, "\nshutting down...")
	loader.Close()
	fmt.Fprintln(os.Stderr, "done")
}

func runLaunch() {
	appID := ""
	policyPath := ""
	var cmdArgs []string

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--app":
			if i+1 < len(os.Args) {
				appID = os.Args[i+1]
				i++
			}
		case "--policy":
			if i+1 < len(os.Args) {
				policyPath = os.Args[i+1]
				i++
			}
		case "--":
			cmdArgs = os.Args[i+1:]
			i = len(os.Args) // break out of loop
		}
	}

	if appID == "" || policyPath == "" || len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "error: --app, --policy, and -- <cmd> are required")
		os.Exit(1)
	}

	pol, err := LoadPolicy(policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	found := false
	for _, app := range pol.Applications {
		if app.AppID == appID {
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "error: app %q not found in policy\n", appID)
		os.Exit(1)
	}

	binary, err := lookPath(cmdArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if KernelSupportsClone3Cgroup() {
		// Atomic cgroup placement: clone3 creates the child directly
		// inside the target cgroup. No race window -- the child's
		// very first connect() is already mediated by ProcRoute.
		fmt.Fprintf(os.Stderr, "using clone3(CLONE_INTO_CGROUP) for atomic cgroup placement\n")
		pid, err := LaunchIntoCgroup(appID, binary, cmdArgs, os.Environ())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error launching into cgroup: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "launched pid %d into cgroup %s\n", pid, AppCgroupPath(appID))

		// Wait for the child to exit and propagate its exit status.
		var ws syscall.WaitStatus
		for {
			_, err := syscall.Wait4(pid, &ws, 0, nil)
			if err == syscall.EINTR {
				continue
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "error waiting for child: %v\n", err)
				os.Exit(1)
			}
			break
		}

		if ws.Exited() {
			os.Exit(ws.ExitStatus())
		}
		// Killed by signal
		os.Exit(128 + int(ws.Signal()))
	}

	// Fallback for kernels < 5.7: move current process, then exec.
	// A brief race window exists between MoveToCgroup and Exec.
	fmt.Fprintf(os.Stderr, "kernel < 5.7: falling back to MoveToCgroup + exec\n")
	if err := MoveToCgroup(appID); err != nil {
		fmt.Fprintf(os.Stderr, "error moving to cgroup: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "moved to cgroup %s\n", AppCgroupPath(appID))

	if err := syscall.Exec(binary, cmdArgs, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "error exec %s: %v\n", cmdArgs[0], err)
		os.Exit(1)
	}
}

func lookPath(name string) (string, error) {
	if len(name) > 0 && name[0] == '/' {
		if _, err := os.Stat(name); err == nil {
			return name, nil
		}
		return "", fmt.Errorf("executable not found: %s", name)
	}

	paths := os.Getenv("PATH")
	for _, dir := range splitPath(paths) {
		full := dir + "/" + name
		if fi, err := os.Stat(full); err == nil {
			if fi.Mode()&0o111 != 0 {
				return full, nil
			}
		}
	}
	return "", fmt.Errorf("executable not found in PATH: %s", name)
}

func splitPath(path string) []string {
	if path == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == ':' {
			if i > start {
				result = append(result, path[start:i])
			}
			start = i + 1
		}
	}
	if start < len(path) {
		result = append(result, path[start:])
	}
	return result
}

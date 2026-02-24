package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// CgroupRoot is the default cgroup v2 mount point.
	CgroupRoot = "/sys/fs/cgroup"
	// ProcRouteCgroup is the parent cgroup for all ProcRoute-managed apps.
	ProcRouteCgroup = "procroute"
)

func CgroupBasePath() string {
	return filepath.Join(CgroupRoot, ProcRouteCgroup)
}

func AppCgroupPath(appID string) string {
	return filepath.Join(CgroupBasePath(), appID)
}

// EnsureCgroupHierarchy sets up /sys/fs/cgroup/procroute/<app_id>/ for each app
func EnsureCgroupHierarchy(apps []Application) (map[string]uint64, error) {
	base := CgroupBasePath()

	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, fmt.Errorf("creating cgroup %s: %w", base, err)
	}

	// Enable controllers in parent so children can use them
	if err := enableControllers(base); err != nil {
		// Non-fatal: some environments don't need this
		fmt.Fprintf(os.Stderr, "warning: could not enable controllers in %s: %v\n", base, err)
	}

	inodes := make(map[string]uint64)
	for _, app := range apps {
		appPath := AppCgroupPath(app.AppID)
		if err := os.MkdirAll(appPath, 0o755); err != nil {
			return nil, fmt.Errorf("creating cgroup %s: %w", appPath, err)
		}

		inode, err := CgroupInode(appPath)
		if err != nil {
			return nil, fmt.Errorf("getting inode for %s: %w", appPath, err)
		}
		inodes[app.AppID] = inode
	}

	return inodes, nil
}

// CgroupInode returns the inode (matches bpf_get_current_cgroup_id).
func CgroupInode(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return st.Ino, nil
}

func CgroupRootInode() (uint64, error) {
	return CgroupInode(CgroupBasePath())
}

func MoveToCgroup(appID string) error {
	path := AppCgroupPath(appID)
	procsFile := filepath.Join(path, "cgroup.procs")
	pid := os.Getpid()
	return os.WriteFile(procsFile, []byte(fmt.Sprintf("%d\n", pid)), 0o644)
}

func CleanupCgroups(apps []Application) {
	for _, app := range apps {
		path := AppCgroupPath(app.AppID)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: removing cgroup %s: %v\n", path, err)
		}
	}
	base := CgroupBasePath()
	if err := os.Remove(base); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "warning: removing cgroup %s: %v\n", base, err)
	}
}

func enableControllers(path string) error {
	ctrlFile := filepath.Join(path, "cgroup.subtree_control")
	// We don't actually need any specific controllers for our PoC,
	// but ensure the file exists and is writable.
	_, err := os.Stat(ctrlFile)
	return err
}

// clone3 with CLONE_INTO_CGROUP

// mirrors struct clone_args
type cloneArgs struct {
	flags      uint64
	pidFD      uint64
	childTID   uint64
	parentTID  uint64
	exitSignal uint64
	stack      uint64
	stackSize  uint64
	tls        uint64
	setTID     uint64
	setTIDSize uint64
	cgroup     uint64
}


func KernelSupportsClone3Cgroup() bool {
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return false
	}

	release := unix.ByteSliceToString(utsname.Release[:])
	return kernelVersionAtLeast(release, 5, 7)
}

func kernelVersionAtLeast(release string, major, minor int) bool {
	// Strip anything after first non-version character (e.g. "-generic")
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}

	kmaj, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}

	// Minor may have a suffix like "6-generic"
	minorStr := parts[1]
	for i, c := range minorStr {
		if c < '0' || c > '9' {
			minorStr = minorStr[:i]
			break
		}
	}
	kmin, err := strconv.Atoi(minorStr)
	if err != nil {
		return false
	}

	if kmaj > major {
		return true
	}
	if kmaj == major && kmin >= minor {
		return true
	}
	return false
}

// LaunchIntoCgroup forks into the target cgroup via clone3(CLONE_INTO_CGROUP).

func LaunchIntoCgroup(appID string, binary string, argv []string, env []string) (int, error) {
	cgroupPath := AppCgroupPath(appID)
	cgroupFD, err := unix.Open(cgroupPath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return 0, fmt.Errorf("opening cgroup %s: %w", cgroupPath, err)
	}
	// cgroupFD is consumed by clone3; closed after the syscall.
	defer unix.Close(cgroupFD)

	args := cloneArgs{
		flags:      unix.CLONE_INTO_CGROUP,
		exitSignal: uint64(syscall.SIGCHLD),
		cgroup:     uint64(cgroupFD),
	}

	pid, _, errno := syscall.RawSyscall(
		unix.SYS_CLONE3,
		uintptr(unsafe.Pointer(&args)),
		unsafe.Sizeof(args),
		0,
	)

	if errno != 0 {
		return 0, fmt.Errorf("clone3: %w", errno)
	}

	if pid == 0 {
		// Child process
		// We are already inside the target cgroup.
		// Exec the requested binary (this replaces the process image).
		err := syscall.Exec(binary, argv, env)
		// If exec fails, we must exit immediately -- we are in a
		// vforked-like state with no safe Go runtime.
		if err != nil {
			syscall.Exit(127)
		}
		// Unreachable after successful exec.
	}

	// Parent process
	return int(pid), nil
}

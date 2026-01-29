/*
CarterPerez-dev | 2025
proc.go
*/

package proc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ProcessInfo struct {
	PID          int
	Name         string
	State        string
	PPID         int
	UID          int
	GID          int
	Threads      int
	VmSize       int64
	VmRSS        int64
	Cmdline      []string
	Cgroups      []CgroupEntry
	Namespaces   map[string]uint64
	Capabilities *CapabilitySet
	SeccompMode  string
	NoNewPrivs   bool
}

type CgroupEntry struct {
	HierarchyID int
	Controllers []string
	Path        string
}

func GetProcessInfo(pid int) (*ProcessInfo, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)

	if _, err := os.Stat(procPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("process %d does not exist", pid)
	}

	info := &ProcessInfo{
		PID:        pid,
		Namespaces: make(map[string]uint64),
	}

	if err := info.readStatus(procPath); err != nil {
		return nil, fmt.Errorf("reading status: %w", err)
	}

	//nolint:staticcheck // graceful degradation - errors intentionally ignored
	if err := info.readCmdline(procPath); err != nil {
	}

	//nolint:staticcheck // graceful degradation - errors intentionally ignored
	if err := info.readCgroups(procPath); err != nil {
	}

	//nolint:staticcheck // graceful degradation - errors intentionally ignored
	if err := info.readNamespaces(procPath); err != nil {
	}

	return info, nil
}

func (p *ProcessInfo) readStatus(procPath string) error {
	file, err := os.Open(filepath.Join(procPath, "status"))
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Name":
			p.Name = value
		case "State":
			p.State = strings.Split(value, " ")[0]
		case "PPid":
			p.PPID, _ = strconv.Atoi(value)
		case "Uid":
			fields := strings.Fields(value)
			if len(fields) > 0 {
				p.UID, _ = strconv.Atoi(fields[0])
			}
		case "Gid":
			fields := strings.Fields(value)
			if len(fields) > 0 {
				p.GID, _ = strconv.Atoi(fields[0])
			}
		case "Threads":
			p.Threads, _ = strconv.Atoi(value)
		case "VmSize":
			p.VmSize = parseMemValue(value)
		case "VmRSS":
			p.VmRSS = parseMemValue(value)
		case "CapInh":
			if p.Capabilities == nil {
				p.Capabilities = &CapabilitySet{}
			}
			p.Capabilities.Inheritable, _ = strconv.ParseUint(value, 16, 64)
		case "CapPrm":
			if p.Capabilities == nil {
				p.Capabilities = &CapabilitySet{}
			}
			p.Capabilities.Permitted, _ = strconv.ParseUint(value, 16, 64)
		case "CapEff":
			if p.Capabilities == nil {
				p.Capabilities = &CapabilitySet{}
			}
			p.Capabilities.Effective, _ = strconv.ParseUint(value, 16, 64)
		case "CapBnd":
			if p.Capabilities == nil {
				p.Capabilities = &CapabilitySet{}
			}
			p.Capabilities.Bounding, _ = strconv.ParseUint(value, 16, 64)
		case "CapAmb":
			if p.Capabilities == nil {
				p.Capabilities = &CapabilitySet{}
			}
			p.Capabilities.Ambient, _ = strconv.ParseUint(value, 16, 64)
		case "Seccomp":
			p.SeccompMode = parseSeccompMode(value)
		case "NoNewPrivs":
			p.NoNewPrivs = value == "1"
		}
	}

	return scanner.Err()
}

func (p *ProcessInfo) readCmdline(procPath string) error {
	data, err := os.ReadFile(filepath.Join(procPath, "cmdline"))
	if err != nil {
		return err
	}

	if len(data) > 0 {
		cmdline := strings.TrimRight(string(data), "\x00")
		p.Cmdline = strings.Split(cmdline, "\x00")
	}

	return nil
}

func (p *ProcessInfo) readCgroups(procPath string) error {
	file, err := os.Open(filepath.Join(procPath, "cgroup"))
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}

		hierarchyID, _ := strconv.Atoi(parts[0])
		controllers := strings.Split(parts[1], ",")
		if parts[1] == "" {
			controllers = nil
		}

		p.Cgroups = append(p.Cgroups, CgroupEntry{
			HierarchyID: hierarchyID,
			Controllers: controllers,
			Path:        parts[2],
		})
	}

	return scanner.Err()
}

func (p *ProcessInfo) readNamespaces(procPath string) error {
	nsPath := filepath.Join(procPath, "ns")
	entries, err := os.ReadDir(nsPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join(nsPath, entry.Name()))
		if err != nil {
			continue
		}

		var inode uint64
		_, _ = fmt.Sscanf(link, "%*[^[]:[%d]", &inode)
		p.Namespaces[entry.Name()] = inode
	}

	return nil
}

func (p *ProcessInfo) IsInContainer() bool {
	for _, cg := range p.Cgroups {
		if strings.Contains(cg.Path, "docker") ||
			strings.Contains(cg.Path, "containerd") ||
			strings.Contains(cg.Path, "crio") ||
			strings.Contains(cg.Path, "kubepods") ||
			strings.Contains(cg.Path, "lxc") {
			return true
		}
	}
	return false
}

func (p *ProcessInfo) ContainerID() string {
	for _, cg := range p.Cgroups {
		parts := strings.Split(cg.Path, "/")
		for _, part := range parts {
			if len(part) == 64 && isHex(part) {
				return part
			}
			if strings.HasPrefix(part, "docker-") &&
				strings.HasSuffix(part, ".scope") {
				id := strings.TrimPrefix(part, "docker-")
				id = strings.TrimSuffix(id, ".scope")
				if len(id) == 64 && isHex(id) {
					return id
				}
			}
		}
	}
	return ""
}

func GetContainerPID1(containerID string) (int, error) {
	cgroupPaths := []string{
		"/sys/fs/cgroup/memory/docker/" + containerID + "/cgroup.procs",
		"/sys/fs/cgroup/cpu/docker/" + containerID + "/cgroup.procs",
		"/sys/fs/cgroup/docker/" + containerID + "/cgroup.procs",
		"/sys/fs/cgroup/system.slice/docker-" + containerID + ".scope/cgroup.procs",
	}

	for _, path := range cgroupPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 0 {
			pid, err := strconv.Atoi(lines[0])
			if err == nil {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("could not find PID 1 for container %s", containerID)
}

func ListContainerProcesses(containerID string) ([]int, error) {
	cgroupPaths := []string{
		"/sys/fs/cgroup/memory/docker/" + containerID + "/cgroup.procs",
		"/sys/fs/cgroup/docker/" + containerID + "/cgroup.procs",
		"/sys/fs/cgroup/system.slice/docker-" + containerID + ".scope/cgroup.procs",
	}

	for _, path := range cgroupPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var pids []int
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			if pid, err := strconv.Atoi(line); err == nil {
				pids = append(pids, pid)
			}
		}

		if len(pids) > 0 {
			return pids, nil
		}
	}

	return nil, fmt.Errorf(
		"could not list processes for container %s",
		containerID,
	)
}

func parseMemValue(s string) int64 {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " kB")
	val, _ := strconv.ParseInt(s, 10, 64)
	return val * 1024
}

func parseSeccompMode(s string) string {
	switch s {
	case "0":
		return "disabled"
	case "1":
		return "strict"
	case "2":
		return "filter"
	default:
		return "unknown"
	}
}

func isHex(s string) bool {
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		isUpperHex := c >= 'A' && c <= 'F'
		if !isDigit && !isLowerHex && !isUpperHex {
			return false
		}
	}
	return true
}

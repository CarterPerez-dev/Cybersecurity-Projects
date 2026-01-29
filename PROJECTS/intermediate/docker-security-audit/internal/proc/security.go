/*
CarterPerez-dev | 2026
security.go
*/

package proc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type SecurityProfile struct {
	PID             int
	SeccompMode     SeccompMode
	SeccompFilter   bool
	AppArmorProfile string
	SELinuxContext  string
	NoNewPrivs      bool
	Capabilities    *CapabilitySet
	Namespaces      map[string]uint64
	UserNS          bool
	RootFS          string
	CgroupNS        bool
}

type SeccompMode int

const (
	SeccompDisabled SeccompMode = 0
	SeccompStrict   SeccompMode = 1
	SeccompFilter   SeccompMode = 2
)

func (s SeccompMode) String() string {
	switch s {
	case SeccompDisabled:
		return "disabled"
	case SeccompStrict:
		return "strict"
	case SeccompFilter:
		return "filter"
	default:
		return "unknown"
	}
}

func (s SeccompMode) IsEnabled() bool {
	return s != SeccompDisabled
}

func GetSecurityProfile(pid int) (*SecurityProfile, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)

	if _, err := os.Stat(procPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("process %d does not exist", pid)
	}

	profile := &SecurityProfile{
		PID:        pid,
		Namespaces: make(map[string]uint64),
	}

	//nolint:staticcheck // graceful degradation - errors intentionally ignored
	if err := profile.readSeccomp(procPath); err != nil {
	}

	//nolint:staticcheck // graceful degradation - errors intentionally ignored
	if err := profile.readAppArmor(procPath); err != nil {
	}

	//nolint:staticcheck // graceful degradation - errors intentionally ignored
	if err := profile.readSELinux(procPath); err != nil {
	}

	//nolint:staticcheck // graceful degradation - errors intentionally ignored
	if err := profile.readNoNewPrivs(procPath); err != nil {
	}

	//nolint:staticcheck // graceful degradation - errors intentionally ignored
	if err := profile.readCapabilities(procPath); err != nil {
	}

	//nolint:staticcheck // graceful degradation - errors intentionally ignored
	if err := profile.readNamespaces(procPath); err != nil {
	}

	//nolint:staticcheck // graceful degradation - errors intentionally ignored
	if err := profile.readRootFS(procPath); err != nil {
	}

	return profile, nil
}

func (p *SecurityProfile) readSeccomp(procPath string) error {
	file, err := os.Open(filepath.Join(procPath, "status"))
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Seccomp:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				switch parts[1] {
				case "0":
					p.SeccompMode = SeccompDisabled
				case "1":
					p.SeccompMode = SeccompStrict
				case "2":
					p.SeccompMode = SeccompFilter
					p.SeccompFilter = true
				}
			}
			break
		}
	}

	return scanner.Err()
}

func (p *SecurityProfile) readAppArmor(procPath string) error {
	data, err := os.ReadFile(filepath.Join(procPath, "attr/current"))
	if err != nil {
		attrPath := filepath.Join(procPath, "attr/apparmor/current")
		data, err = os.ReadFile(attrPath)
		if err != nil {
			return err
		}
	}

	profile := strings.TrimSpace(string(data))
	profile = strings.TrimSuffix(profile, " (enforce)")
	profile = strings.TrimSuffix(profile, " (complain)")
	p.AppArmorProfile = profile

	return nil
}

func (p *SecurityProfile) readSELinux(procPath string) error {
	data, err := os.ReadFile(filepath.Join(procPath, "attr/current"))
	if err != nil {
		return err
	}

	context := strings.TrimSpace(string(data))
	if strings.Contains(context, ":") {
		p.SELinuxContext = context
	}

	return nil
}

func (p *SecurityProfile) readNoNewPrivs(procPath string) error {
	file, err := os.Open(filepath.Join(procPath, "status"))
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NoNewPrivs:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				p.NoNewPrivs = parts[1] == "1"
			}
			break
		}
	}

	return scanner.Err()
}

func (p *SecurityProfile) readCapabilities(procPath string) error {
	file, err := os.Open(filepath.Join(procPath, "status"))
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	p.Capabilities = &CapabilitySet{}

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
		case "CapInh":
			_, _ = fmt.Sscanf(value, "%x", &p.Capabilities.Inheritable)
		case "CapPrm":
			_, _ = fmt.Sscanf(value, "%x", &p.Capabilities.Permitted)
		case "CapEff":
			_, _ = fmt.Sscanf(value, "%x", &p.Capabilities.Effective)
		case "CapBnd":
			_, _ = fmt.Sscanf(value, "%x", &p.Capabilities.Bounding)
		case "CapAmb":
			_, _ = fmt.Sscanf(value, "%x", &p.Capabilities.Ambient)
		}
	}

	return scanner.Err()
}

func (p *SecurityProfile) readNamespaces(procPath string) error {
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

		if entry.Name() == "user" {
			initLink, _ := os.Readlink("/proc/1/ns/user")
			var initInode uint64
			_, _ = fmt.Sscanf(initLink, "%*[^[]:[%d]", &initInode)
			p.UserNS = inode != initInode
		}

		if entry.Name() == "cgroup" {
			initLink, _ := os.Readlink("/proc/1/ns/cgroup")
			var initInode uint64
			_, _ = fmt.Sscanf(initLink, "%*[^[]:[%d]", &initInode)
			p.CgroupNS = inode != initInode
		}
	}

	return nil
}

func (p *SecurityProfile) readRootFS(procPath string) error {
	link, err := os.Readlink(filepath.Join(procPath, "root"))
	if err != nil {
		return err
	}
	p.RootFS = link
	return nil
}

func (p *SecurityProfile) HasSeccompEnabled() bool {
	return p.SeccompMode.IsEnabled()
}

func (p *SecurityProfile) HasAppArmorEnabled() bool {
	return p.AppArmorProfile != "" &&
		p.AppArmorProfile != "unconfined" &&
		!strings.HasPrefix(p.AppArmorProfile, "unconfined")
}

func (p *SecurityProfile) HasSELinuxEnabled() bool {
	return p.SELinuxContext != "" &&
		!strings.Contains(p.SELinuxContext, "unconfined")
}

func (p *SecurityProfile) HasMACEnabled() bool {
	return p.HasAppArmorEnabled() || p.HasSELinuxEnabled()
}

func (p *SecurityProfile) HasUserNamespace() bool {
	return p.UserNS
}

func (p *SecurityProfile) IsPrivileged() bool {
	if p.Capabilities == nil {
		return false
	}
	return p.Capabilities.IsFullyPrivileged()
}

func (p *SecurityProfile) SecurityScore() int {
	score := 100

	if !p.HasSeccompEnabled() {
		score -= 20
	}

	if !p.HasMACEnabled() {
		score -= 15
	}

	if !p.NoNewPrivs {
		score -= 10
	}

	if p.Capabilities != nil {
		switch {
		case p.Capabilities.IsFullyPrivileged():
			score -= 40
		case p.Capabilities.HasCriticalCapabilities():
			score -= 25
		case p.Capabilities.HasDangerousCapabilities():
			score -= 15
		}
	}

	if !p.UserNS {
		score -= 5
	}

	if score < 0 {
		score = 0
	}

	return score
}

func (p *SecurityProfile) GetIssues() []string {
	var issues []string

	if !p.HasSeccompEnabled() {
		issues = append(issues, "Seccomp filtering is disabled")
	}

	if !p.HasMACEnabled() {
		issues = append(issues, "No MAC (AppArmor/SELinux) profile active")
	}

	if !p.NoNewPrivs {
		issues = append(issues, "no_new_privs is not set")
	}

	if p.Capabilities != nil {
		if p.Capabilities.IsFullyPrivileged() {
			issues = append(
				issues,
				"Process has full capabilities (privileged)",
			)
		} else {
			for _, cap := range p.Capabilities.GetCriticalCapabilities() {
				issues = append(
					issues,
					fmt.Sprintf("Has critical capability: %s", cap),
				)
			}
		}
	}

	return issues
}

func CheckHostNamespaceSharing(pid int) (map[string]bool, error) {
	shared := make(map[string]bool)

	namespaces := []string{"pid", "net", "ipc", "uts", "mnt"}

	for _, ns := range namespaces {
		procLink, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, ns))
		if err != nil {
			continue
		}

		initLink, err := os.Readlink(fmt.Sprintf("/proc/1/ns/%s", ns))
		if err != nil {
			continue
		}

		shared[ns] = procLink == initLink
	}

	return shared, nil
}

func IsRunningAsRoot(pid int) (bool, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1] == "0", nil
			}
		}
	}

	return false, scanner.Err()
}

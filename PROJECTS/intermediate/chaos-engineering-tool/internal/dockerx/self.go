// ©AngelaMos | 2026
// self.go

package dockerx

import (
	"os"
	"regexp"
	"strings"
)

const (
	procMountInfo = "/proc/self/mountinfo"
	procCgroup    = "/proc/self/cgroup"
)

var (
	containerCgroupPattern = regexp.MustCompile(
		`(?:^|/)docker(?:/|-)([0-9a-f]{64})(?:\.scope)?(?:/|$)`,
	)
	containerMountPattern = regexp.MustCompile(
		`(?:^|/)containers/([0-9a-f]{64})/(?:hostname|hosts|resolv\.conf)$`,
	)
)

func SelfContainerID() string {
	if raw, err := os.ReadFile(procCgroup); err == nil {
		if id := containerIDFromCgroup(raw); id != "" {
			return id
		}
	}

	raw, err := os.ReadFile(procMountInfo)
	if err != nil {
		return ""
	}
	return containerIDFromMountInfo(raw)
}

func containerIDFromCgroup(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		match := containerCgroupPattern.FindStringSubmatch(fields[2])
		if len(match) > 1 {
			return match[1]
		}
	}
	return ""
}

func containerIDFromMountInfo(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		switch fields[4] {
		case "/etc/hostname", "/etc/hosts", "/etc/resolv.conf":
		default:
			continue
		}
		match := containerMountPattern.FindStringSubmatch(fields[3])
		if len(match) > 1 {
			return match[1]
		}
	}
	return ""
}

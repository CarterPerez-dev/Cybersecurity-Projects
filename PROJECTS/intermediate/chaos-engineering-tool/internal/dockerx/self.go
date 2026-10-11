// ©AngelaMos | 2026
// self.go

package dockerx

import (
	"os"
	"regexp"
)

const (
	procMountInfo = "/proc/self/mountinfo"
	procCgroup    = "/proc/self/cgroup"
)

var containerIDPattern = regexp.MustCompile(`[0-9a-f]{64}`)

func SelfContainerID() string {
	for _, path := range []string{procMountInfo, procCgroup} {
		if id := scanForContainerID(path); id != "" {
			return id
		}
	}
	return ""
}

func scanForContainerID(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return containerIDPattern.FindString(string(raw))
}

// ©AngelaMos | 2026
// self_test.go

package dockerx

import (
	"strings"
	"testing"
)

func TestContainerIDFromCgroup(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"v1", "5:cpu,cpuacct:/docker/" + id, id},
		{"v2", "0::/system.slice/docker-" + id + ".scope", id},
		{"rootless", "0::/user.slice/user-1000.slice/docker-" + id + ".scope", id},
		{"nested", "0::/docker/" + id + "/worker", id},
		{"private namespace", "0::/", ""},
		{"host", "0::/user.slice/user-1000.slice/session-1.scope", ""},
		{"unrelated hash", "0::/system.slice/runner-" + id + ".scope", ""},
		{"long hash", "0::/docker/" + id + "a", ""},
		{"short hash", "0::/docker/" + id[:12], ""},
		{"malformed", "/docker/" + id, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := containerIDFromCgroup([]byte(tc.raw)); got != tc.want {
				t.Fatalf("container ID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestContainerIDFromMountInfo(t *testing.T) {
	id := strings.Repeat("a", 64)
	peer := strings.Repeat("b", 64)
	root := "/var/lib/docker/containers/" + id
	mount := func(root, point string) string {
		return "100 90 8:1 " + root + " " + point +
			" rw,relatime shared:7 - ext4 /dev/root rw\n"
	}
	hostMount := mount("/", "/var/lib/docker/rootfs/overlayfs/"+peer)
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"hostname", mount(root+"/hostname", "/etc/hostname"), id},
		{"hosts", mount(root+"/hosts", "/etc/hosts"), id},
		{"resolver", mount(root+"/resolv.conf", "/etc/resolv.conf"), id},
		{"custom root", mount("/srv/docker/containers/"+id+"/hosts", "/etc/hosts"), id},
		{"host overlay", hostMount, ""},
		{"host container file", mount(root+"/hostname", root+"/hostname"), ""},
		{"unrelated bind", mount(root+"/hosts", "/mnt/hosts"), ""},
		{"unrelated hash", mount("/srv/"+id+"/hosts", "/etc/hosts"), ""},
		{"overlay before identity", hostMount + mount(root+"/hosts", "/etc/hosts"), id},
		{"malformed", root + "/hostname /etc/hostname", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := containerIDFromMountInfo([]byte(tc.raw)); got != tc.want {
				t.Fatalf("container ID = %q, want %q", got, tc.want)
			}
		})
	}
}

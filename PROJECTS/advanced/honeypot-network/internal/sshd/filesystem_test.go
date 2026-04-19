/*
©AngelaMos | 2026
filesystem_test.go
*/

package sshd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFakeFSPopulatesDirectories(t *testing.T) {
	fs := NewFakeFS("test-host")

	dirs := []string{
		"/", "/bin", "/boot", "/dev", "/etc",
		"/etc/ssh", "/home", "/home/admin",
		"/proc", "/root", "/tmp", "/usr",
		"/usr/bin", "/var", "/var/log",
	}

	for _, d := range dirs {
		assert.True(t, fs.IsDir(d), "expected %s to be a directory", d)
	}
}

func TestNewFakeFSPopulatesFiles(t *testing.T) {
	fs := NewFakeFS("test-host")

	files := []string{
		"/etc/passwd",
		"/etc/hostname",
		"/etc/os-release",
		"/etc/ssh/sshd_config",
		"/proc/version",
		"/proc/cpuinfo",
		"/proc/meminfo",
	}

	for _, f := range files {
		assert.True(t, fs.Exists(f), "expected %s to exist", f)
		assert.False(t, fs.IsDir(f), "expected %s to not be a directory", f)
	}
}

func TestHostnameInjection(t *testing.T) {
	fs := NewFakeFS("custom-host")

	content, ok := fs.ReadFile("/etc/hostname")
	require.True(t, ok)
	assert.Equal(t, "custom-host\n", content)
}

func TestReadFileExisting(t *testing.T) {
	fs := NewFakeFS("test-host")

	tests := []struct {
		name     string
		path     string
		contains string
	}{
		{"passwd", "/etc/passwd", "root:x:0:0"},
		{"os-release", "/etc/os-release", "Ubuntu"},
		{"cpuinfo", "/proc/cpuinfo", "GenuineIntel"},
		{"meminfo", "/proc/meminfo", "MemTotal"},
		{"sshd_config", "/etc/ssh/sshd_config", "PermitRootLogin yes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, ok := fs.ReadFile(tt.path)
			require.True(t, ok, "expected %s to exist", tt.path)
			assert.Contains(t, content, tt.contains)
		})
	}
}

func TestReadFileMissing(t *testing.T) {
	fs := NewFakeFS("test-host")

	content, ok := fs.ReadFile("/nonexistent")
	assert.False(t, ok)
	assert.Empty(t, content)
}

func TestReadFileOnDirectory(t *testing.T) {
	fs := NewFakeFS("test-host")

	content, ok := fs.ReadFile("/etc")
	assert.False(t, ok)
	assert.Empty(t, content)
}

func TestIsDirTrueAndFalse(t *testing.T) {
	fs := NewFakeFS("test-host")

	assert.True(t, fs.IsDir("/etc"))
	assert.False(t, fs.IsDir("/etc/passwd"))
	assert.False(t, fs.IsDir("/does-not-exist"))
}

func TestListDirRoot(t *testing.T) {
	fs := NewFakeFS("test-host")

	listing := fs.ListDir("/etc")
	require.NotEmpty(t, listing)
	assert.Contains(t, listing, "passwd")
	assert.Contains(t, listing, "hostname")
	assert.Contains(t, listing, "os-release")
	assert.Contains(t, listing, "ssh")
}

func TestListDirEmpty(t *testing.T) {
	fs := NewFakeFS("test-host")

	listing := fs.ListDir("/mnt")
	assert.Empty(t, listing)
}

func TestListDirNonDirectory(t *testing.T) {
	fs := NewFakeFS("test-host")

	listing := fs.ListDir("/etc/passwd")
	assert.Empty(t, listing)
}

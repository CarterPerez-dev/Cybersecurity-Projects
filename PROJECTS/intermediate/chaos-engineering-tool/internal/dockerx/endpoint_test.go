// ©AngelaMos | 2026
// endpoint_test.go

package dockerx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	envHostValue    = "tcp://10.0.0.5:2375"
	ctxName         = "orangepi"
	ctxHostValue    = "ssh://root@192.168.1.178"
	otherCtxName    = "staging"
	otherCtxHost    = "tcp://10.0.0.9:2375"
	rootlessSockDir = "runtime"
)

func fakeEnv(pairs map[string]string) func(string) string {
	return func(key string) string { return pairs[key] }
}

func writeContext(t *testing.T, home, name, host string) {
	t.Helper()

	digest := sha256.Sum256([]byte(name))
	dir := filepath.Join(
		home,
		dockerDir,
		contextsDir,
		contextMetaDir,
		hex.EncodeToString(digest[:]),
	)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir context: %v", err)
	}

	body := `{"Name":"` + name + `","Endpoints":{"docker":{"Host":"` + host + `"}}}`
	if err := os.WriteFile(
		filepath.Join(dir, contextMeta),
		[]byte(body),
		0o644,
	); err != nil {
		t.Fatalf("write context meta: %v", err)
	}
}

func writeCurrentContext(t *testing.T, home, name string) {
	t.Helper()

	dir := filepath.Join(home, dockerDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir docker config: %v", err)
	}

	body := `{"currentContext":"` + name + `"}`
	if err := os.WriteFile(
		filepath.Join(dir, configFile),
		[]byte(body),
		0o644,
	); err != nil {
		t.Fatalf("write docker config: %v", err)
	}
}

func makeRootlessSocket(t *testing.T, home string) string {
	t.Helper()

	dir := filepath.Join(home, rootlessSockDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir runtime: %v", err)
	}

	path := filepath.Join(dir, socketBaseName)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write socket placeholder: %v", err)
	}

	return dir
}

func TestEnvHostWinsOverEverything(t *testing.T) {
	home := t.TempDir()
	writeContext(t, home, ctxName, ctxHostValue)
	writeCurrentContext(t, home, ctxName)

	env := fakeEnv(map[string]string{
		EnvDockerHost:    envHostValue,
		EnvDockerContext: ctxName,
	})

	got, err := ResolveEndpoint(env, home)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if got.Host != envHostValue || got.Source != SourceEnvHost {
		t.Fatalf("got %+v, want %s via %s", got, envHostValue, SourceEnvHost)
	}
}

func TestEnvContextWinsOverConfigContext(t *testing.T) {
	home := t.TempDir()
	writeContext(t, home, ctxName, ctxHostValue)
	writeContext(t, home, otherCtxName, otherCtxHost)
	writeCurrentContext(t, home, ctxName)

	got, err := ResolveEndpoint(
		fakeEnv(map[string]string{EnvDockerContext: otherCtxName}),
		home,
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if got.Host != otherCtxHost || got.Source != SourceEnvContext ||
		got.Name != otherCtxName {
		t.Fatalf("got %+v, want %s via %s", got, otherCtxHost, SourceEnvContext)
	}
}

func TestConfigContextIsResolvedByDigestPath(t *testing.T) {
	home := t.TempDir()
	writeContext(t, home, ctxName, ctxHostValue)
	writeCurrentContext(t, home, ctxName)

	got, err := ResolveEndpoint(fakeEnv(nil), home)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if got.Host != ctxHostValue || got.Source != SourceConfigContext ||
		got.Name != ctxName {
		t.Fatalf(
			"got %+v, want %s via %s",
			got,
			ctxHostValue,
			SourceConfigContext,
		)
	}
}

func TestDefaultContextFallsThroughToSockets(t *testing.T) {
	home := t.TempDir()
	writeCurrentContext(t, home, defaultContext)
	runtimeDir := makeRootlessSocket(t, home)

	got, err := ResolveEndpoint(
		fakeEnv(map[string]string{EnvXDGRuntime: runtimeDir}),
		home,
	)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if got.Source != SourceRootless {
		t.Fatalf("got %+v, want the rootless socket", got)
	}

	want := filepath.Join(runtimeDir, socketBaseName)
	if path, ok := got.SocketPath(); !ok || path != want {
		t.Fatalf("SocketPath() = %q, %v; want %q", path, ok, want)
	}
}

func TestAnUnresolvableNamedContextIsRefusedNotIgnored(t *testing.T) {
	cases := map[string]func(t *testing.T, home string) func(string) string{
		"named by DOCKER_CONTEXT": func(_ *testing.T, _ string) func(string) string {
			return fakeEnv(
				map[string]string{
					EnvDockerContext: "a-context-with-no-metadata",
				},
			)
		},
		"named by docker config": func(t *testing.T, home string) func(string) string {
			writeCurrentContext(t, home, "a-context-with-no-metadata")
			return fakeEnv(nil)
		},
	}

	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			env := setup(t, home)
			makeRootlessSocket(t, home)

			_, err := ResolveEndpoint(env, home)
			if !errors.Is(err, ErrContextUnresolvable) {
				t.Fatalf(
					"got %v; an explicitly named context that cannot be resolved must refuse, "+
						"never silently fall through to whatever daemon happens to be local",
					err,
				)
			}
		})
	}
}

func TestNoEndpointAnywhereIsReportedNotGuessed(t *testing.T) {
	home := t.TempDir()

	got, err := ResolveEndpoint(fakeEnv(nil), home)

	if exists(DockerSocketPath) {
		if err != nil || got.Source != SourceDefault {
			t.Fatalf("got %+v (%v), want the default socket", got, err)
		}
		return
	}

	if !errors.Is(err, ErrNoEndpoint) {
		t.Fatalf("got %+v (%v), want an explicit no-endpoint error", got, err)
	}
}

func TestSocketPathRejectsNonUnixHosts(t *testing.T) {
	e := Endpoint{Host: envHostValue, Source: SourceEnvHost}
	if path, ok := e.SocketPath(); ok {
		t.Fatalf("a tcp endpoint reported a socket path %q", path)
	}
}

// An explicit DOCKER_CONTEXT=default selects the default endpoint. It is not
// the same as leaving the variable unset, and khaos treated it as such.
//
// Measured against docker 29.1.3: with a saved current context of `ag-server`
// and DOCKER_CONTEXT=default, the CLI used the LOCAL daemon. khaos used
// ag-server. `khaos range` shells out to that CLI, so the two halves of one
// command were acting on different machines.
func TestAnExplicitDefaultContextSelectsTheLocalDaemon(t *testing.T) {
	home := t.TempDir()
	writeContext(t, home, "ag-server", "ssh://ag-server")
	writeCurrentContext(t, home, "ag-server")

	socket := t.TempDir()
	runtime := func(name string) string {
		if name == EnvXDGRuntime {
			return socket
		}
		return ""
	}

	if err := os.WriteFile(
		filepath.Join(socket, socketBaseName),
		nil,
		0o600,
	); err != nil {
		t.Fatalf("socket: %v", err)
	}

	// Control: with nothing set, the saved context wins.
	saved, err := ResolveEndpoint(runtime, home)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if saved.Name != "ag-server" {
		t.Fatalf(
			"with no env set khaos resolved %q, want the saved context ag-server",
			saved.Name,
		)
	}

	withDefault := func(name string) string {
		if name == EnvDockerContext {
			return "default"
		}
		return runtime(name)
	}

	resolved, err := ResolveEndpoint(withDefault, home)
	if err != nil {
		t.Fatalf("resolve with DOCKER_CONTEXT=default: %v", err)
	}

	if resolved.Name == "ag-server" {
		t.Fatal(
			"DOCKER_CONTEXT=default resolved to the saved remote context; khaos would inject " +
				"on another machine while `docker compose` acted locally",
		)
	}

	if !strings.HasPrefix(resolved.Host, unixScheme) {
		t.Fatalf(
			"DOCKER_CONTEXT=default resolved to %q, want a local socket",
			resolved.Host,
		)
	}
}

// DOCKER_HOST still outranks DOCKER_CONTEXT, which is what the Docker CLI does.
// Measured: DOCKER_HOST=tcp://127.0.0.1:1 with DOCKER_CONTEXT=ag-server made the
// CLI try 127.0.0.1:1.
func TestDockerHostStillOutranksDockerContext(t *testing.T) {
	home := t.TempDir()
	writeContext(t, home, "ag-server", "ssh://ag-server")

	environ := func(name string) string {
		switch name {
		case EnvDockerHost:
			return "tcp://127.0.0.1:1"
		case EnvDockerContext:
			return "ag-server"
		}
		return ""
	}

	resolved, err := ResolveEndpoint(environ, home)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if resolved.Host != "tcp://127.0.0.1:1" {
		t.Fatalf(
			"resolved %q; the Docker CLI gives DOCKER_HOST precedence and khaos must match",
			resolved.Host,
		)
	}
}

func TestDockerConfigSelectsContextForSDKAndCompose(t *testing.T) {
	home, custom := t.TempDir(), t.TempDir()
	writeContext(t, home, ctxName, ctxHostValue)
	writeCurrentContext(t, home, ctxName)
	writeContext(t, custom, otherCtxName, otherCtxHost)
	writeCurrentContext(t, custom, otherCtxName)
	config := filepath.Join(custom, dockerDir)
	for _, explicit := range []string{"", otherCtxName} {
		env := map[string]string{
			EnvDockerConfig: config, EnvDockerContext: explicit,
		}
		got, err := ResolveEndpoint(fakeEnv(env), home)
		if err != nil || got.Host != otherCtxHost {
			t.Fatalf("custom config endpoint: %+v, %v", got, err)
		}
		composed, err := ComposeEnvironment([]string{
			EnvDockerConfig + "=" + config, EnvDockerContext + "=" + explicit,
		})
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(composed, "\n")
		if !strings.Contains(joined, EnvDockerHost+"="+got.Host) ||
			strings.Contains(joined, EnvDockerContext+"=") {
			t.Fatalf("Compose does not use SDK endpoint: %v", composed)
		}
	}
}

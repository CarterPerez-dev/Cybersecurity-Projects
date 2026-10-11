// ©AngelaMos | 2026
// rangelab_test.go

package rangelab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
)

func writeCompose(t *testing.T, body string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, composeFile)

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	return path
}

func TestOnlyKhaosOwnComposeFileIsAccepted(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		allowed bool
	}{
		{"khaos's own", "name: " + ProjectName + "\nservices: {}\n", true},
		{"quoted name", "name: \"" + ProjectName + "\"\n", true},
		{
			"a comment mentioning it does not count",
			"# name: " + ProjectName + "\nname: someone-else\n",
			false,
		},
		{
			"someone else's project",
			"name: my-production-stack\nservices: {}\n",
			false,
		},
		{
			"no project name at all",
			"services:\n  web:\n    image: nginx\n",
			false,
		},
		{
			"name nested under a service",
			"services:\n  web:\n    name: " + ProjectName + "\n",
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyOwned(writeCompose(t, tc.body))

			if tc.allowed && err != nil {
				t.Fatalf("khaos refused its own compose file: %v", err)
			}

			if !tc.allowed && !errors.Is(err, ErrNotOurs) {
				t.Fatalf(
					"got %v; pointing khaos at a compose file it does not own turns "+
						"`khaos range down` into `docker compose down --volumes` against that "+
						"project, which destroys its named volumes and reports success",
					err,
				)
			}
		})
	}
}

func TestAMissingComposeFileIsRefusedNotAssumed(t *testing.T) {
	if err := VerifyOwned(
		filepath.Join(t.TempDir(), composeFile),
	); !errors.Is(
		err,
		ErrNotOurs,
	) {
		t.Fatalf("got %v, want ErrNotOurs", err)
	}
}

func TestFreePortIsHighAndNotConstant(t *testing.T) {
	const samples = 50

	seen := make(map[int]bool, samples)

	for range samples {
		port, err := FreePort()
		if err != nil {
			t.Fatalf("free port: %v", err)
		}

		if port < portFloor || port >= portCeil {
			t.Fatalf(
				"port %d is outside [%d, %d); every host port khaos binds must be a "+
					"random high one, because the conventional port is the one already taken",
				port,
				portFloor,
				portCeil,
			)
		}

		seen[port] = true
	}

	if len(seen) == 1 {
		t.Fatal(
			"every call returned the same port, so the selection is not random",
		)
	}
}

type fakeReader struct {
	targets []dockerx.Target
	port    int
	environ map[string]string
	address string
	bridge  string
	err     error
}

func (f fakeReader) Targets(
	context.Context,
	dockerx.Filter,
) ([]dockerx.Target, error) {
	return f.targets, f.err
}

func (f fakeReader) PublishedPort(context.Context, string, int) (int, error) {
	return f.port, nil
}

func (f fakeReader) ContainerEnv(
	context.Context,
	string,
) (map[string]string, error) {
	return f.environ, nil
}

func (f fakeReader) NetworkAddress(
	context.Context,
	string,
	string,
) (string, error) {
	return f.address, nil
}

func (f fakeReader) BridgeGateway(context.Context) (string, error) {
	return f.bridge, nil
}

func gateway(running bool) dockerx.Target {
	return dockerx.Target{
		ID:        "abc",
		Name:      GatewayName,
		Project:   ProjectName,
		Running:   running,
		Inspected: true,
	}
}

func TestDiscoverRequiresARunningGateway(t *testing.T) {
	cases := []struct {
		name    string
		reader  fakeReader
		wantErr bool
	}{
		{
			"running",
			fakeReader{targets: []dockerx.Target{gateway(true)}, port: 41234},
			false,
		},
		{
			"stopped",
			fakeReader{targets: []dockerx.Target{gateway(false)}, port: 41234},
			true,
		},
		{"nothing at all", fakeReader{}, true},
		{"some other container", fakeReader{targets: []dockerx.Target{
			{ID: "x", Name: "unrelated", Project: ProjectName, Running: true},
		}}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lab, err := Discover(context.Background(), tc.reader)

			if tc.wantErr {
				if !errors.Is(err, ErrNoRange) {
					t.Fatalf(
						"got %v, want ErrNoRange so the operator is told to run `khaos range up` "+
							"rather than handed a bare Docker error",
						err,
					)
				}
				return
			}

			if err != nil {
				t.Fatalf("discover: %v", err)
			}

			if lab.Port != tc.reader.port {
				t.Fatalf("port = %d, want %d", lab.Port, tc.reader.port)
			}
		})
	}
}

func TestTheGatewayURLIsLoopbackOnly(t *testing.T) {
	lab := Lab{Port: 41234}

	for _, url := range []string{lab.GatewayURL(), lab.ProtectedURL()} {
		if got := url[:len("http://127.0.0.1")]; got != "http://127.0.0.1" {
			t.Fatalf(
				"%q is not loopback; the range is a deliberately vulnerable stack and must "+
					"never be reachable off the host",
				url,
			)
		}
	}
}

// ©AngelaMos | 2026
// build_test.go

package rangelab

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRangeBuildMustSucceedBeforeCreatingServices(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "successful build"
		if fail {
			name = "failed build"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			calls := filepath.Join(dir, "commands")
			binary := `#!/bin/sh
printf '%s\n' "$*" >> "$KHAOS_TEST_COMMANDS"
case " $* " in
  *" build "*)
    if [ "$KHAOS_TEST_BUILD_FAIL" = 1 ]; then
      printf '%s\n' 'fixture build failure' >&2
      exit 37
    fi
    ;;
esac
`
			if err := os.WriteFile(
				filepath.Join(dir, dockerBinary), []byte(binary), 0o700,
			); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("DOCKER_HOST", "unix:///unused-test-daemon.sock")
			t.Setenv("KHAOS_TEST_COMMANDS", calls)
			buildFail := "0"
			if fail {
				buildFail = "1"
			}
			t.Setenv("KHAOS_TEST_BUILD_FAIL", buildFail)

			server := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				},
			))
			defer server.Close()
			address, ok := server.Listener.Addr().(*net.TCPAddr)
			if !ok {
				t.Fatal("fixture health listener is not TCP")
			}
			lab := Lab{Dir: dir, Port: address.Port}
			err := lab.Up(t.Context(), io.Discard, "closed", "2s",
				"", "", "", "", "", false)
			if fail {
				if err == nil ||
					!strings.Contains(err.Error(), "fixture build failure") {
					t.Fatalf("build failure was lost: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			prefix := "compose -p " + ProjectName + " -f " +
				filepath.Join(dir, composeFile) + " "
			want := prefix + "build idp\n"
			if !fail {
				want += prefix + "up --no-build --detach --wait\n"
			}
			if string(data) != want {
				t.Fatalf("commands = %q, want %q", data, want)
			}
		})
	}
}

func TestEveryBuiltRangeServiceUsesTheSharedImage(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "range", composeFile))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Services map[string]struct {
			Image string         `yaml:"image"`
			Build map[string]any `yaml:"build"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	shared, ok := document.Services["idp"]
	if !ok || shared.Image == "" || len(shared.Build) == 0 {
		t.Fatal("range has no shared image build target")
	}
	for name, service := range document.Services {
		if len(service.Build) == 0 {
			continue
		}
		if service.Image != shared.Image ||
			!reflect.DeepEqual(service.Build, shared.Build) {
			t.Fatalf("%s needs a separate build before range startup", name)
		}
	}
}

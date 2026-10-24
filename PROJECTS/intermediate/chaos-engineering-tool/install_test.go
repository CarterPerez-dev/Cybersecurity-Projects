// ©AngelaMos | 2026
// install_test.go

package khaos

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type installerFixture struct {
	root   string
	bin    string
	prefix string
	script string
	env    []string
}

func newInstallerFixture(t *testing.T) installerFixture {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	home := filepath.Join(root, "home")
	for _, path := range []string{bin, home} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		"awk", "bash", "cat", "chmod", "cp", "dirname", "grep", "head",
		"id", "install", "ln", "mkdir", "mktemp", "mv", "readlink", "rm",
		"sha256sum", "sort", "tar", "gzip",
	} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	script, err := filepath.Abs("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	fixture := installerFixture{
		root: root, bin: bin, prefix: filepath.Join(home, "custom bin"),
		script: script,
		env: []string{
			"PATH=" + bin, "HOME=" + home, "SHELL=/bin/bash", "NO_COLOR=1",
			"XDG_CACHE_HOME=" + filepath.Join(root, "cache"),
			"KHAOS_TEST_ROOT=" + root,
		},
	}
	fixture.command(t, "uname", `case "$1" in
-s) printf '%s\n' "${KHAOS_TEST_SYSTEM:-Linux}" ;;
-m) printf '%s\n' "${KHAOS_TEST_ARCH:-x86_64}" ;;
esac
`)
	fixture.command(t, "curl", `cat >/dev/null
destination=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output) destination="$2"; shift 2 ;;
        http*) url="$1"; shift ;;
        *) shift ;;
    esac
done
case "$url" in
    */checksums.txt) cp "$KHAOS_TEST_ROOT/checksums.txt" "$destination" ;;
    */khaos_linux_amd64.tar.gz)
        [ "${KHAOS_TEST_MISSING_RELEASE:-0}" = 0 ] || exit 22
        cp "$KHAOS_TEST_ROOT/release.tar.gz" "$destination"
        ;;
    *) exit 22 ;;
esac
`)
	fixture.command(
		t,
		"docker",
		`printf '%s\n' "$*" >> "$KHAOS_TEST_ROOT/docker-calls"
case "$*" in
    "compose version") exit 0 ;;
    "info") exit "${KHAOS_TEST_DOCKER_FAILURE:-0}" ;;
    "context inspect"*) printf '%s\n' 'tcp://example.invalid:2376' ;;
    *) exit 99 ;;
esac
`,
	)
	fixture.archive(t, "#!/bin/bash\nprintf 'khaos fixture\n'\n")
	return fixture
}

func (f installerFixture) command(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.bin, name),
		[]byte("#!/bin/bash\nset -eu\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func (f installerFixture) archive(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(f.root, "release.tar.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{
		Name: "khaos", Mode: 0o755, Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	for _, close := range []func() error{
		archive.Close, compressed.Close, file.Close,
	} {
		if err := close(); err != nil {
			t.Fatal(err)
		}
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	checksum := fmt.Sprintf("%x  khaos_linux_amd64.tar.gz\n",
		sha256.Sum256(contents))
	if err := os.WriteFile(filepath.Join(f.root, "checksums.txt"),
		[]byte(checksum), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f installerFixture) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "/bin/bash",
		append([]string{f.script}, args...)...)
	cmd.Dir = f.root
	cmd.Env = f.env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestInstallerHelpAndInvalidArgumentsHaveNoSideEffects(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"--unknown"},
		{"--prefix"},
		{"--version"},
		{"--prefix="},
		{"--version=not-a-tag"},
		{"--prefix", "relative"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fixture := newInstallerFixture(t)
			output, err := fixture.run(t, args...)
			if (err == nil) != (args[0] == "--help") {
				t.Fatalf("exit = %v: %s", err, output)
			}
			if _, err := os.Stat(fixture.prefix); !os.IsNotExist(err) {
				t.Fatal("argument handling changed the install directory")
			}
		})
	}
}

func TestPipedInstallerMakesBareNameWorkInTheParentShell(t *testing.T) {
	fixture := newInstallerFixture(t)
	cmd := exec.CommandContext(t.Context(), "/bin/bash", "-c",
		`set -euo pipefail
cat "$1" | bash -s -- --prefix "$2"
khaos version
cat "$1" | bash -s -- --prefix "$2"
khaos version
`, "test", fixture.script, fixture.prefix)
	cmd.Dir = fixture.root
	cmd.Env = fixture.env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("piped install: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "\x1b[") {
		t.Fatal("redirected output contains terminal color escapes")
	}
	configuration, err := os.ReadFile(
		filepath.Join(fixture.root, "home", ".bashrc"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(configuration), "export PATH=") != 1 {
		t.Fatalf("PATH setup was not idempotent: %s", configuration)
	}
	calls, err := os.ReadFile(filepath.Join(fixture.root, "docker-calls"))
	if err != nil || strings.Contains(string(calls), "start") {
		t.Fatalf("running Docker was changed: %s, %v", calls, err)
	}
}

func TestInstallerRejectsBadChecksumBeforeReplacingExistingBinary(
	t *testing.T,
) {
	fixture := newInstallerFixture(t)
	if err := os.MkdirAll(fixture.prefix, 0o700); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(fixture.prefix, "khaos")
	if err := os.WriteFile(installed, []byte("original"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(fixture.root, "checksums.txt"),
		[]byte(
			strings.Repeat("0", 64)+"  khaos_linux_amd64.tar.gz\n",
		),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	output, err := fixture.run(t, "--prefix", fixture.prefix)
	if err == nil || !strings.Contains(output, "Checksum mismatch") {
		t.Fatalf("corrupt release accepted: %v\n%s", err, output)
	}
	contents, err := os.ReadFile(installed)
	if err != nil || string(contents) != "original" {
		t.Fatal("checksum failure replaced the existing installation")
	}
}

func TestMissingReleaseBuildsStaticSource(t *testing.T) {
	fixture := newInstallerFixture(t)
	source, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	fixture.env = append(fixture.env, "KHAOS_TEST_MISSING_RELEASE=1",
		"KHAOS_SOURCE_DIR="+source)
	fixture.command(
		t,
		"go",
		`if [ "$1" = env ]; then printf 'go1.26.5\n'; exit; fi
[ "$1" = build ] && [ "$CGO_ENABLED" = 0 ] || exit 81
while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then destination="$2"; break; fi
    shift
done
printf '#!/bin/bash\nprintf "khaos source-fixture\\n"\n' > "$destination"
chmod 0755 "$destination"
`,
	)
	output, err := fixture.run(t, "--no-docker", "--prefix", fixture.prefix)
	if err != nil || !strings.Contains(output, "khaos source-fixture") {
		t.Fatalf("source fallback failed: %v\n%s", err, output)
	}
}

func TestInstallerFallsBackToWget(t *testing.T) {
	fixture := newInstallerFixture(t)
	if err := os.Remove(filepath.Join(fixture.bin, "curl")); err != nil {
		t.Fatal(err)
	}
	fixture.command(t, "wget", `destination=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-document=*) destination="${1#*=}" ;;
        http*) url="$1" ;;
    esac
    shift
done
case "$url" in
    */checksums.txt) cp "$KHAOS_TEST_ROOT/checksums.txt" "$destination" ;;
    *) cp "$KHAOS_TEST_ROOT/release.tar.gz" "$destination" ;;
esac
`)
	output, err := fixture.run(t, "--no-docker", "--prefix", fixture.prefix)
	if err != nil || !strings.Contains(output, "Installed khaos") {
		t.Fatalf("wget fallback failed: %v\n%s", err, output)
	}
}

func TestInstallerRefusesBrokenReleaseAndUnsupportedPlatform(t *testing.T) {
	for _, scenario := range []string{"broken executable", "macOS", "architecture", "remote Docker"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newInstallerFixture(t)
			switch scenario {
			case "broken executable":
				fixture.archive(t, "#!/bin/bash\nexit 19\n")
			case "macOS":
				fixture.env = append(fixture.env, "KHAOS_TEST_SYSTEM=Darwin")
			case "architecture":
				fixture.env = append(fixture.env, "KHAOS_TEST_ARCH=ppc64le")
			case "remote Docker":
				fixture.env = append(
					fixture.env,
					"DOCKER_HOST=tcp://example.invalid:2376",
					"KHAOS_TEST_DOCKER_FAILURE=1",
				)
			}
			output, err := fixture.run(t, "--prefix", fixture.prefix)
			if err == nil {
				t.Fatalf("invalid installation reported success: %s", output)
			}
			if _, err := os.Stat(fixture.prefix); !os.IsNotExist(err) {
				t.Fatal("refused setup installed an executable")
			}
		})
	}
}

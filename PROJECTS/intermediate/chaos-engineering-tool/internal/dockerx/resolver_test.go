// ©AngelaMos | 2026
// resolver_test.go

package dockerx

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestStaticELFRejectsADynamicBinary is the two-sided control for the guard
// that decides whether `khaos resolver up` can work at all.
//
// It matters because the failure it prevents is invisible until the worst
// moment: khaos imports its own binary as a one-layer image with no base, the
// container starts, and a dynamically linked binary dies looking for
// `/lib64/ld-linux-x86-64.so.2` — an error about a loader path the operator
// never typed, in the middle of an experiment.
//
// Both halves are built here rather than asserted against the test binary,
// because `/proc/self/exe` under `go test` is whatever the toolchain happened
// to produce and a guard checked against one linkage proves nothing about the
// other.
func TestStaticELFRejectsADynamicBinary(t *testing.T) {
	dir := t.TempDir()

	build := func(cgo string) string {
		t.Helper()

		out := filepath.Join(dir, "khaos-"+cgo)

		cmd := exec.Command("go", "build", "-o", out, "../../cmd/khaos")
		cmd.Env = append(os.Environ(), "CGO_ENABLED="+cgo)

		if output, err := cmd.CombinedOutput(); err != nil {
			t.Skipf(
				"cannot build with CGO_ENABLED=%s: %v: %s",
				cgo,
				err,
				output,
			)
		}

		return out
	}

	static := build("0")

	if err := staticELF(static); err != nil {
		t.Errorf("a CGO_ENABLED=0 build was rejected: %v", err)
	}

	dynamic := build("1")

	err := staticELF(dynamic)
	if err == nil {
		t.Fatal(
			"a dynamically linked binary was accepted as its own container " +
				"image, so the guard cannot detect the build it exists to refuse",
		)
	}

	if !errors.Is(err, ErrDynamicSelf) {
		t.Errorf("error %v, want %v", err, ErrDynamicSelf)
	}

	for _, want := range []string{
		"CGO_ENABLED=0",
		"resolver up",
		"already exists",
		"secret_file_",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal never mentions %q: %v", want, err)
		}
	}
}

// TestStaticELFRefusesWhatItCannotRead keeps a missing or unreadable file from
// reading as a static binary, which would let the import proceed and fail later.
func TestStaticELFRefusesWhatItCannotRead(t *testing.T) {
	if err := staticELF(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a file that does not exist passed as a static binary")
	}

	notELF := filepath.Join(t.TempDir(), "notelf")
	if err := os.WriteFile(
		notELF,
		[]byte("#!/bin/sh\necho hi\n"),
		0o600,
	); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := staticELF(notELF); err == nil {
		t.Fatal("a shell script passed as a static binary")
	}
}

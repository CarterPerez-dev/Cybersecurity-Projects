// ©AngelaMos | 2026
// lock_unix_test.go

package lock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	envHolder   = "KHAOS_TEST_LOCK_HOLDER"
	envPath     = "KHAOS_TEST_LOCK_PATH"
	holdFor     = 10 * time.Second
	readyMarker = "HELD"
)

func TestMain(m *testing.M) {
	if os.Getenv(envHolder) == "" {
		os.Exit(m.Run())
	}

	held, err := Acquire(os.Getenv(envPath))
	if err != nil {
		os.Exit(1)
	}

	_, _ = os.Stdout.WriteString(readyMarker + "\n")
	time.Sleep(holdFor)
	_ = held.Release()
	os.Exit(0)
}

func lockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "khaos.lock")
}

func holderProcess(t *testing.T, path string) *exec.Cmd {
	t.Helper()

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), envHolder+"=1", envPath+"="+path)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start holder: %v", err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	buf := make([]byte, len(readyMarker)+1)
	if _, err := stdout.Read(buf); err != nil {
		t.Fatalf("holder never signalled it had the lock: %v", err)
	}

	return cmd
}

func TestASecondAcquireIsRefused(t *testing.T) {
	path := lockPath(t)

	first, err := Acquire(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer func() { _ = first.Release() }()

	second, err := Acquire(path)
	if err == nil {
		_ = second.Release()
		t.Fatal(
			"two khaos instances held the lock at once, so both could inject into the same target",
		)
	}

	if !errors.Is(err, ErrHeld) {
		t.Fatalf("got %v, want an error wrapping ErrHeld", err)
	}
}

func TestTheRefusalNamesTheHoldingProcessAndTheFix(t *testing.T) {
	path := lockPath(t)
	holder := holderProcess(t, path)

	_, err := Acquire(path)
	if err == nil {
		t.Fatal("acquired a lock another process was holding")
	}

	wantPid := strconv.Itoa(holder.Process.Pid)
	if !strings.Contains(err.Error(), wantPid) {
		t.Fatalf(
			"the refusal %q does not name the holding pid %s, so the operator cannot find it",
			err,
			wantPid,
		)
	}

	if !strings.Contains(err.Error(), "khaos reclaim") {
		t.Fatalf("the refusal %q names a cause but no fix", err)
	}
}

func TestTheLockIsReleasedWhenTheHolderIsKilled(t *testing.T) {
	path := lockPath(t)
	holder := holderProcess(t, path)

	if _, err := Acquire(path); err == nil {
		t.Fatal("the lock was free while a holder was alive")
	}

	if err := holder.Process.Kill(); err != nil {
		t.Fatalf("kill holder: %v", err)
	}
	_ = holder.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if held, err := Acquire(path); err == nil {
			_ = held.Release()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal(
		"the lock stayed held after its owner was killed; flock was chosen precisely " +
			"so the kernel releases it, and a stale lock would block every later khaos run",
	)
}

func TestReleaseAllowsReacquisition(t *testing.T) {
	path := lockPath(t)

	first, err := Acquire(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	if err := first.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	second, err := Acquire(path)
	if err != nil {
		t.Fatalf("the lock was not released: %v", err)
	}

	if err := second.Release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

func TestAcquireCreatesTheStateDirectoryPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deeper", "khaos.lock")

	held, err := Acquire(path)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = held.Release() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("lock file was not created: %v", err)
	}

	if info.Mode().Perm() != fileMode {
		t.Fatalf(
			"lock mode is %v, want %v",
			info.Mode().Perm(),
			os.FileMode(fileMode),
		)
	}

	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}

	if dir.Mode().Perm() != dirMode {
		t.Fatalf(
			"state directory mode is %v, want %v",
			dir.Mode().Perm(),
			os.FileMode(dirMode),
		)
	}
}

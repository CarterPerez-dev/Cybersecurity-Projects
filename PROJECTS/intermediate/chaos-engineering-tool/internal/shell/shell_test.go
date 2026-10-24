// ©AngelaMos | 2026
// shell_test.go

package shell

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/lock"
	"github.com/CarterPerez-dev/khaos/internal/statedir"
	"github.com/spf13/cobra"
)

func TestConsolePreservesCredentialBackslashes(t *testing.T) {
	app := newConsole(io.Discard)
	menu := app.ActiveMenu()
	var got []string
	menu.SetCommands(func() *cobra.Command {
		root := &cobra.Command{Use: "khaos"}
		root.AddCommand(&cobra.Command{
			Use: "capture",
			Run: func(_ *cobra.Command, args []string) { got = args },
		})
		return root
	})
	err := menu.RunCommandLine(
		context.Background(), `capture C:\secrets\ "a b" password\`,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`C:\secrets\`, "a b", `password\`}
	if !slices.Equal(got, want) {
		t.Fatalf("arguments = %q, want %q", got, want)
	}
}

// busy holds the instance lock for the duration of a test, which is what a live
// run holds while it owns a fault. The state dir is redirected first so the
// test cannot take the lock out from under a khaos the operator is running.
func busy(t *testing.T) {
	t.Helper()

	t.Setenv(statedir.EnvStateDir, t.TempDir())

	paths, err := statedir.Default()
	if err != nil {
		t.Fatalf("resolve the state dir: %v", err)
	}

	held, err := lock.Acquire(paths.Lock())
	if err != nil {
		t.Fatalf("hold the instance lock: %v", err)
	}

	t.Cleanup(func() { _ = held.Release() })
}

func TestIdleIsFalseWhileARunHoldsTheLock(t *testing.T) {
	busy(t)

	if idle() {
		t.Fatal(
			"idle() was true while the instance lock was held, so every guard " +
				"built on it is inert and the rest of this file proves nothing",
		)
	}
}

// The bug this test exists for: the EOF interrupt discarded leave's error, so
// Ctrl-D while a fault was outstanding printed NOTHING and did not exit. The
// `exit` command explained itself through the same guard, which is what made
// the silence a defect rather than a design.
//
// Only the refusal path is exercised. The accepting path ends in os.Exit, which
// cannot be observed from inside the test binary.
func TestInterruptSaysWhyItWillNotLeave(t *testing.T) {
	busy(t)

	var out bytes.Buffer

	leaveOrSayWhyNot(&out)

	said := out.String()

	if said == "" {
		t.Fatal(
			"the interrupt path printed nothing while a fault was outstanding; " +
				"an operator who gets no answer concludes the key did not register",
		)
	}

	if !strings.Contains(said, ErrBusy.Error()) {
		t.Fatalf(
			"the interrupt path printed %q, which does not carry ErrBusy; the "+
				"operator needs the reason, not just some output",
			said,
		)
	}
}

// Both ways out have to give the same answer. The exit command and the EOF
// interrupt share one guard, so a reader comparing them must not find two
// different behaviours for the same outstanding fault.
func TestExitAndInterruptRefuseAlike(t *testing.T) {
	busy(t)

	var typed bytes.Buffer

	command := newExitCmd(&typed)
	command.SetOut(&typed)
	command.SetErr(&typed)

	commandErr := command.RunE(command, nil)
	if commandErr == nil {
		t.Fatal("`exit` returned no error while a fault was outstanding")
	}

	var interrupted bytes.Buffer

	leaveOrSayWhyNot(&interrupted)

	if !strings.Contains(interrupted.String(), commandErr.Error()) {
		t.Fatalf(
			"`exit` refused with %q but the interrupt said %q; one guard has to "+
				"produce one answer",
			commandErr,
			interrupted.String(),
		)
	}
}

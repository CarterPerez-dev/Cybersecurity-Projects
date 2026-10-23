// ©AngelaMos | 2026
// main_test.go

package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/cli"
	"github.com/CarterPerez-dev/khaos/internal/run"
)

func notATTY(t *testing.T) *os.File {
	t.Helper()

	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = f.Close() })

	return f
}

func pipeEnd(t *testing.T) *os.File {
	t.Helper()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})

	return reader
}

func TestInteractiveRefusesEveryNonTerminalCombination(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		stdin  func(*testing.T) *os.File
		stdout func(*testing.T) *os.File
	}{
		{"piped stdin, devnull stdout", nil, pipeEnd, notATTY},
		{"devnull stdin, devnull stdout", nil, notATTY, notATTY},
		{"piped stdin only", nil, pipeEnd, notATTY},
		{"args present", []string{"version"}, notATTY, notATTY},
		{"args present with a pipe", []string{"targets"}, pipeEnd, notATTY},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if interactive(tc.args, tc.stdin(t), tc.stdout(t)) {
				t.Fatal(
					"interactive() said yes without a terminal on both ends; " +
						"the console spins forever on a non-TTY stdin, writing megabytes per second",
				)
			}
		})
	}
}

func TestInteractiveChecksStdinNotOnlyStdout(t *testing.T) {
	stdin := pipeEnd(t)
	stdout := notATTY(t)

	if interactive(nil, stdin, stdout) {
		t.Fatal("a piped stdin was accepted as interactive")
	}

	if interactive([]string{"version"}, stdin, stdout) {
		t.Fatal("arguments did not force the one-shot path")
	}
}

func TestNoColorFlagAcceptsEverySpellingPflagDoes(t *testing.T) {
	cases := []struct {
		arg  string
		want bool
	}{
		{"--no-color", true},
		{"--no-color=true", true},
		{"--no-color=TRUE", true},
		{"--no-color=True", true},
		{"--no-color=t", true},
		{"--no-color=T", true},
		{"--no-color=1", true},
		{"--no-color=false", false},
		{"--no-color=F", false},
		{"--no-color=0", false},
		{"--no-colour", false},
		{"--color", false},
	}

	for _, tc := range cases {
		t.Run(tc.arg, func(t *testing.T) {
			if got := noColorRequested(
				[]string{"banner", tc.arg},
			); got != tc.want {
				t.Fatalf(
					"noColorRequested(%q) = %v, want %v; cobra and this pre-parser must agree "+
						"or the flag is accepted and silently ignored",
					tc.arg,
					got,
					tc.want,
				)
			}
		})
	}
}

func TestNoColorIsAbsentByDefault(t *testing.T) {
	if noColorRequested([]string{"targets", "--project", "shop"}) {
		t.Fatal("no-color was inferred from unrelated arguments")
	}
}

// Exit-code priority. Anything about the state khaos left the target in has to
// outrank anything about the verdict, and both outrank interruption.
//
// Cancellation used to be checked first, so a run that was interrupted AND
// failed to revert its fault reported "interrupted" and dropped the rollback
// failure entirely. errors.Join carries both; the first branch simply won.
func TestRollbackFailureOutranksEveryOtherExitCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"rollback alone", run.ErrRevertFailed, exitRevertFailed},
		{
			"rollback joined with cancellation",
			errors.Join(context.Canceled, run.ErrRevertFailed),
			exitRevertFailed,
		},
		{
			"rollback joined with a defect",
			errors.Join(cli.ErrDefectFound, run.ErrRevertFailed),
			exitRevertFailed,
		},
		{
			"rollback joined with inconclusive",
			errors.Join(cli.ErrInconclusive, run.ErrRevertFailed),
			exitRevertFailed,
		},
		{
			"a target that never came back",
			cli.ErrNotRecovered,
			exitRevertFailed,
		},
		{"cancellation alone", context.Canceled, exitInterrupted},

		// A finished run arrives carrying its own code, which is the shape
		// exitFor actually produces. The bare sentinels below it reach here
		// only from paths that never got a verdict.
		{
			"a defect carrying its code",
			&cli.Exit{
				Code:    cli.CodeDefect,
				Outcome: cli.OutcomeDefect,
				Err:     cli.ErrDefectFound,
			},
			cli.CodeDefect,
		},
		{
			"a rollback failure carrying its code",
			&cli.Exit{
				Code: cli.CodeRollback,
				Err:  run.ErrRevertFailed,
			},
			exitRevertFailed,
		},
		{
			"an interrupted run carrying its code",
			&cli.Exit{
				Code:    cli.CodeInterrupted,
				Outcome: cli.OutcomeInterrupted,
				Err:     cli.ErrInconclusive,
			},
			cli.CodeInterrupted,
		},
		{
			"a carried code joined with a rollback failure",
			errors.Join(
				&cli.Exit{Code: cli.CodeDefect, Err: cli.ErrDefectFound},
				run.ErrRevertFailed,
			),
			exitRevertFailed,
		},
		{"defect alone, with no code", cli.ErrDefectFound, exitError},
		{"anything else", errors.New("something broke"), exitError},
	}

	for _, each := range cases {
		t.Run(each.name, func(t *testing.T) {
			if got := fail(each.err); got != each.want {
				t.Fatalf("fail(%v) = %d, want %d", each.err, got, each.want)
			}
		})
	}
}

// A bug has to exit 70 rather than with whatever status the runtime chose.
// The deferred cleanup matters more than the code: the panic still unwinds
// every frame, so an applied fault is still reverted on the way out.
func TestAPanicBecomesTheInternalCodeWithCleanupIntact(t *testing.T) {
	reverted := false

	code := guarded(func() int {
		defer func() { reverted = true }()

		panic("a bug in khaos")
	})

	if code != cli.CodeInternal {
		t.Errorf(
			"a recovered panic exited %d, want %d: the taxonomy publishes 70 for exactly this",
			code,
			cli.CodeInternal,
		)
	}

	if !reverted {
		t.Error(
			"a deferred revert did not run while the panic unwound, so khaos would leave the fault applied",
		)
	}
}

// And the boundary is not a blanket: an ordinary run's code passes through
// untouched, or every exit in the taxonomy would collapse to 70.
func TestTheGuardLeavesAnOrdinaryExitAlone(t *testing.T) {
	for _, want := range []int{
		cli.CodeOK,
		cli.CodeDefect,
		cli.CodeRollback,
	} {
		if got := guarded(func() int { return want }); got != want {
			t.Errorf("guarded changed exit %d into %d", want, got)
		}
	}
}

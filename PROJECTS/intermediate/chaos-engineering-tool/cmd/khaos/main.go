// ©AngelaMos | 2026
// main.go

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"github.com/CarterPerez-dev/khaos/internal/cli"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/run"
	"github.com/CarterPerez-dev/khaos/internal/shell"
	"github.com/CarterPerez-dev/khaos/internal/theme"
	"github.com/CarterPerez-dev/khaos/internal/version"
	"golang.org/x/term"
)

const (
	exitOK = cli.CodeOK

	// The catch-all. A bad flag, an unreadable config and an error khaos has
	// no taxonomy entry for are all the operator's to fix before measuring.
	exitError = cli.CodeUsage

	exitInterrupted  = cli.CodeInterrupted
	exitRevertFailed = cli.CodeRollback

	noColorFlag     = "--" + cli.FlagNoColor
	noColorFlagTrue = noColorFlag + "="
	errorFormat     = "%s: %v\n"
	fixFormat       = "       fix: %s\n"
	panicFormat     = "       cause: %v\n"
)

var internalFailure = errors.New(
	"khaos hit a bug and stopped; run `khaos reclaim` to verify recovery and retry any unfinished rollback",
)

var errInterrupted = errors.New(
	"interrupted before the run could reach a verdict",
)

func main() {
	os.Exit(guarded(execute))
}

// guarded is the boundary that makes CodeInternal reachable, so a bug exits
// 70 rather than with whatever status the runtime chose.
//
// Recovering HERE and nowhere deeper is deliberate: the panic still unwinds
// every frame below, so every deferred revert, lease release and lock
// handoff runs as it does on any other error path.
func guarded(run func() int) (code int) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}

		fmt.Fprintf(os.Stderr, errorFormat, version.Name, internalFailure)
		fmt.Fprintf(os.Stderr, panicFormat, recovered)
		fmt.Fprint(os.Stderr, string(debug.Stack()))

		code = cli.CodeInternal
	}()

	return run()
}

func execute() int {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	args := os.Args[1:]
	out := theme.NewWriter(os.Stdout, os.Environ(), noColorRequested(args))

	if interactive(args, os.Stdin, os.Stdout) {
		if err := shell.Run(ctx, out); err != nil {
			return fail(err)
		}
		return exitOK
	}

	root := cli.NewRoot()
	root.SetOut(out)
	root.SetErr(os.Stderr)
	root.SetArgs(args)

	if err := root.ExecuteContext(ctx); err != nil {
		return fail(err)
	}

	return exitOK
}

func interactive(args []string, stdin, stdout *os.File) bool {
	if len(args) > 0 {
		return false
	}
	return term.IsTerminal(fd(stdin)) && term.IsTerminal(fd(stdout))
}

// fd narrows a descriptor for the syscall wrappers that want an int.
// RLIMIT_NOFILE bounds it far below MaxInt, so it cannot overflow.
func fd(file *os.File) int {
	return int(file.Fd()) //nolint:gosec // bounded by RLIMIT_NOFILE
}

func noColorRequested(args []string) bool {
	for _, arg := range args {
		if arg == noColorFlag {
			return true
		}
		if value, ok := strings.CutPrefix(arg, noColorFlagTrue); ok {
			parsed, err := strconv.ParseBool(value)
			return err == nil && parsed
		}
	}
	return false
}

// fail maps an error to an exit code, and the ORDER is the contract: the state
// khaos left the target in outranks the verdict, and both outrank interruption.
// errors.Join carries several at once, so the first match decides.
//
// A finished run arrives carrying its own code, because the precedence among
// verdict outcomes is decided once where the run ends rather than re-derived
// by a chain here that grows with every epistemic value. The checks below it
// are for errors that never reached a verdict at all.
// fail decides what the operator READS. What the process RETURNS is decided
// by cli.ExitCode, the same classification the run record carries, so the
// status and the artifact cannot disagree.
func fail(err error) int {
	code := cli.ExitCode(err)

	// Cancellation gets its own wording, because "context canceled" is Go's
	// phrasing for a decision the operator made.
	if errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, errorFormat, version.Name, errInterrupted)

		return code
	}

	fmt.Fprintf(os.Stderr, errorFormat, version.Name, err)

	// The fix line is for a refusal that names one, which is every refusal
	// predicate and every unrevertable fault.
	if errors.Is(err, run.ErrRevertFailed) || code == exitError {
		printFix(err)
	}

	return code
}

func printFix(err error) {
	var refusal *dockerx.Refusal
	if errors.As(err, &refusal) && refusal.Fix != "" {
		fmt.Fprintf(os.Stderr, fixFormat, refusal.Fix)
	}
}

// ©AngelaMos | 2026
// main.go

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
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
	exitOK     = 0
	exitError  = 1
	exitDefect = 2

	// Design section 8 assigns 4 to an inconclusive run. An interrupted run is a
	// kind of inconclusive one, and Chaos Toolkit's lattice keeps `interrupted`
	// on the same epistemic axis, so they share it until M10 builds the full
	// taxonomy out. What matters here is that neither is 0.
	exitInconclusive = 4
	exitInterrupted  = 4

	exitRevertFailed = 6

	noColorFlag     = "--" + cli.FlagNoColor
	noColorFlagTrue = noColorFlag + "="
	errorFormat     = "%s: %v\n"
	fixFormat       = "       fix: %s\n"
)

var errInterrupted = errors.New(
	"interrupted before the run could reach a verdict",
)

func main() {
	os.Exit(execute())
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

// fd narrows a descriptor for the syscall wrappers that want an int. A file
// descriptor is bounded by RLIMIT_NOFILE, orders of magnitude below MaxInt, so
// the conversion cannot overflow.
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

// fail maps an error to an exit code, and the ORDER is the contract.
//
// Anything about the state khaos left the target in outranks anything about the
// verdict, and both outrank interruption. Cancellation used to be checked first,
// so an interrupted run that ALSO failed to revert its fault returned
// "interrupted" and silently dropped the rollback failure — the one outcome an
// operator must never miss, hidden by the one they already know about, because
// `errors.Join` carries both and the first branch won.
func fail(err error) int {
	if errors.Is(err, run.ErrRevertFailed) {
		fmt.Fprintf(os.Stderr, errorFormat, version.Name, err)
		printFix(err)
		return exitRevertFailed
	}

	if errors.Is(err, cli.ErrNotRecovered) {
		fmt.Fprintf(os.Stderr, errorFormat, version.Name, err)
		return exitRevertFailed
	}

	if errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, errorFormat, version.Name, errInterrupted)
		return exitInterrupted
	}

	fmt.Fprintf(os.Stderr, errorFormat, version.Name, err)
	printFix(err)

	if errors.Is(err, cli.ErrDefectFound) {
		return exitDefect
	}

	if errors.Is(err, cli.ErrInconclusive) {
		return exitInconclusive
	}

	return exitError
}

func printFix(err error) {
	var refusal *dockerx.Refusal
	if errors.As(err, &refusal) && refusal.Fix != "" {
		fmt.Fprintf(os.Stderr, fixFormat, refusal.Fix)
	}
}

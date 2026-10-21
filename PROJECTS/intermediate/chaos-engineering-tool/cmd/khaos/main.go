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
func fail(err error) int {
	if errors.Is(err, run.ErrRevertFailed) {
		fmt.Fprintf(os.Stderr, errorFormat, version.Name, err)
		printFix(err)
		return exitRevertFailed
	}

	// Checked before the carried code as well as inside it: this is the one
	// outcome nothing may suppress, so it is matched on the sentinel too and
	// not only on a code some other layer computed.
	if errors.Is(err, cli.ErrNotRecovered) {
		fmt.Fprintf(os.Stderr, errorFormat, version.Name, err)
		return exitRevertFailed
	}

	var exit *cli.Exit
	if errors.As(err, &exit) {
		fmt.Fprintf(os.Stderr, errorFormat, version.Name, err)
		return exit.Code
	}

	if errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, errorFormat, version.Name, errInterrupted)
		return exitInterrupted
	}

	fmt.Fprintf(os.Stderr, errorFormat, version.Name, err)
	printFix(err)

	return exitError
}

func printFix(err error) {
	var refusal *dockerx.Refusal
	if errors.As(err, &refusal) && refusal.Fix != "" {
		fmt.Fprintf(os.Stderr, fixFormat, refusal.Fix)
	}
}

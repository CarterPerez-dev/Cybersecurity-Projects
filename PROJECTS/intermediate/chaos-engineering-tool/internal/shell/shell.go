// ©AngelaMos | 2026
// shell.go

package shell

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/reeflective/console"
	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/khaos/internal/banner"
	"github.com/CarterPerez-dev/khaos/internal/cli"
	"github.com/CarterPerez-dev/khaos/internal/lock"
	"github.com/CarterPerez-dev/khaos/internal/statedir"
	"github.com/CarterPerez-dev/khaos/internal/version"
)

const (
	historyName = "local"
	historyFile = ".khaos_history"

	exitShort = "leave the khaos console"
	exitLong  = `exit leaves the console.

It refuses while a fault is still applied or still being reverted, because
leaving at that moment would abandon the rollback and report success.`

	newline  = "\n"
	exitCode = 0
)

var ErrBusy = errors.New("a khaos run is still holding or reverting a fault; wait for it to finish, then exit again")

func Run(ctx context.Context, out io.Writer) error {
	app := console.New(version.Name)
	app.NewlineBefore = true
	app.NewlineAfter = true

	app.SetPrintLogo(func(*console.Console) {
		_ = banner.Write(out)
	})

	menu := app.ActiveMenu()
	menu.SetCommands(func() *cobra.Command {
		root := cli.NewRoot()
		root.SetOut(out)
		root.SetErr(out)
		root.AddCommand(newExitCmd(out))
		return root
	})

	menu.AddInterrupt(io.EOF, func(*console.Console) {
		leave(out)
	})

	if path, ok := historyPath(); ok {
		menu.AddHistorySourceFile(historyName, path)
	}

	return app.StartContext(ctx)
}

func newExitCmd(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:     "exit",
		Aliases: []string{"quit"},
		Short:   exitShort,
		Long:    exitLong,
		Args:    cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return leave(out)
		},
	}
}

func leave(out io.Writer) error {
	if !idle() {
		return ErrBusy
	}

	_, _ = io.WriteString(out, newline)
	os.Exit(exitCode)

	return nil
}

func idle() bool {
	paths, err := statedir.Default()
	if err != nil {
		return true
	}

	held, err := lock.Acquire(paths.Lock())
	if err != nil {
		return false
	}

	return held.Release() == nil
}

func historyPath() (string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false
	}
	return filepath.Join(home, historyFile), true
}

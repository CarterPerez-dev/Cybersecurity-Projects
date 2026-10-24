// ©AngelaMos | 2026
// root_test.go

package cli

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
)

func silence(cmd *cobra.Command) {
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
}

func TestFreshTreeDoesNotInheritFlagState(t *testing.T) {
	first := NewRoot()
	silence(first)
	first.SetArgs([]string{"version", "--" + FlagNoColor})

	if err := first.Execute(); err != nil {
		t.Fatalf("first execute: %v", err)
	}

	if set, err := first.PersistentFlags().
		GetBool(FlagNoColor); err != nil ||
		!set {
		t.Fatalf("first tree did not record the flag (set=%v err=%v)", set, err)
	}

	second := NewRoot()
	silence(second)
	second.SetArgs([]string{"version"})

	if err := second.Execute(); err != nil {
		t.Fatalf("second execute: %v", err)
	}

	set, err := second.PersistentFlags().GetBool(FlagNoColor)
	if err != nil {
		t.Fatalf("second tree flag lookup: %v", err)
	}

	if set {
		t.Fatal(
			"a freshly built tree inherited --no-color from a previous invocation",
		)
	}
}

func TestSharedTreeLeaksFlagState(t *testing.T) {
	shared := NewRoot()
	silence(shared)

	shared.SetArgs([]string{"version", "--" + FlagNoColor})
	if err := shared.Execute(); err != nil {
		t.Fatalf("first execute: %v", err)
	}

	shared.SetArgs([]string{"version"})
	if err := shared.Execute(); err != nil {
		t.Fatalf("second execute: %v", err)
	}

	set, err := shared.PersistentFlags().GetBool(FlagNoColor)
	if err != nil {
		t.Fatalf("flag lookup: %v", err)
	}

	if !set {
		t.Fatal(
			"cobra no longer leaks flag state across invocations on a shared tree, " +
				"which means TestFreshTreeDoesNotInheritFlagState proves nothing and the " +
				"factory may no longer be load bearing",
		)
	}
}

func TestEveryCommandRejectsStrayArguments(t *testing.T) {
	registered := NewRoot().Commands()
	if len(registered) < 4 {
		t.Fatalf(
			"only %d commands registered; this test is named 'every' and must cover them all",
			len(registered),
		)
	}

	for _, cmd := range registered {
		name := cmd.Name()
		if cmd.Args == nil {
			t.Fatalf(
				"%s declares no Args validator, so it silently accepts stray positional arguments",
				name,
			)
		}
	}

	for _, name := range []string{"version", "banner", "doctor", "targets"} {
		t.Run(name, func(t *testing.T) {
			root := NewRoot()
			silence(root)
			root.SetArgs([]string{name, "unexpected"})

			if err := root.Execute(); err == nil {
				t.Fatalf("%s accepted a stray positional argument", name)
			}
		})
	}
}

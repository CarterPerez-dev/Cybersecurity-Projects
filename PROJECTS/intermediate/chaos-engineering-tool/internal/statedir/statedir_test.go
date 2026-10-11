// ©AngelaMos | 2026
// statedir_test.go

package statedir

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestResolvePrecedence(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		home string
		want string
	}{
		{"explicit override wins", map[string]string{
			EnvStateDir: "/tmp/explicit",
			EnvXDGState: "/home/op/.state",
		}, "/home/op", "/tmp/explicit"},
		{
			"xdg state home",
			map[string]string{EnvXDGState: "/home/op/.state"},
			"/home/op",
			"/home/op/.state/khaos",
		},
		{"home fallback", nil, "/home/op", "/home/op/.local/state/khaos"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(
				func(k string) string { return tc.env[k] },
				tc.home,
			)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got.Root != tc.want {
				t.Fatalf("got %q, want %q", got.Root, tc.want)
			}
		})
	}
}

func TestResolveWithNothingToGoOnIsAnError(t *testing.T) {
	if _, err := Resolve(
		func(string) string { return "" },
		"",
	); !errors.Is(
		err,
		ErrUnresolvable,
	) {
		t.Fatalf("got %v; resolution must refuse rather than guess a path", err)
	}
}

func TestJournalAndLockLiveTogetherAndDiffer(t *testing.T) {
	paths := Paths{Root: "/state/khaos"}

	if filepath.Dir(paths.Journal()) != paths.Root {
		t.Fatalf("journal %q is not inside %q", paths.Journal(), paths.Root)
	}

	if filepath.Dir(paths.Lock()) != paths.Root {
		t.Fatalf("lock %q is not inside %q", paths.Lock(), paths.Root)
	}

	if paths.Journal() == paths.Lock() {
		t.Fatal("the journal and the lock resolve to the same file")
	}
}

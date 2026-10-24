// ©AngelaMos | 2026
// statedir.go

package statedir

import (
	"errors"
	"os"
	"path/filepath"
)

const (
	EnvStateDir = "KHAOS_STATE_DIR"
	EnvXDGState = "XDG_STATE_HOME"

	dirName      = "khaos"
	fallbackPath = ".local/state"

	journalName = "journal.jsonl"
	lockName    = "khaos.lock"
)

var ErrUnresolvable = errors.New(
	"no state directory could be resolved: set " + EnvStateDir + " or " + EnvXDGState,
)

type Paths struct {
	Root string
}

func Resolve(getenv func(string) string, home string) (Paths, error) {
	if dir := getenv(EnvStateDir); dir != "" {
		return Paths{Root: dir}, nil
	}

	if dir := getenv(EnvXDGState); dir != "" {
		return Paths{Root: filepath.Join(dir, dirName)}, nil
	}

	if home == "" {
		return Paths{}, ErrUnresolvable
	}

	return Paths{Root: filepath.Join(home, fallbackPath, dirName)}, nil
}

func Default() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	return Resolve(os.Getenv, home)
}

func (p Paths) Journal() string {
	return filepath.Join(p.Root, journalName)
}

func (p Paths) Runs() string {
	return filepath.Join(p.Root, "runs")
}

func (p Paths) Run(id string) string {
	return filepath.Join(p.Runs(), id)
}

// Settle guards a read-decide-append on the journal. It is separate from Lock
// because the reaper runs beside a live run and cannot take that one.
func (p Paths) Settle() string {
	return p.Journal() + ".settle"
}

func (p Paths) Lock() string {
	return filepath.Join(p.Root, lockName)
}

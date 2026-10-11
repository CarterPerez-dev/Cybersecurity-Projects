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

var ErrUnresolvable = errors.New("no state directory could be resolved: set " + EnvStateDir + " or " + EnvXDGState)

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

// Settle is the short-lived lock around a read-decide-append transition on the
// journal. It is SEPARATE from Lock, which is the instance lock a run holds for
// its whole lifetime: the reaper deliberately runs beside a live run, so it
// cannot take that one, and without a second lock the two raced over the same
// records.
func (p Paths) Settle() string {
	return p.Journal() + ".settle"
}

func (p Paths) Lock() string {
	return filepath.Join(p.Root, lockName)
}

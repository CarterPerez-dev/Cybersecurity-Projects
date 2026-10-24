// ©AngelaMos | 2026
// secretfile.go

package secretfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type Kind string

const (
	// Empty is the nastiest of the four and the only one that is not an error
	// at the syscall level: os.ReadFile returns ([]byte{}, nil), so every
	// error-handling path in the target is bypassed and the empty value flows
	// into the crypto. A guard written `if b == nil` does not catch it.
	Empty Kind = "empty"

	// Truncated is a silently WRONG key rather than a missing one.
	Truncated Kind = "truncated"

	// Missing is the one an application usually handles, because it is the one
	// that errors.
	Missing Kind = "missing"

	// Unreadable is the natural negative control for Empty: it is the only
	// shape of the four that returns an error from the read itself.
	Unreadable Kind = "unreadable"
)

const (
	// AsideSuffix keeps the original beside the secret, inside the target's own
	// mount. khaos never carries the content out: a snapshot in the journal or
	// in khaos's state directory would leave the secret on disk after the run.
	AsideSuffix = ".khaos-held"

	unreadableMode = 0o000

	// A secret is conventionally delivered read-only, and the OWNER of a 0400
	// file cannot write it either. Making it writable first means the
	// same-uid case needs no capability at all; the helper's DAC_OVERRIDE and
	// FOWNER are only for the cross-uid case, which is the usual one.
	writableMode = 0o600

	defaultTruncate = 4

	tempPrefix = ".khaos-holding-"

	describeEmpty = "truncate %s to zero bytes in place, which is the one secret fault that is not an error at the syscall level: os.ReadFile returns no error and an empty slice, so every error-handling path in the target is bypassed"

	describeTruncated = "cut %s down to a few bytes in place, which leaves a silently WRONG key rather than a missing one"

	describeMissing = "move %s aside so it is gone from the target's own filesystem"

	describeUnreadable = "make %s unreadable in place, which is the one shape of the four that errors on the read itself and is the natural negative control for the empty one"

	errUnknownKind = "%w: %q (known secret faults: %s)"
	errNoPath      = "%w: a secret fault needs the path of the file it acts on"
	errRelative    = "%w: %q is not an absolute path inside the container"
	errSelfAside   = "%w: the path khaos would keep the original at is the secret itself"
	errNoSecret    = "%s does not exist in the container, so there is no secret for khaos to break"
	errHeldExists  = "%s already exists, so khaos will not overwrite what may be another run's original"
	errNoHeld      = "%s does not exist, so khaos has nothing to restore the secret from"
)

var ErrUnknownKind = errors.New(
	"no secret fault is registered under that name",
)

var ErrBadPath = errors.New(
	"that is not a path khaos will act on",
)

// Mutation is one secret-file fault, performed INSIDE the target's own mount by
// a short-lived container. Every field is a path in the container's namespace.
type Mutation struct {
	Kind         Kind    `json:"kind"`
	Path         string  `json:"path"`
	Aside        string  `json:"aside"`
	Bytes        int     `json:"bytes,omitempty"`
	OriginalMode *uint32 `json:"original_mode,omitempty"`
	OriginalSize *int64  `json:"original_size,omitempty"`
}

func Kinds() []string {
	return []string{
		string(Empty),
		string(Missing),
		string(Truncated),
		string(Unreadable),
	}
}

// Describe names what the fault does to the file, in the operator's terms
// rather than in the syscall's.
func Describe(kind Kind, path string) string {
	switch kind {
	case Empty:
		return fmt.Sprintf(describeEmpty, path)
	case Truncated:
		return fmt.Sprintf(describeTruncated, path)
	case Missing:
		return fmt.Sprintf(describeMissing, path)
	case Unreadable:
		return fmt.Sprintf(describeUnreadable, path)
	default:
		return string(kind)
	}
}

func AsideFor(path string) string {
	return path + AsideSuffix
}

func (m Mutation) Validate() error {
	if !slices.Contains(Kinds(), string(m.Kind)) {
		return fmt.Errorf(
			errUnknownKind,
			ErrUnknownKind,
			m.Kind,
			strings.Join(Kinds(), ", "),
		)
	}

	if m.Path == "" {
		return fmt.Errorf(errNoPath, ErrBadPath)
	}

	if !filepath.IsAbs(m.Path) {
		return fmt.Errorf(errRelative, ErrBadPath, m.Path)
	}

	if m.Aside == "" || m.Aside == m.Path {
		return fmt.Errorf(errSelfAside, ErrBadPath)
	}

	if !filepath.IsAbs(m.Aside) {
		return fmt.Errorf(errRelative, ErrBadPath, m.Aside)
	}

	return nil
}

// Apply performs the fault. Everything that can be done IN PLACE is, because
// the archive API replaces the inode and a target holding an open file
// descriptor then never experiences the fault at all - measured. Only Missing
// has to move the file, which is also why it is the one khaos cannot deliver
// against a file-level bind mount.
func (m Mutation) Apply() error {
	if err := m.Validate(); err != nil {
		return err
	}

	info, err := os.Stat(m.Path)
	if err != nil {
		return fmt.Errorf(errNoSecret, m.Path)
	}

	if _, err := os.Stat(m.Aside); err == nil {
		return fmt.Errorf(errHeldExists, m.Aside)
	}

	switch m.Kind {
	case Missing:
		return os.Rename(m.Path, m.Aside)

	case Empty:
		if err := m.hold(info); err != nil {
			return err
		}

		return os.Truncate(m.Path, 0)

	case Truncated:
		if err := m.hold(info); err != nil {
			return err
		}

		return os.Truncate(m.Path, m.keep(info.Size()))

	case Unreadable:
		if err := publishCopy(m.Path, m.Aside, info.Mode()); err != nil {
			return err
		}

		return os.Chmod(m.Path, unreadableMode)

	default:
		return fmt.Errorf(
			errUnknownKind,
			ErrUnknownKind,
			m.Kind,
			strings.Join(Kinds(), ", "),
		)
	}
}

// hold copies the original aside and then makes the secret writable, in that
// order: the copy has to happen while the file can still be read.
//
// The backup is PUBLISHED atomically, so its existence means it is complete.
// Restore cannot tell a truncated backup from a genuinely short secret by
// looking at it, so the guarantee is structural rather than validated.
func (m Mutation) hold(info os.FileInfo) error {
	if err := publishCopy(m.Path, m.Aside, info.Mode()); err != nil {
		return err
	}

	return os.Chmod(m.Path, writableMode)
}

// keep is how much of the secret survives truncation: enough to be a plausible
// key and not enough to be the right one.
func (m Mutation) keep(size int64) int64 {
	want := int64(m.Bytes)
	if want <= 0 {
		want = defaultTruncate
	}

	if want >= size {
		want = size / 2
	}

	return want
}

// Restore puts the original back. It is idempotent and reports a missing
// original rather than guessing, because a secret khaos cannot restore is one
// it should never have broken.
func (m Mutation) Restore() error {
	if err := m.Validate(); err != nil {
		return err
	}

	held, err := os.Stat(m.Aside)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if m.alreadyRestored() {
			return nil
		}

		return fmt.Errorf(errNoHeld, m.Aside)
	}

	if m.Kind == Missing {
		return os.Rename(m.Aside, m.Path)
	}

	// Writable first, for the same reason Apply needed it: the mode khaos is
	// about to restore is usually one that forbids the write restoring it.
	if err := os.Chmod(m.Path, writableMode); err != nil {
		return err
	}

	if err := copyInto(m.Aside, m.Path, held.Mode()); err != nil {
		return err
	}

	if err := os.Chmod(m.Path, held.Mode().Perm()); err != nil {
		return err
	}

	return os.Remove(m.Aside)
}

func (m Mutation) alreadyRestored() bool {
	info, err := os.Stat(m.Path)
	if err != nil {
		return false
	}
	if m.OriginalSize != nil && info.Size() != *m.OriginalSize {
		return false
	}
	if m.OriginalMode != nil {
		return uint32(info.Mode().Perm()) == *m.OriginalMode
	}
	return m.Kind != Unreadable || info.Mode().Perm() != unreadableMode
}

// publishCopy writes to a temporary file in the destination's own directory,
// flushes it, and renames it into place, so a failed copy leaves NOTHING a
// later Restore could mistake for a complete original.
//
// Same directory because rename is only atomic within a filesystem, and the
// flush before it because a rename that beats the data to disk publishes a
// complete-looking backup with no bytes in it.
func publishCopy(from, to string, mode os.FileMode) error {
	//nolint:gosec // the path is the fault's subject, guarded by the nonce
	source, err := os.Open(from)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	temp, err := os.CreateTemp(filepath.Dir(to), tempPrefix)
	if err != nil {
		return err
	}

	published := false

	defer func() {
		if !published {
			_ = temp.Close()
			//nolint:gosec // os.CreateTemp's own name, in the directory
			// khaos derived from the destination; no caller supplies it
			_ = os.Remove(temp.Name())
		}
	}()

	if _, err := io.Copy(temp, source); err != nil {
		return err
	}

	if err := temp.Sync(); err != nil {
		return err
	}

	if err := temp.Chmod(mode.Perm()); err != nil {
		return err
	}

	if err := temp.Close(); err != nil {
		return err
	}

	//nolint:gosec // same: both paths are khaos's own, and the rename is what
	// makes the backup's existence mean it is complete
	if err := os.Rename(temp.Name(), to); err != nil {
		return err
	}

	published = true

	return nil
}

// copyInto overwrites the destination IN PLACE, keeping its inode. A rename
// here would swap the inode, and a target holding the file open would read
// the fault forever.
func copyInto(from, to string, mode os.FileMode) error {
	//nolint:gosec // the path is the fault's subject, guarded by the nonce
	source, err := os.Open(from)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	// Truncated rather than appended, so a restore over a longer file leaves
	// no tail of the fault behind.
	//nolint:gosec // same: this command exists to write the path it is given
	target, err := os.OpenFile(
		to,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		mode.Perm(),
	)
	if err != nil {
		return err
	}

	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		return err
	}

	return target.Close()
}

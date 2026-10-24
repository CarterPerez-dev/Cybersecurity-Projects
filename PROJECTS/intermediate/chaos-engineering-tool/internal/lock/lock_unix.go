// ©AngelaMos | 2026
// lock_unix.go

package lock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	dirMode  = 0o700
	fileMode = 0o600

	holderBufBytes = 32

	errOpen        = "open lock file: %w"
	errWrite       = "record lock holder: %w"
	errHeldBy      = "%w (pid %s). wait for it to finish, or stop it and run `khaos reclaim` to revert anything it left behind"
	errUnlockable  = "%w: %v"
	fixUnsupported = ". set KHAOS_STATE_DIR to a local filesystem that supports file locking"
)

var (
	ErrHeld       = errors.New("another khaos instance is already running")
	ErrUnlockable = errors.New(
		"khaos could not take its instance lock, so it cannot be sure another run is not already holding a fault",
	)
	unsupportedFS  = []error{unix.ENOLCK, unix.ENOSYS, unix.EOPNOTSUPP}
	ErrUnsupported = errors.New(
		"this filesystem does not support file locking" + fixUnsupported,
	)
)

type Lock struct {
	file *os.File
}

func AcquireContext(ctx context.Context, path string) (*Lock, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		held, err := Acquire(path)
		if !errors.Is(err, ErrHeld) {
			return held, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func Acquire(path string) (*Lock, error) {
	//nolint:gosec // khaos's own state dir, from statedir.Paths
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, fmt.Errorf(errOpen, err)
	}

	//nolint:gosec // khaos's own state dir, from statedir.Paths
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return nil, fmt.Errorf(errOpen, err)
	}

	if err := unix.Flock(
		fd(file),
		unix.LOCK_EX|unix.LOCK_NB,
	); err != nil {
		holder := readHolder(file)
		_ = file.Close()
		return nil, classify(err, holder)
	}

	if err := recordHolder(file); err != nil {
		_ = unix.Flock(fd(file), unix.LOCK_UN)
		_ = file.Close()
		return nil, err
	}

	return &Lock{file: file}, nil
}

func (l *Lock) Release() error {
	if err := unix.Flock(fd(l.file), unix.LOCK_UN); err != nil {
		_ = l.file.Close()
		return err
	}
	return l.file.Close()
}

// fd narrows a descriptor for the flock wrapper, which wants an int. RLIMIT_NOFILE
// bounds it far below MaxInt, so the conversion cannot overflow.
func fd(file *os.File) int {
	return int(file.Fd()) //nolint:gosec // bounded by RLIMIT_NOFILE
}

func classify(err error, holder string) error {
	if errors.Is(err, unix.EWOULDBLOCK) {
		return fmt.Errorf(errHeldBy, ErrHeld, orUnknown(holder))
	}

	for _, unsupported := range unsupportedFS {
		if errors.Is(err, unsupported) {
			return fmt.Errorf(errUnlockable, ErrUnsupported, err)
		}
	}

	return fmt.Errorf(errUnlockable, ErrUnlockable, err)
}

func recordHolder(file *os.File) error {
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf(errWrite, err)
	}

	if _, err := file.WriteAt(
		[]byte(strconv.Itoa(os.Getpid())),
		0,
	); err != nil {
		return fmt.Errorf(errWrite, err)
	}

	return file.Sync()
}

func readHolder(file *os.File) string {
	buf := make([]byte, holderBufBytes)

	n, _ := file.ReadAt(buf, 0)
	if n == 0 {
		return ""
	}

	return strings.TrimSpace(string(buf[:n]))
}

func orUnknown(holder string) string {
	if holder == "" {
		return "unknown"
	}
	return holder
}

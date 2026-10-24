// ©AngelaMos | 2026
// bundle.go

package khaos

import (
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed go.mod go.sum bundle.go cmd internal range
var rangeSource embed.FS

func RangeDirectory() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate the range cache: %w", err)
	}

	return cacheRange(filepath.Join(cache, "khaos", "range"))
}

func cacheRange(parent string) (string, error) {
	digest, err := sourceDigest(rangeSource)
	if err != nil {
		return "", fmt.Errorf("read the bundled range: %w", err)
	}
	destination := filepath.Join(parent, digest)
	if _, err := os.Lstat(destination); err == nil {
		return verifiedRange(destination, digest)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(parent, ".unpack-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := unpackRange(staging); err != nil {
		return "", fmt.Errorf("unpack the bundled range: %w", err)
	}
	if err := os.Rename(staging, destination); err != nil {
		if dir, verifyErr := verifiedRange(
			destination,
			digest,
		); verifyErr == nil {
			return dir, nil
		}
		return "", fmt.Errorf("publish the range cache: %w", err)
	}
	return verifiedRange(destination, digest)
}

func verifiedRange(directory, want string) (string, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("range cache %s is not a directory", directory)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	digest, err := sourceDigest(root.FS())
	if err != nil {
		return "", fmt.Errorf("verify the range cache %s: %w", directory, err)
	}
	if digest != want {
		return "", fmt.Errorf(
			"range cache %s was modified; move it aside and retry", directory,
		)
	}
	return filepath.Join(directory, "range"), nil
}

func sourceDigest(source fs.FS) (string, error) {
	digest := sha256.New()
	err := fs.WalkDir(source, ".", func(
		path string, entry fs.DirEntry, walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected non-regular range file: %s", path)
		}
		file, err := source.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		fmt.Fprintf(digest, "%s\x00", path)
		if _, err := io.Copy(digest, file); err != nil {
			return err
		}
		fmt.Fprint(digest, "\x00")
		return nil
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", digest.Sum(nil)), nil
}

func unpackRange(directory string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return fs.WalkDir(rangeSource, ".", func(
		path string, entry fs.DirEntry, walkErr error,
	) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		if entry.IsDir() {
			return root.Mkdir(path, 0o700)
		}
		contents, err := rangeSource.ReadFile(path)
		if err != nil {
			return err
		}
		return root.WriteFile(path, contents, 0o600)
	})
}

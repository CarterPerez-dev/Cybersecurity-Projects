// ©AngelaMos | 2026
// replay_test.go

package secretfile

import (
	"os"
	"testing"
)

func TestSecretReplayVerifiesCapturedMetadata(t *testing.T) {
	for _, name := range Kinds() {
		t.Run(name, func(t *testing.T) {
			path, aside := seeded(t)
			mode, size := uint32(secretPerm), int64(len(original))
			m := Mutation{
				Kind: Kind(name), Path: path, Aside: aside,
				OriginalMode: &mode, OriginalSize: &size,
			}
			if err := m.Restore(); err != nil {
				t.Fatalf("before application: %v", err)
			}
			if err := m.Apply(); err != nil {
				t.Fatal(err)
			}
			if err := m.Restore(); err != nil {
				t.Fatal(err)
			}
			if err := m.Restore(); err != nil {
				t.Fatalf("replay: %v", err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := m.Restore(); err == nil {
				t.Fatal(
					"mismatched original permissions accepted without a backup",
				)
			}
		})
	}
}

func TestZeroPermissionBackupAndReplayKeepOriginalMode(t *testing.T) {
	path, aside := seeded(t)
	if err := publishCopy(path, aside, 0); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(aside)
	if err != nil || info.Mode().Perm() != 0 {
		t.Fatalf("zero mode backup: %v, %v", info, err)
	}
	if err := os.Remove(aside); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	mode, size := uint32(0), int64(len(original))
	mutation := Mutation{
		Kind: Unreadable, Path: path, Aside: aside,
		OriginalMode: &mode, OriginalSize: &size,
	}
	if err := mutation.Restore(); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil || info.Mode().Perm() != 0 {
		t.Fatalf("zero mode replay: %v, %v", info, err)
	}
}

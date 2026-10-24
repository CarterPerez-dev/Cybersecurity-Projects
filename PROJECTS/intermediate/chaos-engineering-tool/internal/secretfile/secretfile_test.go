// ©AngelaMos | 2026
// secretfile_test.go

package secretfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	original   = "a-real-secret-that-is-long-enough-to-truncate"
	secretPerm = 0o400
)

func seeded(t *testing.T) (string, string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "hmac")

	if err := os.WriteFile(path, []byte(original), secretPerm); err != nil {
		t.Fatalf("seeding the secret: %v", err)
	}

	return path, AsideFor(path)
}

// TestEveryFaultIsReversible is the control for the whole tier's contract: the
// original stays beside the secret inside the target's own mount, so khaos
// needs no copy of it in a journal or in memory, and a cold-started revert can
// put it back. Every one of the four has to round-trip.
func TestEveryFaultIsReversible(t *testing.T) {
	for _, kind := range []Kind{Empty, Truncated, Missing, Unreadable} {
		t.Run(string(kind), func(t *testing.T) {
			path, aside := seeded(t)

			mutation := Mutation{Kind: kind, Path: path, Aside: aside}

			if err := mutation.Apply(); err != nil {
				t.Fatalf("apply: %v", err)
			}

			if err := mutation.Restore(); err != nil {
				t.Fatalf("restore: %v", err)
			}
			if err := mutation.Restore(); err != nil {
				t.Fatalf("replayed restore: %v", err)
			}

			restored, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading the restored secret: %v", err)
			}

			if string(restored) != original {
				t.Fatalf(
					"the restored secret is %q, want %q",
					restored,
					original,
				)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}

			if info.Mode().Perm() != secretPerm {
				t.Errorf(
					"the restored secret is mode %04o, want %04o",
					info.Mode().Perm(),
					secretPerm,
				)
			}

			if _, err := os.Stat(aside); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf(
					"khaos left %s behind, which is the original sitting beside the secret",
					aside,
				)
			}
		})
	}
}

func TestEachFaultIsTheShapeTheResearchDescribes(t *testing.T) {
	t.Run("empty reads as success with an empty slice", func(t *testing.T) {
		path, aside := seeded(t)

		if err := (Mutation{
			Kind:  Empty,
			Path:  path,
			Aside: aside,
		}).Apply(); err != nil {
			t.Fatalf("apply: %v", err)
		}

		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("an empty secret must not error: %v", err)
		}

		if len(body) != 0 {
			t.Fatalf("len = %d, want 0", len(body))
		}

		// The sharpening that matters: the slice is NOT nil, so a guard
		// written `if b == nil` does not catch an empty secret.
		if body == nil {
			t.Error(
				"os.ReadFile returned a nil slice, which would make `if b == nil` a working guard",
			)
		}
	})

	t.Run("truncated reads as success with a wrong key", func(t *testing.T) {
		path, aside := seeded(t)

		if err := (Mutation{
			Kind:  Truncated,
			Path:  path,
			Aside: aside,
			Bytes: 4,
		}).Apply(); err != nil {
			t.Fatalf("apply: %v", err)
		}

		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("a truncated secret must not error: %v", err)
		}

		if len(body) != 4 {
			t.Fatalf("len = %d, want 4", len(body))
		}

		if string(body) == original {
			t.Fatal("the secret was not truncated at all")
		}
	})

	t.Run("missing reads as ErrNotExist", func(t *testing.T) {
		path, aside := seeded(t)

		if err := (Mutation{
			Kind:  Missing,
			Path:  path,
			Aside: aside,
		}).Apply(); err != nil {
			t.Fatalf("apply: %v", err)
		}

		if _, err := os.ReadFile(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("err = %v, want fs.ErrNotExist", err)
		}
	})

	t.Run("unreadable reads as ErrPermission", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root, which ignores the mode this fault sets")
		}

		path, aside := seeded(t)

		if err := (Mutation{
			Kind:  Unreadable,
			Path:  path,
			Aside: aside,
		}).Apply(); err != nil {
			t.Fatalf("apply: %v", err)
		}

		if _, err := os.ReadFile(path); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("err = %v, want fs.ErrPermission", err)
		}
	})
}

// TestApplyRefusesToOverwriteAnOriginal is the guard that keeps a second run
// from destroying the first one's copy, which would leave a secret khaos can
// never put back.
func TestApplyRefusesToOverwriteAnOriginal(t *testing.T) {
	path, aside := seeded(t)

	mutation := Mutation{Kind: Empty, Path: path, Aside: aside}

	if err := mutation.Apply(); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	if err := mutation.Apply(); err == nil {
		t.Fatal("a second apply overwrote the original khaos was keeping")
	}

	if err := mutation.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil || string(body) != original {
		t.Fatalf("the original did not survive: %q, %v", body, err)
	}
}

func TestValidateRefusesWhatCannotBeUndone(t *testing.T) {
	cases := []struct {
		name     string
		mutation Mutation
		want     error
	}{
		{
			name:     "no kind",
			mutation: Mutation{Path: "/x", Aside: "/x.held"},
			want:     ErrUnknownKind,
		},
		{
			name:     "an invented kind",
			mutation: Mutation{Kind: "shred", Path: "/x", Aside: "/x.held"},
			want:     ErrUnknownKind,
		},
		{
			name:     "no path",
			mutation: Mutation{Kind: Empty, Aside: "/x.held"},
			want:     ErrBadPath,
		},
		{
			name:     "a relative path",
			mutation: Mutation{Kind: Empty, Path: "hmac", Aside: "/x.held"},
			want:     ErrBadPath,
		},
		{
			name:     "the original kept at the secret itself",
			mutation: Mutation{Kind: Empty, Path: "/x", Aside: "/x"},
			want:     ErrBadPath,
		},
		{
			name:     "no original at all",
			mutation: Mutation{Kind: Empty, Path: "/x"},
			want:     ErrBadPath,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.mutation.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("err = %v, want %v", err, test.want)
			}
		})
	}
}

func TestApplyRefusesASecretThatIsNotThere(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent")

	err := (Mutation{
		Kind:  Empty,
		Path:  path,
		Aside: AsideFor(path),
	}).Apply()

	if err == nil {
		t.Fatal("khaos broke a secret that did not exist")
	}
}

// TestTheEmptyKeyVerifies is the mechanism behind the whole empty-secret
// fault, and the reason it is a finding rather than an outage: crypto/hmac
// computes with a zero-length key and the result verifies.
func TestTheEmptyKeyVerifies(t *testing.T) {
	token := Token(nil, "a-nonce")

	if !Verify(token, nil) {
		t.Fatal("a token signed with the empty key does not verify against it")
	}

	if !Verify(token, []byte{}) {
		t.Fatal("nil and an empty slice are not the same key")
	}

	if Verify(token, []byte(original)) {
		t.Fatal("a token signed with the empty key verified against a real one")
	}

	if Verify(Token([]byte(original), "a-nonce"), nil) {
		t.Fatal("a token signed with a real key verified against the empty one")
	}
}

// TestEveryTokenIsDifferentAndStillVerifies is the control for the nonce: the
// catalogue census requires the negative control to vary per request, and this
// experiment requires it to stay signed with the same key. Both at once is
// what the nonce inside the signed message buys.
func TestEveryTokenIsDifferentAndStillVerifies(t *testing.T) {
	seen := map[string]bool{}

	const rounds = 8

	for i := range rounds {
		nonce := fmt.Sprintf("nonce-%d", i)
		token := Token(nil, nonce)

		seen[token] = true

		if !Verify(token, nil) {
			t.Fatalf("%q does not verify against the empty key", token)
		}

		if Verify(token, []byte(original)) {
			t.Fatalf("%q verified against a real key", token)
		}
	}

	if len(seen) != rounds {
		t.Fatalf(
			"%d calls produced %d distinct credentials",
			rounds,
			len(seen),
		)
	}
}

func TestVerifyRefusesAMalformedCredential(t *testing.T) {
	for _, token := range []string{
		"",
		"no-separator",
		Payload,
		Payload + ".nonce",
		Payload + ".nonce.not-hex",
		Payload + ".00",
		"wrong-payload.nonce.00",
		Token([]byte(original), "one") + ".extra",
	} {
		if Verify(token, []byte(original)) {
			t.Errorf("%q verified", token)
		}
	}
}

// The one outcome this package must never produce: khaos destroying the secret
// it was asked to preserve.
//
// Restore cannot tell a truncated backup from a genuinely short secret by
// looking at it, so the guarantee is structural: the backup is published
// atomically, and a failed hold leaves nothing behind to trust.
func TestAFailedHoldLeavesTheOriginalIntactAndUnrestorable(t *testing.T) {
	path, aside := seeded(t)

	// /proc/self/mem opens cleanly and fails on the first read, so the copy
	// fails with the destination already created under the old code.
	failing := Mutation{Kind: Empty, Path: "/proc/self/mem", Aside: aside}

	if err := failing.hold(modeOf(t, path)); err == nil {
		t.Fatal("copying from an unreadable source reported success")
	}

	if _, err := os.Stat(aside); err == nil {
		body, _ := os.ReadFile(aside)
		t.Fatalf(
			"a failed backup left %d bytes at the path Restore trusts as the whole original",
			len(body),
		)
	}

	// The chain that destroyed the secret: the revert that follows a failed
	// apply must refuse, not restore from whatever is lying there.
	mutation := Mutation{Kind: Empty, Path: path, Aside: aside}

	if err := mutation.Restore(); err != nil {
		t.Fatalf(
			"an untouched secret with no backup should be already-restored, got: %v",
			err,
		)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the original is unreadable after the revert: %v", err)
	}

	if string(body) != original {
		t.Fatalf(
			"khaos destroyed the secret it was preserving: now %q (%d bytes), was %q (%d bytes)",
			body,
			len(body),
			original,
			len(original),
		)
	}
}

// Publishing atomically must not leave its temporary file behind either: the
// secret's own directory is inside the target's mount, and a stray copy of a
// credential there outlives the run.
func TestAFailedHoldLeavesNoTemporaryCopyOfTheSecret(t *testing.T) {
	path, aside := seeded(t)

	failing := Mutation{Kind: Empty, Path: "/proc/self/mem", Aside: aside}
	_ = failing.hold(modeOf(t, path))

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("reading the secret's directory: %v", err)
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			t.Fatalf(
				"a failed hold left %q beside the secret, which is a stray copy of a credential",
				entry.Name(),
			)
		}
	}
}

// The backup a SUCCESSFUL hold publishes has to be byte-identical and carry the
// original's mode, or the restore puts back something the target cannot read.
func TestThePublishedBackupIsTheWholeOriginal(t *testing.T) {
	path, aside := seeded(t)

	mutation := Mutation{Kind: Empty, Path: path, Aside: aside}

	if err := mutation.hold(modeOf(t, path)); err != nil {
		t.Fatalf("hold: %v", err)
	}

	body, err := os.ReadFile(aside)
	if err != nil {
		t.Fatalf("the published backup is unreadable: %v", err)
	}

	if string(body) != original {
		t.Fatalf("the backup holds %q, want %q", body, original)
	}

	info, err := os.Stat(aside)
	if err != nil {
		t.Fatalf("stat the backup: %v", err)
	}

	if info.Mode().Perm() != secretPerm {
		t.Fatalf(
			"the backup is mode %#o, want the original's %#o",
			info.Mode().Perm(),
			secretPerm,
		)
	}
}

func modeOf(t *testing.T, path string) os.FileInfo {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	return info
}

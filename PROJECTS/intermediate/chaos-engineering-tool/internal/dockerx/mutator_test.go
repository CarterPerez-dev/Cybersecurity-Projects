// ©AngelaMos | 2026
// mutator_test.go

package dockerx

import (
	"errors"
	"strings"
	"testing"
)

func mounted() Target {
	return Target{
		Name: "shop-api",
		Mounts: []Mount{
			{
				Type:        "volume",
				Name:        "shop-secrets",
				Source:      "/var/lib/docker/volumes/shop-secrets/_data",
				Destination: "/run/secrets",
				ReadWrite:   false,
			},
			{
				Type:        "bind",
				Source:      "/srv/shop/config",
				Destination: "/etc/shop",
				ReadWrite:   true,
			},
			{
				Type:        "bind",
				Source:      "/srv/shop/token",
				Destination: "/etc/shop/token",
				ReadWrite:   true,
			},
			{
				Type:        "tmpfs",
				Destination: "/run/ephemeral",
			},
		},
	}
}

// TestMountForPicksTheDEEPESTMount is the one that decides which mount khaos
// replicates. A file inside a bind-mounted DIRECTORY that also has a
// file-level bind mount of its own has two candidates, and taking the shallower
// one would have the helper write into the directory underneath a mount the
// target is actually reading through.
func TestMountForPicksTheDeepestMount(t *testing.T) {
	cases := map[string]string{
		"/run/secrets/hmac":  "/run/secrets",
		"/etc/shop/other":    "/etc/shop",
		"/etc/shop/token":    "/etc/shop/token",
		"/etc/shop/sub/deep": "/etc/shop",
	}

	for path, want := range cases {
		mount, err := MountFor(mounted(), path)
		if err != nil {
			t.Fatalf("MountFor(%q): %v", path, err)
		}

		if mount.Destination != want {
			t.Errorf(
				"MountFor(%q) chose %q, want %q",
				path,
				mount.Destination,
				want,
			)
		}
	}
}

// TestMountForRefusesWhatCannotBeUndone is the control for the two shapes khaos
// declines rather than approximating: a path on no mount at all, which a helper
// cannot reach and a cold start could not restore, and a tmpfs, which is
// private to the container's own namespace so a helper mounting the same spec
// would write into an empty filesystem and report a fault that landed nowhere.
func TestMountForRefusesWhatCannotBeUndone(t *testing.T) {
	for _, path := range []string{
		"/etc/hostname",
		"/app/baked-in-the-image",
		"/run/ephemeral/hmac",
		"/run/ephemeral",
	} {
		if _, err := MountFor(mounted(), path); !errors.Is(
			err,
			ErrUnreachableSecret,
		) {
			t.Errorf("MountFor(%q) = %v, want ErrUnreachableSecret", path, err)
		}
	}
}

// TestFileLevelMountIsTheMountPointItself separates the one fault khaos cannot
// deliver on that shape - a mount point cannot be renamed - from the three it
// can, which write in place.
func TestFileLevelMountIsTheMountPointItself(t *testing.T) {
	file, err := MountFor(mounted(), "/etc/shop/token")
	if err != nil {
		t.Fatalf("MountFor: %v", err)
	}

	if !FileLevelMount(file, "/etc/shop/token") {
		t.Error("a file-level bind mount was not recognised as one")
	}

	dir, err := MountFor(mounted(), "/run/secrets/hmac")
	if err != nil {
		t.Fatalf("MountFor: %v", err)
	}

	if FileLevelMount(dir, "/run/secrets/hmac") {
		t.Error("a file INSIDE a mount was called the mount point")
	}
}

// TestTheHelperMountsReadWriteWhateverTheTargetDid pins the measured reason the
// helper exists at all: read-only is a property of the TARGET's mount rather
// than of the volume, and the archive API refuses a `:ro` mount outright.
func TestTheHelperMountsReadWriteWhateverTheTargetDid(t *testing.T) {
	mount, err := MountFor(mounted(), "/run/secrets/hmac")
	if err != nil {
		t.Fatalf("MountFor: %v", err)
	}

	if mount.ReadWrite {
		t.Fatal("this fixture's secret mount is supposed to be read-only")
	}

	if source := mutatorSource(mount); source != "shop-secrets" {
		t.Errorf(
			"a volume mount has to be replicated by NAME, got %q",
			source,
		)
	}

	bind, err := MountFor(mounted(), "/etc/shop/other")
	if err != nil {
		t.Fatalf("MountFor: %v", err)
	}

	if source := mutatorSource(bind); source != "/srv/shop/config" {
		t.Errorf(
			"a bind mount has to be replicated by host PATH, got %q",
			source,
		)
	}
}

// TestATmpfsFromHostConfigIsStillATmpfs is the control for a measured API
// asymmetry: a tmpfs declared the SHORT way - compose's `tmpfs:` key, or
// `--tmpfs` - lands in HostConfig and leaves `Mounts` EMPTY, while the long
// form appears in Mounts like every other mount.
//
// Measured on the range's own postgres, where `.Mounts` was `[]` and
// `.HostConfig.Tmpfs` carried the path. Before khaos read both, a secret on
// such a tmpfs was refused by the no-mount branch, which is still SAFE and
// names the wrong reason - and a refusal that explains the wrong thing sends
// the operator to fix something that is not the problem.
func TestATmpfsFromHostConfigIsStillATmpfs(t *testing.T) {
	short := Target{
		Name: "shop-api",
		Mounts: []Mount{
			{Type: tmpfsType, Destination: "/run/ephemeral", ReadWrite: true},
		},
	}

	_, err := MountFor(short, "/run/ephemeral/hmac")
	if !errors.Is(err, ErrUnreachableSecret) {
		t.Fatalf("err = %v, want ErrUnreachableSecret", err)
	}

	if !strings.Contains(err.Error(), "private to the container") {
		t.Errorf(
			"the refusal explains the wrong thing: %v",
			err,
		)
	}
}

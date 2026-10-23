// ©AngelaMos | 2026
// envfault_recovery_test.go

package inject

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const (
	fixtureImage = "alpine:3.22"
	fixtureName  = "khaos-envrevert-original"
)

// dockerOrSkip connects to the daemon, or skips: this package's other tiers
// are in-process, and the environment tier is the one that cannot be tested
// without a real container to rename.
func dockerOrSkip(t *testing.T) *dockerx.Client {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := dockerx.Open(ctx)
	if err != nil {
		t.Skipf("no docker daemon: %v", err)
	}

	return client
}

// seedOriginal creates a container that stands in for the operator's own, and
// returns its immutable id. Created through the CLI rather than through
// dockerx, because dockerx creates only from a captured spec and the point
// here is to own a container khaos did not make.
func seedOriginal(t *testing.T, name string) string {
	t.Helper()

	_ = exec.Command("docker", "rm", "-f", name).Run()

	out, err := exec.Command(
		"docker", "create", "--name", name, fixtureImage, "sleep", "300",
	).Output()
	if err != nil {
		t.Skipf("could not create the fixture container: %v", err)
	}

	id := strings.TrimSpace(string(out))

	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	return id
}

func alive(name string) bool {
	return exec.Command("docker", "inspect", name).Run() == nil
}

// THE one outcome this tier must never produce: khaos destroying the
// operator's own container.
//
// On a cold start the revert has only a NAME to find the replacement by, and
// that name is the original's. It resolves to the original in two windows:
// khaos dying after the PENDING record and before the rename, and a replay
// after a revert that already succeeded.
func TestARevertNeverRemovesTheOriginalContainer(t *testing.T) {
	client := dockerOrSkip(t)
	defer func() { _ = client.Close() }()

	for name, tc := range map[string]struct {
		// mustSucceed is the difference between the two windows. Dying
		// before the rename leaves a state the revert cannot complete, and
		// it is allowed to say so. A revert that ALREADY succeeded and lost
		// only its journal append is a different thing: replaying it has to
		// be a no-op that reports success, because an error there keeps the
		// record outstanding, makes reap retry it forever, and reports
		// rollback-failed -- exit 6, which no --fail-on may suppress.
		mustSucceed bool
	}{
		"the rename never happened": {mustSucceed: false},
		"the revert already ran":    {mustSucceed: true},
	} {
		t.Run(name, func(t *testing.T) {
			originalID := seedOriginal(t, fixtureName)

			payload, err := json.Marshal(EnvPlan{
				Kind:       EnvUnset,
				Variable:   "A_SECRET",
				Held:       fixtureName + dockerx.HeldSuffix,
				OriginalID: originalID,
			})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			ctx, cancel := context.WithTimeout(
				context.Background(),
				60*time.Second,
			)
			defer cancel()

			revertErr := (envMutator{kind: EnvUnset}).Revert(
				ctx,
				Env{Docker: client},
				journal.Record{Payload: payload},
			)

			if !alive(fixtureName) {
				t.Fatalf(
					"khaos removed the operator's own container %q (id %s): the revert resolved the replacement by name, and that name was the original's",
					fixtureName,
					dockerx.ShortID(originalID),
				)
			}

			if tc.mustSucceed && revertErr != nil {
				t.Fatalf(
					"replaying a revert that already completed returned %v; it has to be a no-op, or the record stays outstanding and the run reports an unreverted fault",
					revertErr,
				)
			}
		})
	}
}

// The NEGATIVE CONTROL: a removeReplacement that never removed anything
// would satisfy the test above, so this drives the state the fault really
// produces and requires the replacement to go and the original to come back.
func TestARevertStillRemovesAGenuineReplacement(t *testing.T) {
	client := dockerOrSkip(t)
	defer func() { _ = client.Close() }()

	held := fixtureName + dockerx.HeldSuffix

	originalID := seedOriginal(t, fixtureName)

	// The fault's own sequence: original aside, a different container on the
	// name it vacated.
	if err := exec.Command("docker", "rename", fixtureName, held).
		Run(); err != nil {
		t.Skipf("could not rename the fixture aside: %v", err)
	}

	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", held).Run() })

	replacementID := seedOriginal(t, fixtureName)

	if replacementID == originalID {
		t.Fatal("the fixture did not create a second container")
	}

	payload, err := json.Marshal(EnvPlan{
		Kind:       EnvUnset,
		Variable:   "A_SECRET",
		Held:       held,
		OriginalID: originalID,
		// ReplacedID deliberately empty: the cold-start shape, which is the
		// dangerous path.
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := (envMutator{kind: EnvUnset}).Revert(
		ctx,
		Env{Docker: client},
		journal.Record{Payload: payload},
	); err != nil {
		t.Fatalf("revert: %v", err)
	}

	if alive(replacementID) {
		t.Errorf(
			"the replacement %s survived the revert, so the guard is refusing to remove anything at all",
			dockerx.ShortID(replacementID),
		)
	}

	id, err := client.Identify(ctx, fixtureName)
	if err != nil {
		t.Fatalf("the original was not restored under its own name: %v", err)
	}

	if id != originalID {
		t.Errorf(
			"%q is %s, want the original %s",
			fixtureName,
			dockerx.ShortID(id),
			dockerx.ShortID(originalID),
		)
	}
}

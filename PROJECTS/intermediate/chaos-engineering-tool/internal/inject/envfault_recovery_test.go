// ©AngelaMos | 2026
// envfault_recovery_test.go

package inject

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const (
	fixtureImage = "alpine:3.22"
)

// dockerOrSkip connects to the daemon, or skips: this package's other tiers
// are in-process, and the environment tier is the one that cannot be tested
// without a real container to rename.
func dockerOrSkip(t *testing.T) *dockerx.Client {
	t.Helper()
	if os.Getenv("KHAOS_DOCKER_TESTS") != "1" {
		t.Skip("set KHAOS_DOCKER_TESTS=1 to run Docker integration tests")
	}

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
func seedOriginal(t *testing.T, name string, labels ...string) string {
	t.Helper()

	args := []string{"create", "--name", name}
	for _, label := range labels {
		args = append(args, "--label", label)
	}
	args = append(args, fixtureImage, "sleep", "300")
	out, err := exec.Command("docker", args...).Output()
	if err != nil {
		t.Fatalf("could not create the fixture container: %v", err)
	}

	id := strings.TrimSpace(string(out))

	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })

	return id
}

func TestRecoveryRefusesAnUnownedContainerReusingTheOriginalName(t *testing.T) {
	client := dockerOrSkip(t)
	defer client.Close()
	name := "khaos-env-unowned-" + strings.ToLower(journal.NewID())
	id := seedOriginal(t, name)
	held := dockerx.HeldName(name)
	if err := exec.Command("docker", "rename", id, held).Run(); err != nil {
		t.Fatal(err)
	}
	unrelated := seedOriginal(t, name)
	payload, err := journal.EncodePayload(EnvPlan{
		Kind: EnvUnset, Variable: "SECRET", Held: held, OriginalID: id,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = (envMutator{kind: EnvUnset}).Revert(
		ctx, Env{Docker: client}, journal.Record{Payload: payload},
	)
	if err == nil || !alive(unrelated) || !alive(id) {
		t.Fatalf(
			"unowned container recovery: error=%v original=%v unrelated=%v",
			err, alive(id), alive(unrelated),
		)
	}
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
			fixtureName := "khaos-envrevert-" + strings.ToLower(journal.NewID())
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

	fixtureName := "khaos-envrevert-" + strings.ToLower(journal.NewID())
	held := fixtureName + dockerx.HeldSuffix

	originalID := seedOriginal(t, fixtureName)

	// The fault's own sequence: original aside, a different container on the
	// name it vacated.
	if err := exec.Command("docker", "rename", fixtureName, held).
		Run(); err != nil {
		t.Skipf("could not rename the fixture aside: %v", err)
	}

	owner := journal.NewID()
	replacementID := seedOriginal(t, fixtureName, ReplacementLabel+"="+owner)

	if replacementID == originalID {
		t.Fatal("the fixture did not create a second container")
	}

	payload, err := json.Marshal(EnvPlan{
		Kind:       EnvUnset,
		Variable:   "A_SECRET",
		Held:       held,
		OriginalID: originalID,
		Owner:      owner,
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

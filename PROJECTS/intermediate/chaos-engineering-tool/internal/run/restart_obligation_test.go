// ©AngelaMos | 2026
// restart_obligation_test.go

package run

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/journal"
)

const restartImage = "alpine:3.22"

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

	t.Cleanup(func() { _ = client.Close() })

	return client
}

// A stop whose start cannot follow leaves the operator's target DOWN, and
// nothing records that it owes a restart: Restart journalled nothing at all,
// on the reasoning that a stop followed by a start leaves the container where
// it was -- which holds only when both halves complete.
//
// The start is made to fail for real rather than simulated: the container
// publishes a host port, the test holds that port, and the daemon refuses to
// allocate it. Stop on an already-stopped container succeeds, so the window
// is exact.
func TestAStopWhoseStartFailsLeavesARestartObligation(t *testing.T) {
	client := dockerOrSkip(t)

	port := freeHighPort(t)
	name := fmt.Sprintf("khaos-restart-obligation-%d", port)

	id := seedPublished(t, name, port)

	// Stop it, then take the port so the daemon cannot give it back.
	if err := exec.Command("docker", "stop", name).Run(); err != nil {
		t.Skipf("could not stop the fixture: %v", err)
	}

	blocker, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skipf("could not hold the port: %v", err)
	}
	defer func() { _ = blocker.Close() }()

	log := tempJournal(t)
	session := newSessionWith(
		inject.Env{Docker: client},
		log,
		time.Hour,
		inject.Lookup,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	target := dockerx.Target{ID: id, Name: name}

	if err := session.Restart(ctx, target); err == nil {
		t.Fatal(
			"the start succeeded while its port was held; the fixture did not reproduce the window",
		)
	}

	if running(name) {
		t.Fatal("the fixture is running, so the start did not actually fail")
	}

	outstanding, err := journal.Outstanding(log.Path())
	if err != nil {
		t.Fatalf("outstanding: %v", err)
	}

	if len(outstanding) == 0 {
		t.Fatal(
			"khaos stopped the operator's target, failed to start it again, and recorded no obligation to bring it back: a cold-started reclaim has nothing to act on",
		)
	}
}

// The control: a Restart that completes leaves NOTHING outstanding, or the
// obligation above would simply be a fault khaos never clears.
func TestACompletedRestartLeavesNoObligation(t *testing.T) {
	client := dockerOrSkip(t)

	port := freeHighPort(t)
	name := fmt.Sprintf("khaos-restart-clean-%d", port)

	id := seedPublished(t, name, port)

	log := tempJournal(t)
	session := newSessionWith(
		inject.Env{Docker: client},
		log,
		time.Hour,
		inject.Lookup,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := session.Restart(
		ctx,
		dockerx.Target{ID: id, Name: name},
	); err != nil {
		t.Fatalf("restart: %v", err)
	}

	if !running(name) {
		t.Fatal("the target did not come back up")
	}

	outstanding, err := journal.Outstanding(log.Path())
	if err != nil {
		t.Fatalf("outstanding: %v", err)
	}

	if len(outstanding) != 0 {
		t.Fatalf(
			"a completed restart left %d obligation(s) outstanding, which a reaper would act on forever",
			len(outstanding),
		)
	}
}

func freeHighPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no free port: %v", err)
	}
	defer func() { _ = listener.Close() }()

	return listener.Addr().(*net.TCPAddr).Port
}

func seedPublished(t *testing.T, name string, port int) string {
	t.Helper()

	out, err := exec.Command(
		"docker", "run", "-d", "--name", name,
		"-p", fmt.Sprintf("127.0.0.1:%d:7", port),
		restartImage, "sleep", "600",
	).Output()
	if err != nil {
		t.Fatalf("could not create the fixture: %v", err)
	}

	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	return id
}

func running(name string) bool {
	out, err := exec.Command(
		"docker", "inspect", "-f", "{{.State.Running}}", name,
	).Output()

	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// The obligation is only worth journalling if recovery acts on it: a cold
// reclaim has to put back a target khaos took down and never brought up.
//
// Modelled the way it actually happens -- khaos cancelled or killed partway
// through the restart of a RUNNING target. The fixture ignores SIGTERM, so
// the stop takes its full timeout and the cancellation lands inside it.
func TestAReclaimRestoresATargetLeftDownByAFailedRestart(t *testing.T) {
	client := dockerOrSkip(t)

	port := freeHighPort(t)
	name := fmt.Sprintf("khaos-restart-reclaim-%d", port)

	id := seedPublished(t, name, port)

	if !running(name) {
		t.Skip("the fixture is not running")
	}

	log := tempJournal(t)
	env := inject.Env{Docker: client}
	session := newSessionWith(env, log, time.Hour, inject.Lookup)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- session.Restart(ctx, dockerx.Target{ID: id, Name: name})
	}()

	// Well inside the stop's own timeout.
	time.Sleep(1500 * time.Millisecond)
	cancel()

	if err := <-done; err == nil {
		t.Skip("the restart completed before the cancellation landed")
	}

	// The daemon finishes the stop it was asked for, so the target is down
	// with khaos no longer able to bring it back.
	deadline := time.Now().Add(30 * time.Second)
	for running(name) && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}

	if running(name) {
		t.Skip("the target never went down, so there is no obligation to test")
	}

	sweep := reclaimWith(
		context.Background(),
		env,
		log,
		time.Now().UTC().Add(2*time.Hour),
		true,
		inject.Lookup,
	)

	if sweep.Failed() {
		t.Fatalf("the reclaim reported failures: %+v", sweep.Results)
	}

	if len(sweep.Results) == 0 {
		t.Fatal("the reclaim found nothing to act on")
	}

	if !running(name) {
		t.Fatal(
			"a reclaim ran over the restart obligation and the operator's target is still down",
		)
	}
}

// The obligation has to be DURABLE before the stop begins, not written once
// the outcome is known: khaos killed outright partway through leaves only
// what the journal already holds, and a stop with nothing recorded is a
// target down with no record that it owes a start.
func TestTheRestartObligationIsDurableBeforeTheStop(t *testing.T) {
	client := dockerOrSkip(t)

	port := freeHighPort(t)
	name := fmt.Sprintf("khaos-restart-durable-%d", port)

	id := seedPublished(t, name, port)

	log := tempJournal(t)
	session := newSessionWith(
		inject.Env{Docker: client},
		log,
		time.Hour,
		inject.Lookup,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- session.Restart(ctx, dockerx.Target{ID: id, Name: name})
	}()

	// The fixture ignores SIGTERM, so the stop is still running here.
	time.Sleep(1500 * time.Millisecond)

	outstanding, err := journal.Outstanding(log.Path())
	if err != nil {
		t.Fatalf("outstanding: %v", err)
	}

	if len(outstanding) == 0 {
		t.Error(
			"the stop is in flight and the journal holds no obligation; a khaos killed right now leaves the target down with nothing to recover from",
		)
	}

	if err := <-done; err != nil {
		t.Fatalf("restart: %v", err)
	}
}

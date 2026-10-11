// ©AngelaMos | 2026
// reclaim_test.go

package run

import (
	"errors"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/journal"
)

// A fault on another daemon is left alone AND left outstanding.
//
// Without this, reclaiming against a second daemon found no such container,
// read that as "the target is gone so the fault went with it", and wrote
// REVERTED. The container on the first daemon stayed paused, and no later sweep
// would ever look at it again because the journal said it was settled — an
// irreversible loss of the only record that the fault exists.
func TestASweepWillNotSettleAFaultFromAnotherDaemon(t *testing.T) {
	cases := []struct {
		name     string
		recorded string
		here     string
		refuse   bool
	}{
		{"same daemon", "daemon-a", "daemon-a", false},
		{"a different daemon", "daemon-a", "daemon-b", true},
		{"the record predates the field", "", "daemon-b", false},
		{"the daemon would not identify itself", "daemon-a", "", false},
		{"neither is known", "", "", false},
	}

	refusals := 0

	for _, each := range cases {
		t.Run(each.name, func(t *testing.T) {
			err := daemonMismatch(
				journal.Record{Daemon: each.recorded, TargetID: "abc"},
				each.here,
			)

			if (err != nil) != each.refuse {
				t.Fatalf("recorded=%q here=%q refused=%v, want %v (%v)",
					each.recorded, each.here, err != nil, each.refuse, err)
			}

			if !each.refuse {
				return
			}

			refusals++

			if !errors.Is(err, ErrOtherDaemon) {
				t.Fatalf("the refusal is not ErrOtherDaemon: %v", err)
			}

			// It has to name BOTH daemons, or the operator cannot tell where to
			// go and reclaim.
			for _, want := range []string{each.recorded, each.here} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not name %q: %v", want, err)
				}
			}
		})
	}

	// The ambiguous cases deliberately do NOT refuse, so without this the whole
	// table could pass with a function that never refuses anything.
	if refusals == 0 {
		t.Fatal(
			"no case refused, so this table cannot detect a check that always allows",
		)
	}
}

// ©AngelaMos | 2026
// reap_status_test.go

package cli

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/run"
)

func TestReaperExitRetainsSkippedFailuresUntilActuallySettled(t *testing.T) {
	log, err := journal.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	now := time.Now().UTC()
	record := journal.Record{
		MutationID: "failed", Phase: journal.PhaseRenewed,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := log.Append(record); err != nil {
		t.Fatal(err)
	}
	failed := map[string]bool{record.MutationID: true}
	err = reapExit(log.Path(), failed, now)
	if !errors.Is(err, run.ErrRevertFailed) {
		t.Fatalf("renewed unresolved failure disappeared: %v", err)
	}
	if err := reapExit(log.Path(), nil, now); err != nil {
		t.Fatalf("unexpired active obligation affected exit: %v", err)
	}
	err = reapExit(log.Path(), nil, now.Add(2*time.Hour))
	if !errors.Is(err, run.ErrRevertFailed) {
		t.Fatalf("expired skipped obligation disappeared: %v", err)
	}
	record.Phase = journal.PhaseReverted
	if err := log.Append(record); err != nil {
		t.Fatal(err)
	}
	if err := reapExit(log.Path(), failed, now); err != nil {
		t.Fatalf("settled failure still affected exit: %v", err)
	}
}

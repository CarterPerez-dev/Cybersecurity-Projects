// ©AngelaMos | 2026
// reconciliation_test.go

package workspace

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/run"
)

func TestMutationsRefuseOutstandingRecoveryAndDamagedReplay(t *testing.T) {
	log, err := journal.Open(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	work := &Workspace{Journal: log}
	if err := work.RequireClean(); err != nil {
		t.Fatalf("clean workspace refused: %v", err)
	}
	work.Reconciled.Damage = errors.New("damaged journal tail")
	if err := work.RequireClean(); !errors.Is(err, run.ErrRevertFailed) {
		t.Fatalf("damaged reconciliation accepted: %v", err)
	}
	work.Reconciled = run.Sweep{}
	record := journal.Record{
		MutationID: journal.NewID(), Kind: "fake", Phase: journal.PhasePending,
	}
	if err := log.Append(record); err != nil {
		t.Fatal(err)
	}
	if err := work.RequireClean(); !errors.Is(err, run.ErrRevertFailed) {
		t.Fatalf("outstanding mutation accepted: %v", err)
	}
	record.Phase = journal.PhaseReverted
	if err := log.Append(record); err != nil {
		t.Fatal(err)
	}
	if err := work.RequireClean(); err != nil {
		t.Fatalf("reconciled workspace refused: %v", err)
	}
}

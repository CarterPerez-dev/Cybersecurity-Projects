// ©AngelaMos | 2026
// compaction_test.go

package journal

import (
	"path/filepath"
	"testing"
)

func TestCompactionPreservesOpenWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	writer, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	record := Record{MutationID: "active", Phase: PhaseApplied}
	if err := writer.Append(record); err != nil {
		t.Fatal(err)
	}
	if err := Compact(path); err != nil {
		t.Fatal(err)
	}
	record.Phase = PhaseReverted
	if err := writer.Append(record); err != nil {
		t.Fatal(err)
	}
	live, err := Outstanding(path)
	if err != nil || len(live) != 0 {
		t.Fatalf("reversion was lost after compaction: %v, %v", live, err)
	}
}

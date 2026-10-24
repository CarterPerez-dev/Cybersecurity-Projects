// ©AngelaMos | 2026
// journal_test.go

package journal

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	testFile    = "journal.jsonl"
	wantDirMode = fs.FileMode(0o700)
)

func tempJournal(t *testing.T) *Journal {
	t.Helper()

	j, err := Open(filepath.Join(t.TempDir(), "nested", testFile))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })

	return j
}

func record(id string, phase Phase) Record {
	return Record{
		MutationID: id,
		RunID:      "run-1",
		LeaseID:    "lease-1",
		Kind:       "container-pause",
		TargetID:   "abc123",
		TargetName: "shop-api-1",
		Phase:      phase,
	}
}

type payload struct {
	Networks []string `json:"networks"`
}

func TestAppendAndReplayRoundTrip(t *testing.T) {
	j := tempJournal(t)

	raw, err := EncodePayload(
		payload{Networks: []string{"shop_default", "shop_edge"}},
	)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	want := record("m1", PhaseApplied)
	want.Payload = raw
	want.ExpiresAt = time.Now().UTC().Add(time.Minute).Truncate(time.Second)

	if err := j.Append(want); err != nil {
		t.Fatalf("append: %v", err)
	}

	got, err := Replay(j.Path())
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("replayed %d records, want 1", len(got))
	}

	var decoded payload
	if err := got[0].DecodePayload(&decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	if len(decoded.Networks) != 2 || decoded.Networks[0] != "shop_default" {
		t.Fatalf("payload did not survive the round trip: %+v", decoded)
	}

	if got[0].At.IsZero() {
		t.Fatal("append did not stamp a time")
	}
}

func TestDecodingAnAbsentPayloadIsNamed(t *testing.T) {
	if err := record(
		"m1",
		PhaseApplied,
	).DecodePayload(&payload{}); !errors.Is(
		err,
		ErrNoPayload,
	) {
		t.Fatalf(
			"got %v, want ErrNoPayload so a revert can tell empty from corrupt",
			err,
		)
	}
}

func TestOutstandingCollapsesToTheLatestPhaseAndKeepsOrder(t *testing.T) {
	j := tempJournal(t)

	for _, r := range []Record{
		record("m1", PhasePending),
		record("m1", PhaseApplied),
		record("m2", PhasePending),
		record("m2", PhaseApplied),
		record("m2", PhaseReverted),
		record("m3", PhasePending),
	} {
		if err := j.Append(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	out, err := Outstanding(j.Path())
	if err != nil {
		t.Fatalf("outstanding: %v", err)
	}

	if len(out) != 2 {
		t.Fatalf(
			"got %d outstanding, want 2 (m1 applied, m3 pending)",
			len(out),
		)
	}

	if out[0].MutationID != "m1" || out[1].MutationID != "m3" {
		t.Fatalf(
			"outstanding came back as %s,%s; first-seen order must hold because "+
				"reclaim reverts in reverse to undo most-recent-first",
			out[0].MutationID,
			out[1].MutationID,
		)
	}
}

func TestOutstandingKeepsTheLatestPayload(t *testing.T) {
	j := tempJournal(t)

	raw, err := EncodePayload(payload{Networks: []string{"shop_default"}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	pending := record("m1", PhasePending)
	applied := record("m1", PhaseApplied)
	applied.Payload = raw

	for _, r := range []Record{pending, applied} {
		if err := j.Append(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	out, err := Outstanding(j.Path())
	if err != nil {
		t.Fatalf("outstanding: %v", err)
	}

	var decoded payload
	if err := out[0].DecodePayload(&decoded); err != nil {
		t.Fatalf(
			"the collapse dropped the payload, so a revert would silently do nothing: %v",
			err,
		)
	}

	if len(decoded.Networks) != 1 {
		t.Fatalf("payload came back as %+v", decoded)
	}
}

func TestPendingAndFailedAreBothOutstanding(t *testing.T) {
	if !record("m1", PhasePending).Outstanding() {
		t.Fatal(
			"a mutation journaled before it was applied must still be reclaimed, " +
				"because khaos may have died between the write and the apply",
		)
	}

	if !record("m1", PhaseFailed).Outstanding() {
		t.Fatal(
			"a mutation whose apply failed may have partially landed and must stay reclaimable",
		)
	}

	if record("m1", PhaseReverted).Outstanding() {
		t.Fatal("a reverted mutation must not be reclaimed again")
	}
}

func TestARecordWithNoLeaseIsTreatedAsExpired(t *testing.T) {
	r := record("m1", PhaseApplied)

	if !r.Expired(time.Now().UTC()) {
		t.Fatal(
			"a record carrying no lease was treated as immortal; every injected fault " +
				"must carry a lease, so a record without one is malformed and must fail safe",
		)
	}

	r.ExpiresAt = time.Now().UTC().Add(time.Hour)
	if r.Expired(time.Now().UTC()) {
		t.Fatal("a live lease was reported expired")
	}
}

func TestReplayOfAMissingJournalIsEmptyNotAnError(t *testing.T) {
	got, err := Replay(filepath.Join(t.TempDir(), "absent.jsonl"))
	if err != nil {
		t.Fatalf("replay of a missing journal errored: %v", err)
	}
	if got != nil {
		t.Fatalf("got %d records from a missing journal", len(got))
	}
}

func TestADamagedLineIsQuarantinedNotFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), testFile)

	body := "{\"mutation_id\":\"m1\",\"phase\":\"applied\"}\n" +
		"{\"mutation_id\":\"m2\",\"phase\":\"appl\n" +
		"{\"mutation_id\":\"m3\",\"phase\":\"pending\"}\n"

	if err := os.WriteFile(path, []byte(body), fileMode); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, err := Outstanding(path)

	if !errors.Is(err, ErrDamaged) {
		t.Fatalf(
			"got %v; a damaged line must be reported, or khaos silently claims completeness",
			err,
		)
	}

	if len(out) != 2 {
		t.Fatalf(
			"got %d outstanding records; the readable records must still be acted on, "+
				"or one bad line strands every fault on the machine forever",
			len(out),
		)
	}
}

func TestCompactKeepsOnlyOutstandingRecords(t *testing.T) {
	j := tempJournal(t)

	for _, r := range []Record{
		record("m1", PhasePending),
		record("m1", PhaseApplied),
		record("m1", PhaseReverted),
		record("m2", PhasePending),
		record("m2", PhaseApplied),
	} {
		if err := j.Append(r); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	before, err := os.Stat(j.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := Compact(j.Path()); err != nil {
		t.Fatalf("compact: %v", err)
	}

	after, err := os.Stat(j.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if after.Size() >= before.Size() {
		t.Fatalf(
			"compaction grew the journal from %d to %d bytes",
			before.Size(),
			after.Size(),
		)
	}

	out, err := Outstanding(j.Path())
	if err != nil {
		t.Fatalf("outstanding: %v", err)
	}

	if len(out) != 1 || out[0].MutationID != "m2" {
		t.Fatalf("compaction changed what is outstanding: %+v", out)
	}
}

func TestTheJournalIsNotWorldReadable(t *testing.T) {
	j := tempJournal(t)

	if err := j.Append(record("m1", PhaseApplied)); err != nil {
		t.Fatalf("append: %v", err)
	}

	info, err := os.Stat(j.Path())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if info.Mode().Perm() != fileMode {
		t.Fatalf(
			"journal mode is %v, want %v; it records container names and network topology",
			info.Mode().Perm(),
			fs.FileMode(fileMode),
		)
	}

	dir, err := os.Stat(filepath.Dir(j.Path()))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}

	if dir.Mode().Perm() != wantDirMode {
		t.Fatalf(
			"state directory mode is %v, want %v",
			dir.Mode().Perm(),
			wantDirMode,
		)
	}
}

func TestAppendSurfacesAWriteFailure(t *testing.T) {
	j := tempJournal(t)

	if err := j.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if err := j.Append(record("m1", PhaseApplied)); err == nil {
		t.Fatal(
			"append on a closed journal reported success, so a durability failure " +
				"would be swallowed while the fault stays applied",
		)
	}
}

func TestIDsAreDistinct(t *testing.T) {
	seen := make(map[string]bool, 128)

	for range 128 {
		id := NewID()
		if seen[id] {
			t.Fatalf(
				"duplicate id %q; two mutations would collapse into one journal entry",
				id,
			)
		}
		seen[id] = true
	}
}

// A completed reversion is terminal against a RENEWAL and re-openable by an
// APPLICATION, and the journal has to tell those apart: a stale renewal must
// not resurrect a fault the reaper undid, while an Apply that completed after
// the reaper reverted it leaves a LIVE fault that has to stay recoverable.
func TestAReversionIsTerminalForARenewalAndNotForAnApplication(t *testing.T) {
	for name, tc := range map[string]struct {
		last Phase
		want int
	}{
		"a stale renewal landing after the reversion": {
			last: PhaseRenewed,
			want: 0,
		},
		"an apply that completed after the reversion": {
			last: PhaseApplied,
			want: 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.ndjson")

			log, err := Open(path)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer func() { _ = log.Close() }()

			const id = "mutation-1"

			for _, phase := range []Phase{
				PhasePending,
				PhaseApplied,
				// The reaper wins the race and reverts.
				PhaseReverted,
				tc.last,
			} {
				if err := log.Append(Record{
					MutationID: id,
					Kind:       "container-pause",
					TargetID:   "abc",
					Phase:      phase,
				}); err != nil {
					t.Fatalf("append: %v", err)
				}
			}

			outstanding, err := Outstanding(path)
			if err != nil {
				t.Fatalf("outstanding: %v", err)
			}

			if len(outstanding) != tc.want {
				t.Fatalf(
					"%d outstanding, want %d: a %s record following a reversion",
					len(outstanding),
					tc.want,
					tc.last,
				)
			}
		})
	}
}

// And the control: a mutation that was never reverted is still outstanding, or
// the rule above would simply have hidden every fault.
func TestAnAppliedMutationIsStillOutstanding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.ndjson")

	log, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = log.Close() }()

	for _, record := range []Record{
		{MutationID: "m", Kind: "container-pause", TargetID: "abc", Phase: PhasePending},
		{MutationID: "m", Kind: "container-pause", TargetID: "abc", Phase: PhaseApplied},
	} {
		if err := log.Append(record); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	outstanding, err := Outstanding(path)
	if err != nil {
		t.Fatalf("outstanding: %v", err)
	}

	if len(outstanding) != 1 {
		t.Fatalf("an applied mutation is not outstanding: %+v", outstanding)
	}
}

// ©AngelaMos | 2026
// record_test.go

package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

func outcome(
	at time.Time,
	credential probe.Credential,
	disposition probe.Disposition,
) probe.Outcome {
	return probe.Outcome{
		At:          at,
		Credential:  credential,
		Disposition: disposition,
		LatencyMS:   7,
	}
}

// finished is a run with every window populated, so a test that drops a
// window or a stream fails instead of quietly measuring a smaller shape.
func finished() experiment.Result {
	base := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

	window := func(offset time.Duration, invalid probe.Disposition) probe.Window {
		out := probe.Window{}

		for i := range 3 {
			at := base.Add(offset + time.Duration(i)*time.Second)
			out.Record(outcome(at, probe.Valid, probe.Accepted))
			out.Record(outcome(at, probe.Invalid, invalid))
		}

		return out
	}

	return experiment.Result{
		Experiment: "control.policy_store_down",
		Family:     "control",
		RunID:      "01KRUN0000000000000000000",
		Hypothesis: "a hypothesis sentence",
		Fault: experiment.Fault{
			Kind:   "proxy-reset",
			Target: "khaos-range-gateway-control",
		},
		StartedAt: base,
		Duration:  30 * time.Second,
		Observation: experiment.Observation{
			Baseline: window(0, probe.Rejected),
			Fault:    window(10*time.Second, probe.Accepted),

			// Shift is the authorization tier's second fault window and
			// Resumed is what the idleness discriminator reads. A fixture
			// missing either lets a serializer drop it unnoticed.
			Shift:          window(15*time.Second, probe.Accepted),
			Shifted:        true,
			Resumed:        window(18*time.Second, probe.Rejected),
			Recovery:       window(20*time.Second, probe.Rejected),
			FaultConfirmed: true,
			ConfirmMethod:  "a measured observable",
			FaultFor:       20 * time.Second,
		},
		Verdict: experiment.Verdict{
			Epistemic:  experiment.Deviated,
			Direction:  experiment.Permitted,
			Recovery:   experiment.Recovered,
			Conclusive: true,
			Defect:     true,
			Reasons:    []string{"a reason"},
		},
	}
}

func definition(t *testing.T) experiment.Definition {
	t.Helper()

	found, err := experiment.Lookup("control.policy_store_down")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	return found
}

// The record has to carry what the terminal shows. These are the fields a
// reader cannot reconstruct from anything else, and a record missing one is
// a record that cannot answer why khaos said what it said.
func TestTheRecordCarriesWhatTheVerdictRestsOn(t *testing.T) {
	rec := Of("1.2.3", finished(), definition(t), 2, "defect")

	for name, got := range map[string]any{
		"schema version":  rec.Schema,
		"khaos version":   rec.Khaos,
		"run id":          rec.RunID,
		"started at":      rec.Started,
		"ended at":        rec.Ended,
		"experiment name": rec.Experiment.Name,
		"family":          rec.Experiment.Family,
		"hypothesis":      rec.Experiment.Hypothesis,
		"fault kind":      rec.Fault.Kind,
		"fault target":    rec.Fault.Target,
		"confirm method":  rec.Fault.Method,
		"epistemic":       rec.Verdict.Epistemic,
		"direction":       rec.Verdict.Direction,
		"recovery":        rec.Verdict.Recovery,
		"exit code":       rec.Exit.Code,
		"exit outcome":    rec.Exit.Outcome,
	} {
		switch value := got.(type) {
		case string:
			if value == "" {
				t.Errorf("the record carries no %s", name)
			}
		case int:
			if value == 0 && name != "exit code" {
				t.Errorf("the record carries no %s", name)
			}
		}
	}

	if !rec.Fault.Confirmed {
		t.Error("the record does not say the fault was confirmed")
	}

	if !rec.Verdict.Defect {
		t.Error("the record does not carry the defect flag")
	}

	// The DECLARED defects, because the same direction is a finding for one
	// control and correct for another: a reader with the direction alone
	// cannot tell which they are looking at.
	if len(rec.Experiment.Defects) == 0 {
		t.Error(
			"the record does not say which directions this experiment calls a defect",
		)
	}

	if rec.Experiment.Rationale == "" {
		t.Error("the record does not carry the polarity's rationale")
	}
}

// A window khaos never reached is ABSENT, not zero. "khaos did not get here"
// and "khaos measured nothing here" are different facts and a reader cannot
// tell them apart from a zero.
func TestAnUnmeasuredWindowIsAbsentRatherThanZero(t *testing.T) {
	result := finished()
	result.Observation.Recovery = probe.Window{}

	rec := Of("1.2.3", result, definition(t), 2, "defect")

	if _, present := rec.Windows["recovery"]; present {
		t.Fatal("a window that was never measured is recorded as zero")
	}

	for _, name := range []string{"baseline", "fault"} {
		if _, present := rec.Windows[name]; !present {
			t.Fatalf("the %s window is missing from the record", name)
		}
	}

	// And a stream nothing drove is absent for the same reason.
	if _, present := rec.Windows["baseline"].Streams["forged"]; present {
		t.Fatal("a stream that never fired is recorded as zero")
	}
}

func TestTheWindowAggregatesMatchTheObservations(t *testing.T) {
	rec := Of("1.2.3", finished(), definition(t), 2, "defect")

	fault := rec.Windows["fault"]

	if fault.Paired != 3 {
		t.Errorf("fault paired = %d, want 3", fault.Paired)
	}

	// Six requests over two streams, which is the number the probe footprint
	// is read from and the number a reader checks the verdict against.
	if fault.Requests != 6 {
		t.Errorf("fault requests = %d, want 6", fault.Requests)
	}

	invalid := fault.Streams["invalid"]
	if invalid.Distribution["accepted"] != 3 {
		t.Errorf(
			"the fault window's invalid stream shows %v, want 3 accepted",
			invalid.Distribution,
		)
	}

	baseline := rec.Windows["baseline"].Streams["invalid"]
	if baseline.Distribution["rejected"] != 3 {
		t.Errorf(
			"the baseline's invalid stream shows %v, want 3 rejected",
			baseline.Distribution,
		)
	}
}

// Every observation reaches the events file. A record that summarises 800
// observations and ships 600 of them is unauditable in the way that matters:
// the missing ones are invisible.
func TestEveryObservationReachesTheEventsFile(t *testing.T) {
	result := finished()
	events := EventsOf(result.Observation)

	// Requests, not Len: Len is Paired, and one paired sample is at least
	// two requests. Counting pairs here would have asserted half the
	// observations reached the file and called that complete.
	//
	// Summed over Phases rather than a list written here, so a new phase
	// cannot go uncounted.
	want := 0
	for _, phase := range Phases(result.Observation) {
		want += phase.Window.Requests()
	}

	if len(events) != want {
		t.Fatalf("wrote %d events for %d observations", len(events), want)
	}

	windows := map[string]int{}
	for _, event := range events {
		windows[event.Window]++

		if event.At == "" || event.Stream == "" || event.Disposition == "" {
			t.Fatalf("an event is missing a field: %+v", event)
		}
	}

	for _, name := range []string{"baseline", "fault", "recovery"} {
		if windows[name] == 0 {
			t.Errorf("no events carry the window %q", name)
		}
	}
}

// Within a window the streams are recorded one after another, so a naive
// concatenation reads as four separate runs rather than one interleaved one.
func TestEventsWithinAWindowAreTimeOrdered(t *testing.T) {
	events := EventsOf(finished().Observation)

	for i := 1; i < len(events); i++ {
		if events[i-1].Window != events[i].Window {
			continue
		}

		if events[i-1].At > events[i].At {
			t.Fatalf(
				"events in the %s window are out of order: %s then %s",
				events[i].Window,
				events[i-1].At,
				events[i].At,
			)
		}
	}
}

// The hash is what stops a record being silently separated from its data, so
// it has to be the hash of the bytes that actually landed.
func TestTheRecordHashesTheEventsItActuallyWrote(t *testing.T) {
	dir := t.TempDir()
	result := finished()

	written, err := Write(
		dir,
		Of("1.2.3", result, definition(t), 2, "defect"),
		EventsOf(result.Observation),
	)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	if written.Events == nil {
		t.Fatal("the record carries no events reference")
	}

	body, err := os.ReadFile(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatalf("read the events file: %v", err)
	}

	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != written.Events.SHA256 {
		t.Fatalf(
			"the record claims sha256 %s and the file on disk hashes to %s",
			written.Events.SHA256,
			got,
		)
	}

	lines := strings.Count(strings.TrimRight(string(body), "\n"), "\n") + 1
	if lines != written.Events.Count {
		t.Fatalf(
			"the record claims %d events and the file has %d lines",
			written.Events.Count,
			lines,
		)
	}
}

// The record on disk must parse back into the same shape, or every
// projection built on it is built on a guess.
func TestTheWrittenRecordParsesBackIdentically(t *testing.T) {
	dir := t.TempDir()
	result := finished()

	written, err := Write(
		dir,
		Of("1.2.3", result, definition(t), 2, "defect"),
		EventsOf(result.Observation),
	)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dir, RecordFile))
	if err != nil {
		t.Fatalf("read the record: %v", err)
	}

	var parsed Record
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("the record khaos wrote is not valid JSON: %v", err)
	}

	first, err := Encode(written)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	second, err := Encode(parsed)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}

	if string(first) != string(second) {
		t.Fatal("the record does not survive a parse-and-re-encode round trip")
	}
}

// Every events line is its own JSON object. A single malformed line makes
// the whole file useless to a streaming reader, which is the only kind of
// reader a 1,200-line file gets.
func TestEveryEventsLineIsItsOwnObject(t *testing.T) {
	dir := t.TempDir()
	result := finished()

	if _, err := Write(
		dir,
		Of("1.2.3", result, definition(t), 2, "defect"),
		EventsOf(result.Observation),
	); err != nil {
		t.Fatalf("write: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if !strings.HasSuffix(string(body), "\n") {
		t.Fatal(
			"the events file does not end in a newline, so its last line is unterminated",
		)
	}

	for i, line := range strings.Split(strings.TrimRight(string(body), "\n"), "\n") {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("events line %d is not an object: %v", i+1, err)
		}
	}
}

// Atomicity is the requirement that fails silently: a reader that opens a
// half-written file gets no error, just a truncated record. Proven by there
// being no leftover temporary file and by the destination never existing in
// a partial state, which is what rename-into-place buys.
func TestTheWriteLeavesNoPartialFileBehind(t *testing.T) {
	dir := t.TempDir()
	result := finished()

	if _, err := Write(
		dir,
		Of("1.2.3", result, definition(t), 2, "defect"),
		EventsOf(result.Observation),
	); err != nil {
		t.Fatalf("write: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the directory: %v", err)
	}

	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())

		if strings.HasPrefix(entry.Name(), ".khaos-") {
			t.Errorf(
				"a temporary file survived the write: %s",
				entry.Name(),
			)
		}
	}

	if len(names) != 2 {
		t.Fatalf(
			"the directory holds %v, want exactly the record and its events",
			names,
		)
	}
}

// A second run into the same directory replaces the pair rather than failing
// or appending, because re-running one experiment is the normal thing to do.
func TestWritingTwiceReplacesTheRecord(t *testing.T) {
	dir := t.TempDir()
	result := finished()

	for range 2 {
		if _, err := Write(
			dir,
			Of("1.2.3", result, definition(t), 2, "defect"),
			EventsOf(result.Observation),
		); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("a second write left %d files, want 2", len(entries))
	}
}

// Rename-into-place versus truncate-in-place, discriminated by the INODE.
// This is the half of atomicity a single-threaded test can actually prove: a
// truncating write reuses the destination's inode and is visible to a reader
// in a partial state, while a rename installs a different inode whose
// contents were complete before it became reachable under that name.
func TestTheRecordIsRenamedIntoPlaceRatherThanTruncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, RecordFile)
	result := finished()

	// A first write, so the destination already exists and a truncating
	// implementation has something to truncate.
	if _, err := Write(
		dir,
		Of("1.2.3", result, definition(t), 2, "defect"),
		EventsOf(result.Observation),
	); err != nil {
		t.Fatalf("first write: %v", err)
	}

	before, err := inodeOf(path)
	if err != nil {
		t.Fatalf("stat before: %v", err)
	}

	if _, err := Write(
		dir,
		Of("9.9.9", result, definition(t), 2, "defect"),
		EventsOf(result.Observation),
	); err != nil {
		t.Fatalf("second write: %v", err)
	}

	after, err := inodeOf(path)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}

	if before == after {
		t.Fatal(
			"the record kept its inode across a rewrite, so it was written in place; a reader can see it half-written and gets no error saying so",
		)
	}

	// And the new content is actually there, or "it moved" is meaningless.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if !strings.Contains(string(body), "9.9.9") {
		t.Fatal("the second write did not replace the record's contents")
	}
}

func inodeOf(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errNoInode
	}

	return stat.Ino, nil
}

var errNoInode = errors.New(
	"this platform does not expose an inode, so the rename cannot be distinguished from a truncation here",
)

// Every window the VERDICT reads has to survive serialization, or a defect
// is saved without the observations that established it -- with an events
// hash and count internally consistent about the wrong set.
func TestEveryMeasuredPhaseSurvivesTheRecord(t *testing.T) {
	result := finished()

	for name, window := range map[string]probe.Window{
		"baseline": result.Observation.Baseline,
		"fault":    result.Observation.Fault,
		"shift":    result.Observation.Shift,
		"resumed":  result.Observation.Resumed,
		"recovery": result.Observation.Recovery,
	} {
		if window.Len() == 0 {
			t.Fatalf(
				"the fixture does not populate %q, so this test cannot see it dropped",
				name,
			)
		}
	}

	rec := Of("1.2.3", result, definition(t), 2, "defect")

	for _, name := range []string{
		"baseline",
		"fault",
		"shift",
		"resumed",
		"recovery",
	} {
		if _, ok := rec.Windows[name]; !ok {
			t.Errorf(
				"the record has no %q window, so a verdict resting on it cannot be audited from the record",
				name,
			)
		}
	}

	seen := map[string]int{}
	for _, event := range EventsOf(result.Observation) {
		seen[event.Window]++
	}

	for _, name := range []string{
		"baseline",
		"fault",
		"shift",
		"resumed",
		"recovery",
	} {
		if seen[name] == 0 {
			t.Errorf("events.jsonl carries no %q observation", name)
		}
	}
}

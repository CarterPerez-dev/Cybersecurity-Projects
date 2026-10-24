// ©AngelaMos | 2026
// write.go

package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	dirMode = 0o755

	tempPattern = ".khaos-*"

	errWriteDir  = "create the directory for the run record: %w"
	errWriteFile = "write %s: %w"
	errEncode    = "encode the run record: %w"
)

// Event is one line of events.jsonl. The window is on the line rather than
// implied by position, so a consumer can filter without tracking state, and
// `grep '"window":"fault"' events.jsonl` is a useful thing to be able to do.
type Event struct {
	At          string `json:"at"`
	Window      string `json:"window"`
	Stream      string `json:"stream"`
	Credential  string `json:"credential"`
	Disposition string `json:"disposition"`
	Status      int    `json:"status,omitempty"`
	LatencyMS   int64  `json:"latency_ms"`
	Detail      string `json:"detail,omitempty"`
}

// Write puts the record and its events in dir, and fills the record's events
// reference with the hash of what it actually wrote.
//
// The events go down FIRST: the record names their hash, so writing the
// record before the bytes it hashes would leave a record pointing at a file
// that does not exist yet, which is the window a reader is most likely to
// land in when a run is killed.
func Write(dir string, rec Record, events []Event) (Record, error) {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return rec, fmt.Errorf(errWriteDir, err)
	}

	encoded, err := encodeEvents(events)
	if err != nil {
		return rec, err
	}

	if err := writeAtomic(
		filepath.Join(dir, EventsFile),
		encoded,
	); err != nil {
		return rec, fmt.Errorf(errWriteFile, EventsFile, err)
	}

	sum := sha256.Sum256(encoded)

	rec.Events = &Events{
		File:   EventsFile,
		SHA256: hex.EncodeToString(sum[:]),
		Count:  len(events),
	}

	return rec, WriteRecord(dir, rec)
}

func WriteRecord(dir string, rec Record) error {
	body, err := Encode(rec)
	if err != nil {
		return err
	}

	if err := writeAtomic(
		filepath.Join(dir, RecordFile),
		body,
	); err != nil {
		return fmt.Errorf(errWriteFile, RecordFile, err)
	}

	return nil
}

// Encode is the one JSON form, used for the files and for stdout alike, so
// the two cannot differ. Indented because a record a human will not open is
// a record nobody checks, and HTML escaping off because a URL in a reason
// should read as a URL.
func Encode(rec Record) ([]byte, error) {
	buffer := &writeBuffer{}

	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(rec); err != nil {
		return nil, fmt.Errorf(errEncode, err)
	}

	return buffer.bytes, nil
}

type writeBuffer struct {
	bytes []byte
}

func (b *writeBuffer) Write(p []byte) (int, error) {
	b.bytes = append(b.bytes, p...)
	return len(p), nil
}

func encodeEvents(events []Event) ([]byte, error) {
	buffer := &writeBuffer{}

	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)

	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return nil, fmt.Errorf(errEncode, err)
		}
	}

	return buffer.bytes, nil
}

// writeAtomic writes a temporary file in the SAME directory and renames it
// into place. Same directory because rename is only atomic within one
// filesystem, and atomic because a reader that opens a half-written record
// gets no error, just a truncated one.
func writeAtomic(path string, body []byte) error {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)

	temp, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return err
	}

	name := temp.Name()

	// Removed on every failure path below, so a run that could not finish
	// writing does not leave litter next to the record it failed to produce.
	defer func() { _ = os.Remove(name) }()

	if _, err := temp.Write(body); err != nil {
		_ = temp.Close()
		return err
	}

	// Durability before visibility: a rename that beats the data to disk
	// leaves a correctly named, empty file after a crash.
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}

	if err := temp.Close(); err != nil {
		return err
	}

	// Left at the 0600 os.CreateTemp gives it, deliberately. A probe
	// outcome's Detail carries whatever the target answered, so the record
	// is not a file to widen by default, and the operator khaos runs as is
	// the operator CI runs as.
	//nolint:gosec // the operator's own --record destination, cleaned above;
	// khaos holds no privilege they do not, so there is no boundary here to
	// traverse
	return os.Rename(name, path)
}

// Events flattens every window's streams into one time-ordered sequence,
// which is the order they were observed in and the order a reader expects.
func EventsOf(observation experiment.Observation) []Event {
	out := []Event{}

	for _, phase := range Phases(observation) {
		out = append(out, eventsOfWindow(phase.Name, phase.Window)...)
	}

	return out
}

func eventsOfWindow(window string, from probe.Window) []Event {
	out := []Event{}

	for _, named := range []struct {
		name   string
		stream probe.Stream
	}{
		{"valid", from.Valid},
		{"invalid", from.Invalid},
		{"revoked", from.Revoked},
		{"forged", from.Forged},
	} {
		for _, outcome := range named.stream.Outcomes {
			out = append(out, Event{
				At:          outcome.At.UTC().Format(timeLayout),
				Window:      window,
				Stream:      named.name,
				Credential:  string(outcome.Credential),
				Disposition: string(outcome.Disposition),
				Status:      outcome.Status,
				LatencyMS:   outcome.LatencyMS,
				Detail:      outcome.Detail,
			})
		}
	}

	// Within a window the streams are recorded one after another, so a naive
	// concatenation interleaves nothing and reads as four separate runs.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].At < out[j].At
	})

	return out
}

// WriteFile puts one projection where it was asked for, with the same
// atomic rename the record gets: node_exporter reading a half-written
// metrics file ships corrupted data rather than an error, and a CI reporter
// parsing a half-written XML file reports a broken suite.
func WriteFile(path string, body []byte) error {
	dir := filepath.Dir(filepath.Clean(path))

	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf(errWriteDir, err)
	}

	if err := writeAtomic(path, body); err != nil {
		return fmt.Errorf(errWriteFile, filepath.Base(path), err)
	}

	return nil
}

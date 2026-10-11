// ©AngelaMos | 2026
// journal.go

package journal

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Phase string

const (
	PhasePending  Phase = "pending"
	PhaseApplied  Phase = "applied"
	PhaseReverted Phase = "reverted"
	PhaseFailed   Phase = "failed"
)

const (
	dirMode  = 0o700
	fileMode = 0o600

	scanInitialBytes = 64 * 1024
	scanMaxBytes     = 1024 * 1024

	tempSuffix = ".compacting"

	errOpen    = "open journal: %w"
	errRead    = "read journal: %w"
	errAppend  = "append to journal: %w"
	errEncode  = "encode journal record: %w"
	errDamaged = "%w: %s line %d: %v"
	errCompact = "compact journal: %w"
	errPayload = "journal payload: %w"
)

var (
	ErrDamaged = errors.New(
		"the journal contains a line khaos cannot parse, so it may be hiding an outstanding fault",
	)
	ErrNoPayload = errors.New(
		"the journal record carries no payload, so khaos cannot tell what to restore",
	)
)

func NewID() string {
	return rand.Text()
}

type Record struct {
	MutationID string `json:"mutation_id"`
	RunID      string `json:"run_id"`
	LeaseID    string `json:"lease_id"`
	Kind       string `json:"kind"`

	// Daemon is the Docker daemon this mutation lives on. Without it a container
	// ID is ambiguous across machines: reclaiming against another daemon finds
	// no such container, reads that as "the target is gone, the fault went with
	// it", and marks the record REVERTED. The original fault stays applied on
	// the original daemon and is now invisible to every future sweep.
	//
	// Empty means khaos could not establish it, which is a different state from
	// a mismatch and must not be settled automatically.
	Daemon string `json:"daemon,omitempty"`

	TargetID   string          `json:"target_id"`
	TargetName string          `json:"target_name"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Phase      Phase           `json:"phase"`
	At         time.Time       `json:"at"`
	ExpiresAt  time.Time       `json:"expires_at,omitempty"`
	Detail     string          `json:"detail,omitempty"`
}

func (r Record) DecodePayload(into any) error {
	if len(r.Payload) == 0 {
		return ErrNoPayload
	}
	if err := json.Unmarshal(r.Payload, into); err != nil {
		return fmt.Errorf(errPayload, err)
	}
	return nil
}

func EncodePayload(from any) (json.RawMessage, error) {
	raw, err := json.Marshal(from)
	if err != nil {
		return nil, fmt.Errorf(errPayload, err)
	}
	return raw, nil
}

func (r Record) Expired(now time.Time) bool {
	if r.ExpiresAt.IsZero() {
		return true
	}
	return now.After(r.ExpiresAt)
}

func (r Record) Outstanding() bool {
	return r.Phase == PhasePending || r.Phase == PhaseApplied ||
		r.Phase == PhaseFailed
}

type Journal struct {
	path string
	file *os.File
}

func Open(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return nil, fmt.Errorf(errOpen, err)
	}

	//nolint:gosec // khaos's own state dir, from statedir.Paths
	file, err := os.OpenFile(
		path,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		fileMode,
	)
	if err != nil {
		return nil, fmt.Errorf(errOpen, err)
	}

	return &Journal{path: path, file: file}, nil
}

func (j *Journal) Path() string {
	return j.path
}

func (j *Journal) Append(record Record) error {
	if record.At.IsZero() {
		record.At = time.Now().UTC()
	}

	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf(errEncode, err)
	}

	if _, err := j.file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf(errAppend, err)
	}

	return j.file.Sync()
}

func (j *Journal) Close() error {
	return j.file.Close()
}

func Replay(path string) ([]Record, error) {
	//nolint:gosec // khaos's own journal, from statedir.Paths
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf(errOpen, err)
	}
	defer func() { _ = file.Close() }()

	var (
		records []Record
		damage  error
	)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, scanInitialBytes), scanMaxBytes)

	for line := 1; scanner.Scan(); line++ {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}

		var record Record
		if err := json.Unmarshal(raw, &record); err != nil {
			if damage == nil {
				damage = fmt.Errorf(errDamaged, ErrDamaged, path, line, err)
			}
			continue
		}

		records = append(records, record)
	}

	if err := scanner.Err(); err != nil {
		return records, fmt.Errorf(errRead, err)
	}

	return records, damage
}

func Outstanding(path string) ([]Record, error) {
	records, damage := Replay(path)

	latest := make(map[string]Record, len(records))
	order := make([]string, 0, len(records))
	settled := make(map[string]bool, len(records))

	for _, record := range records {
		if _, seen := latest[record.MutationID]; !seen {
			order = append(order, record.MutationID)
		}

		// A completed reversion is TERMINAL. Plain last-write-wins let a record
		// come back: the reaper reverts a fault and appends Reverted while a
		// renewal that read the journal before that is still in flight, and the
		// renewal then appends Applied with a fresh expiry from its stale
		// snapshot. Replay believed the newer line, so khaos went on renewing a
		// lease for a fault that no longer existed, and the next reaper sweep
		// would try to revert a target nothing had touched.
		//
		// Nothing legitimately re-applies a mutation ID: a new fault gets a new
		// one. So the first successful reversion ends that ID's life.
		if record.Phase == PhaseReverted {
			settled[record.MutationID] = true
		}

		latest[record.MutationID] = record
	}

	out := make([]Record, 0, len(order))
	for _, id := range order {
		if settled[id] {
			continue
		}
		if record := latest[id]; record.Outstanding() {
			out = append(out, record)
		}
	}

	return out, damage
}

func Compact(path string) error {
	outstanding, err := Outstanding(path)
	if err != nil {
		return err
	}

	temp := path + tempSuffix

	//nolint:gosec // the compaction temp beside khaos's own journal
	file, err := os.OpenFile(temp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf(errCompact, err)
	}

	encoder := json.NewEncoder(file)
	for _, record := range outstanding {
		if err := encoder.Encode(record); err != nil {
			_ = file.Close()
			_ = os.Remove(temp)
			return fmt.Errorf(errCompact, err)
		}
	}

	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temp)
		return fmt.Errorf(errCompact, err)
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf(errCompact, err)
	}

	return os.Rename(temp, path)
}

// ShortDaemon trims a daemon ID for display, the way container IDs are trimmed.
// The full value stays in the record; this is only for a human reading an error.
func ShortDaemon(id string) string {
	if len(id) <= shortDaemonLength {
		return id
	}
	return id[:shortDaemonLength]
}

const shortDaemonLength = 12

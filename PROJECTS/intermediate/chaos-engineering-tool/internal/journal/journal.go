// ©AngelaMos | 2026
// journal.go

package journal

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/lock"
)

type Phase string

const (
	PhasePending  Phase = "pending"
	PhaseApplied  Phase = "applied"
	PhaseReverted Phase = "reverted"
	PhaseFailed   Phase = "failed"

	// PhaseRenewed is an expiry extension and nothing else. It is distinct
	// from PhaseApplied because an application re-opens a mutation a reaper
	// already reverted and a renewal must never be able to.
	PhaseRenewed Phase = "renewed"
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

	// Daemon disambiguates a container ID across machines. Empty means khaos
	// could not establish it, which is not the same as a mismatch.
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
		r.Phase == PhaseFailed || r.Phase == PhaseRenewed
}

type Journal struct {
	mu   sync.Mutex
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
	j.mu.Lock()
	defer j.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	held, err := lock.AcquireContext(ctx, j.path+".write")
	if err != nil {
		return fmt.Errorf(errAppend, err)
	}
	defer func() { _ = held.Release() }()
	if err := j.refresh(); err != nil {
		return err
	}
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
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.file.Close()
}

func (j *Journal) refresh() error {
	opened, err := j.file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Stat(j.path)
	if err == nil && os.SameFile(opened, current) {
		return nil
	}
	if err != nil {
		return err
	}
	reopened, err := Open(j.path)
	if err != nil {
		return err
	}
	_ = j.file.Close()
	j.file = reopened.file
	return nil
}

func Replay(path string) ([]Record, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	held, err := lock.AcquireContext(ctx, path+".write")
	if err != nil {
		return nil, err
	}
	defer func() { _ = held.Release() }()
	return replay(path)
}

func replay(path string) ([]Record, error) {
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
	return outstanding(records), damage
}

func outstanding(records []Record) []Record {
	latest := make(map[string]Record, len(records))
	order := make([]string, 0, len(records))
	settled := make(map[string]bool, len(records))

	for _, record := range records {
		if _, seen := latest[record.MutationID]; !seen {
			order = append(order, record.MutationID)
		}

		// A reversion is terminal against a renewal, because last-write-wins
		// would let a stale one resurrect the record. It is NOT terminal
		// against an application: a reaper can revert a mutation whose Apply
		// is still in flight, and that Apply leaves a live fault that has to
		// stay recoverable.
		switch record.Phase {
		case PhaseReverted:
			settled[record.MutationID] = true
		case PhaseApplied, PhaseFailed:
			delete(settled, record.MutationID)
		case PhasePending, PhaseRenewed:
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

	return out
}

func Compact(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	held, err := lock.AcquireContext(ctx, path+".write")
	if err != nil {
		return err
	}
	defer func() { _ = held.Release() }()
	records, err := replay(path)
	if err != nil {
		return err
	}
	live := outstanding(records)

	temp := path + tempSuffix

	//nolint:gosec // the compaction temp beside khaos's own journal
	file, err := os.OpenFile(temp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf(errCompact, err)
	}

	encoder := json.NewEncoder(file)
	for _, record := range live {
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

// ShortDaemon trims a daemon ID for display; the full value stays in the record.
func ShortDaemon(id string) string {
	if len(id) <= shortDaemonLength {
		return id
	}
	return id[:shortDaemonLength]
}

const shortDaemonLength = 12

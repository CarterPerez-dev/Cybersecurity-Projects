// ©AngelaMos | 2026
// record.go

package record

import (
	"time"

	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	// Version is the record's own schema version, independent of khaos's. A
	// consumer that parses this file needs to know when its shape changed,
	// and the binary's version moves for reasons that do not touch it.
	Version = 2

	// EventsFile sits beside the record rather than inside it. A sixty-second
	// run at 300ms over four streams is roughly 800 observations: embedded
	// they make the record impossible to read or paste into a ticket, and
	// discarded they make the verdict unauditable.
	RecordFile = "run.json"
	EventsFile = "events.jsonl"

	// RFC 3339 with nanoseconds, so events at a 300ms interval sort
	// lexicographically as well as chronologically.
	timeLayout = time.RFC3339Nano
)

type Record struct {
	Schema  int    `json:"schema_version"`
	Khaos   string `json:"khaos_version"`
	RunID   string `json:"run_id"`
	Started string `json:"started_at"`
	Ended   string `json:"ended_at"`

	DurationMS int64 `json:"duration_ms"`

	Experiment    Experiment               `json:"experiment"`
	Fault         Fault                    `json:"fault"`
	Configuration experiment.Configuration `json:"configuration"`
	HaltReason    string                   `json:"halt_reason,omitempty"`

	Windows map[string]Window `json:"windows"`

	Verdict Verdict `json:"verdict"`

	// Exit is what khaos returned to the shell, in the record, because the
	// exit code is the only part of a run most CI ever sees and a record that
	// cannot explain it is not a record of the run.
	Exit           Exit     `json:"exit"`
	ArtifactErrors []string `json:"artifact_errors,omitempty"`

	// Events names the file beside this one and the hash of its bytes, so a
	// record cannot be silently separated from the observations it summarises.
	Events *Events `json:"events,omitempty"`
}

type Experiment struct {
	Name       string `json:"name"`
	Family     string `json:"family"`
	Hypothesis string `json:"hypothesis"`

	// Defects is the directions THIS experiment declares a defect, which is
	// what makes the verdict's direction readable: the same direction is a
	// finding for one control and correct for another.
	Defects   []string `json:"declared_defects"`
	Rationale string   `json:"polarity_rationale,omitempty"`
}

type Fault struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`

	// Confirmed is REQUIRED for any verdict khaos will stand behind: an
	// injection the API accepted is not a fault that took effect, and a run
	// measuring no fault at all reads as a pass.
	Confirmed bool   `json:"confirmed"`
	Method    string `json:"confirm_method,omitempty"`

	HeldFor int64 `json:"held_for_ms,omitempty"`

	RollbackFailed bool `json:"rollback_failed"`
}

// Window is one measurement window, aggregated. The raw per-observation data
// is in the events file.
type Window struct {
	Paired   int               `json:"paired"`
	Requests int               `json:"requests"`
	Streams  map[string]Stream `json:"streams"`
}

type Stream struct {
	Countable    int            `json:"countable"`
	Answered     int            `json:"answered"`
	Distribution map[string]int `json:"distribution"`
}

type Verdict struct {
	Epistemic  string   `json:"epistemic"`
	Direction  string   `json:"direction"`
	Cause      string   `json:"cause"`
	Recovery   string   `json:"recovery"`
	Conclusive bool     `json:"conclusive"`
	Defect     bool     `json:"defect"`
	Reasons    []string `json:"reasons"`
	Warnings   []string `json:"warnings,omitempty"`
}

type Exit struct {
	Code    int    `json:"code"`
	Outcome string `json:"outcome,omitempty"`
}

type Events struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Count  int    `json:"count"`
}

// Of projects a finished run onto the record. It is the ONE place the shape
// is decided, so the stdout form and the files cannot drift from each other.
func Of(
	version string,
	result experiment.Result,
	definition experiment.Definition,
	code int,
	outcome string,
) Record {
	ended := result.StartedAt.Add(result.Duration)

	return Record{
		Schema:        Version,
		Khaos:         version,
		RunID:         result.RunID,
		Started:       result.StartedAt.UTC().Format(time.RFC3339Nano),
		Ended:         ended.UTC().Format(time.RFC3339Nano),
		DurationMS:    result.Duration.Milliseconds(),
		Configuration: result.Configuration,
		HaltReason:    result.Observation.HaltReason,
		Experiment: Experiment{
			Name:       result.Experiment,
			Family:     result.Family,
			Hypothesis: result.Hypothesis,
			Defects:    directions(definition.Polarity.Defects),
			Rationale:  definition.Polarity.Rationale,
		},
		Fault: Fault{
			Kind:           result.Fault.Kind,
			Target:         result.Fault.Target,
			Confirmed:      result.Observation.FaultConfirmed,
			Method:         result.Observation.ConfirmMethod,
			HeldFor:        result.Observation.FaultFor.Milliseconds(),
			RollbackFailed: result.Observation.RollbackFailed,
		},
		Windows: windows(result.Observation),
		Verdict: Verdict{
			Epistemic:  string(result.Verdict.Epistemic),
			Direction:  string(result.Verdict.Direction),
			Cause:      string(result.Verdict.Cause),
			Recovery:   string(result.Verdict.Recovery),
			Conclusive: result.Verdict.Conclusive,
			Defect:     result.Verdict.Defect,
			Reasons:    result.Verdict.Reasons,
			Warnings:   warnings(result.Verdict.Warnings),
		},
		Exit: Exit{Code: code, Outcome: outcome},
	}
}

func directions(from []experiment.Direction) []string {
	out := make([]string, 0, len(from))
	for _, direction := range from {
		out = append(out, string(direction))
	}
	return out
}

func warnings(from []experiment.Warning) []string {
	out := make([]string, 0, len(from))
	for _, warning := range from {
		out = append(out, string(warning))
	}
	return out
}

// Phase is one measured window under the name the record calls it by.
type Phase struct {
	Name   string
	Window probe.Window
}

// Phases is the ONE enumeration of the measured windows, in the order the
// engine measures them. Both serializers read it, so a phase added to the
// engine cannot go missing from one of them and leave a verdict resting on
// observations the record does not carry.
func Phases(observation experiment.Observation) []Phase {
	return []Phase{
		{"baseline", observation.Baseline},
		{"fault", observation.Fault},
		{"shift", observation.Shift},
		{"resumed", observation.Resumed},
		{"recovery", observation.Recovery},
	}
}

// windows omits a window that was never measured rather than recording it as
// zero: "khaos did not get here" and "khaos measured nothing here" are
// different facts, and a reader cannot tell them apart from a zero.
func windows(observation experiment.Observation) map[string]Window {
	out := map[string]Window{}

	for _, phase := range Phases(observation) {
		if phase.Window.Valid.Len()+phase.Window.Invalid.Len()+
			phase.Window.Revoked.Len()+phase.Window.Forged.Len() == 0 {
			continue
		}

		out[phase.Name] = aggregate(phase.Window)
	}

	return out
}

func aggregate(window probe.Window) Window {
	out := Window{
		Paired:   window.Paired(),
		Requests: window.Requests(),
		Streams:  map[string]Stream{},
	}

	for name, stream := range map[string]probe.Stream{
		"valid":   window.Valid,
		"invalid": window.Invalid,
		"revoked": window.Revoked,
		"forged":  window.Forged,
	} {
		if stream.Len() == 0 {
			continue
		}

		out.Streams[name] = Stream{
			Countable:    stream.Countable(),
			Answered:     stream.Answered(),
			Distribution: distribution(stream),
		}
	}

	return out
}

func distribution(stream probe.Stream) map[string]int {
	out := map[string]int{}
	for disposition, count := range stream.Distribution() {
		out[string(disposition)] = count
	}
	return out
}

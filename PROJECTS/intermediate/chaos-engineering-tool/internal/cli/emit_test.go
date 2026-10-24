// ©AngelaMos | 2026
// emit_test.go

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/record"
	"github.com/spf13/pflag"
)

func emitted(t *testing.T) (experiment.Result, experiment.Definition) {
	t.Helper()

	definition, err := experiment.Lookup("control.policy_store_down")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	result := held()
	result.Experiment = definition.Name
	result.Family = definition.Family
	result.Hypothesis = "a hypothesis"
	result.Fault = experiment.Fault{
		Kind:   definition.FaultKind,
		Target: "a-target",
	}

	return result, definition
}

func TestSurvivingArtifactsCarryProjectionFailureAndFinalExit(t *testing.T) {
	result, definition := emitted(t)
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &strings.Builder{}
	err := emitRecord(out, definition, result, nil, Output{
		Shape: outputJSON, Record: dir,
		Projections: Projections{JUnit: filepath.Join(blocker, "junit.xml")},
	})
	if !errors.Is(err, ErrRecordUnwritten) {
		t.Fatalf("publication error = %v", err)
	}
	disk, readErr := os.ReadFile(filepath.Join(dir, record.RecordFile))
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, body := range [][]byte{disk, []byte(out.String())} {
		var rec record.Record
		if decodeErr := json.Unmarshal(body, &rec); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if rec.Exit.Code != ExitCode(err) || len(rec.ArtifactErrors) == 0 {
			t.Fatalf(
				"publication failure absent: exit=%+v errors=%v",
				rec.Exit, rec.ArtifactErrors,
			)
		}
	}
}

// Under --output json, stdout carries the record and NOTHING else. A single
// banner line makes `khaos run x --output json | jq .verdict` fail on the
// first byte, and that failure names jq rather than khaos.
func TestJSONOutputWritesOnlyTheRecord(t *testing.T) {
	result, definition := emitted(t)

	out := &strings.Builder{}

	if err := emitRecord(
		out,
		definition,
		result,
		nil,
		Output{Shape: outputJSON, Record: ""},
	); err != nil {
		t.Fatalf("emit: %v", err)
	}

	body := out.String()

	if !strings.HasPrefix(body, "{") {
		t.Fatalf("stdout does not begin with the record: %.40q", body)
	}

	var parsed record.Record
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("stdout is not a single JSON object: %v", err)
	}

	if parsed.Experiment.Name != definition.Name {
		t.Fatalf("the record names %q", parsed.Experiment.Name)
	}
}

// The text shape writes no record to stdout at all, or every existing
// consumer of the terminal report gets a wall of JSON appended to it.
func TestTextOutputWritesNoRecordToStdout(t *testing.T) {
	result, definition := emitted(t)

	out := &strings.Builder{}

	if err := emitRecord(
		out,
		definition,
		result,
		nil,
		Output{Shape: outputText, Record: ""},
	); err != nil {
		t.Fatalf("emit: %v", err)
	}

	if out.String() != "" {
		t.Fatalf("the text shape wrote to stdout: %.60q", out.String())
	}
}

// The record carries the code khaos is about to return, because the exit
// status is the only part of a run most CI ever sees.
func TestTheRecordCarriesTheExitItIsAbout(t *testing.T) {
	result, definition := emitted(t)

	for _, row := range []struct {
		name    string
		outcome error
		code    int
		label   string
	}{
		{"a clean run", nil, CodeOK, ""},
		{
			"a defect",
			&Exit{
				Code:    CodeDefect,
				Outcome: OutcomeDefect,
				Err:     ErrDefectFound,
			},
			CodeDefect,
			string(OutcomeDefect),
		},
		{
			"thin evidence",
			&Exit{
				Code:    CodeInconclusive,
				Outcome: OutcomeInconclusive,
				Err:     ErrInconclusive,
			},
			CodeInconclusive,
			string(OutcomeInconclusive),
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			out := &strings.Builder{}

			err := emitRecord(
				out,
				definition,
				result,
				row.outcome,
				Output{Shape: outputJSON, Record: ""},
			)

			if !errors.Is(err, row.outcome) {
				t.Fatalf("emit returned %v, want %v", err, row.outcome)
			}

			var parsed record.Record
			if decodeErr := json.Unmarshal(
				[]byte(out.String()),
				&parsed,
			); decodeErr != nil {
				t.Fatalf("decode: %v", decodeErr)
			}

			if parsed.Exit.Code != row.code {
				t.Errorf(
					"the record says exit %d and khaos returns %d",
					parsed.Exit.Code,
					row.code,
				)
			}

			if parsed.Exit.Outcome != row.label {
				t.Errorf(
					"the record names the outcome %q, want %q",
					parsed.Exit.Outcome,
					row.label,
				)
			}
		})
	}
}

// A verdict khaos reached outranks a file it could not write: a run that
// found a bypass still exits on the bypass.
func TestAVerdictOutranksARecordThatCouldNotBeWritten(t *testing.T) {
	result, definition := emitted(t)

	defect := &Exit{
		Code:    CodeDefect,
		Outcome: OutcomeDefect,
		Err:     ErrDefectFound,
	}

	out := &strings.Builder{}
	diagnostic := &strings.Builder{}

	err := emitRecord(
		out,
		definition,
		result,
		defect,
		Output{
			Shape:      outputText,
			Record:     filepath.Join("/proc", "khaos-cannot-write-here"),
			Diagnostic: diagnostic,
		},
	)

	if !errors.Is(err, ErrDefectFound) {
		t.Fatalf("the defect was masked by the write failure: %v", err)
	}

	// And the failure is still SAID, because an operator who asked for a
	// record and did not get one must not have to guess. On the DIAGNOSTIC
	// stream, not the report stream: the same line on stdout appended prose to
	// the JSON document under --output json.
	if !strings.Contains(
		diagnostic.String(),
		"could not write the run record",
	) {
		t.Fatalf("the write failure was silent: %.80q", diagnostic.String())
	}

	if strings.Contains(out.String(), "could not write") {
		t.Fatalf(
			"the write failure reached the report stream, which is what breaks --output json: %.80q",
			out.String(),
		)
	}
}

// But a CLEAN run that could not write the record the operator asked for
// fails on the write: in CI they believe they have an artifact and do not.
func TestACleanRunFailsWhenItsRecordCannotBeWritten(t *testing.T) {
	result, definition := emitted(t)

	err := emitRecord(
		&strings.Builder{},
		definition,
		result,
		nil,
		Output{
			Shape:  outputText,
			Record: filepath.Join("/proc", "khaos-cannot-write-here"),
		},
	)

	if !errors.Is(err, ErrRecordUnwritten) {
		t.Fatalf("a missing record was silent on a clean run: %v", err)
	}
}

// THE PROJECTION INVARIANT. The record is canonical and the stdout form is a
// projection of it, so the bytes on stdout and the bytes on disk have to be
// the same record. If they can differ, "the pretty output says one thing and
// the JSON says another" is back.
func TestTheRecordOnStdoutIsTheRecordOnDisk(t *testing.T) {
	result, definition := emitted(t)
	dir := t.TempDir()

	out := &strings.Builder{}

	if err := emitRecord(
		out,
		definition,
		result,
		nil,
		Output{Shape: outputJSON, Record: dir},
	); err != nil {
		t.Fatalf("emit: %v", err)
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, record.RecordFile))
	if err != nil {
		t.Fatalf("read the record: %v", err)
	}

	if out.String() != string(onDisk) {
		t.Fatal(
			"the record on stdout and the record on disk are not the same bytes",
		)
	}
}

// An unrecognised --output is refused rather than falling back to the
// terminal report: a pipeline that asked for json and silently got a banner
// fails somewhere that does not name the cause.
func TestAnUnknownOutputShapeIsRefused(t *testing.T) {
	cmd := find(t, NewRoot(), "run")

	sub := find(t, cmd, "control.policy_store_down")

	if err := sub.Flags().Set(flagOutput, "yaml"); err != nil {
		t.Fatalf("set: %v", err)
	}

	_, err := outputShape(sub)
	if !errors.Is(err, ErrUnknownOutput) {
		t.Fatalf("an unknown output shape was accepted: %v", err)
	}
}

// Both shapes are accepted, so the refusal above cannot be passing because
// outputShape refuses everything.
func TestBothOutputShapesAreAccepted(t *testing.T) {
	cmd := find(t, NewRoot(), "run")
	sub := find(t, cmd, "control.policy_store_down")

	for _, shape := range []string{outputText, outputJSON} {
		if err := sub.Flags().Set(flagOutput, shape); err != nil {
			t.Fatalf("set %q: %v", shape, err)
		}

		got, err := outputShape(sub)
		if err != nil {
			t.Fatalf("outputShape(%q): %v", shape, err)
		}

		if got != shape {
			t.Fatalf("outputShape(%q) = %q", shape, got)
		}
	}
}

// Both projections are written from the FINISHED record, so they describe
// the same run as the file on disk. Deriving either one before the record is
// complete is how a JUnit suite ends up naming a different exit code than
// the record beside it.
func TestTheProjectionsDescribeTheSameRunAsTheRecord(t *testing.T) {
	result, definition := emitted(t)
	dir := t.TempDir()

	defect := &Exit{
		Code:    CodeDefect,
		Outcome: OutcomeDefect,
		Err:     ErrDefectFound,
	}

	junit := filepath.Join(dir, "khaos.xml")
	metrics := filepath.Join(dir, "khaos.prom")

	err := emitRecord(
		&strings.Builder{},
		definition,
		result,
		defect,
		Output{
			Shape:       outputText,
			Record:      dir,
			Projections: Projections{JUnit: junit, Metrics: metrics},
		},
	)

	if !errors.Is(err, ErrDefectFound) {
		t.Fatalf("emit: %v", err)
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, record.RecordFile))
	if err != nil {
		t.Fatalf("read the record: %v", err)
	}

	var parsed record.Record
	if err := json.Unmarshal(onDisk, &parsed); err != nil {
		t.Fatalf("decode: %v", err)
	}

	xmlBody, err := os.ReadFile(junit)
	if err != nil {
		t.Fatalf("read the junit: %v", err)
	}

	promBody, err := os.ReadFile(metrics)
	if err != nil {
		t.Fatalf("read the metrics: %v", err)
	}

	// The run id ties all three together, and the exit code is the thing
	// most likely to be computed twice and disagree.
	for name, body := range map[string]string{
		"junit":   string(xmlBody),
		"metrics": string(promBody),
	} {
		if !strings.Contains(body, parsed.RunID) {
			t.Errorf("the %s does not carry the record's run id", name)
		}

		if !strings.Contains(body, strconv.Itoa(parsed.Exit.Code)) {
			t.Errorf(
				"the %s does not carry the record's exit code %d",
				name,
				parsed.Exit.Code,
			)
		}
	}

	// And the record's own events reference survived being written before
	// the projections were derived from it.
	if parsed.Events == nil || parsed.Events.SHA256 == "" {
		t.Error("the record on disk carries no events reference")
	}
}

// A projection khaos could not write follows the same rule as the record: a
// verdict outranks it, and it is never silent.
func TestAProjectionThatCannotBeWrittenIsNotSilent(t *testing.T) {
	result, definition := emitted(t)

	err := emitRecord(
		&strings.Builder{},
		definition,
		result,
		nil,
		Output{
			Shape:  outputText,
			Record: "",
			Projections: Projections{
				JUnit: filepath.Join("/proc", "nope", "khaos.xml"),
			},
		},
	)

	if !errors.Is(err, ErrRecordUnwritten) {
		t.Fatalf("a projection khaos could not write was silent: %v", err)
	}
}

// pflag advertises a flag's value by the FIRST backquoted word in its usage
// string, so the placeholder is prose maintained like a signature. --record
// takes a DIRECTORY, and advertising a filename sends an operator to the
// wrong shape.
func TestTheReportingFlagsAdvertiseWhatTheyTake(t *testing.T) {
	definition := outage(t)
	sub := experimentCmdFor(t, newRunCmd(), definition)

	for name, want := range map[string]string{
		flagRecord:     "dir",
		flagJUnit:      "file",
		flagMetricsOut: "file",
	} {
		flag := sub.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("--%s is not registered on %s", name, definition.Name)
		}

		got, _ := pflag.UnquoteUsage(flag)
		if got != want {
			t.Errorf(
				"--%s advertises %q, want %q: a placeholder an operator can "+
					"mistake for a value or a default sends them to the wrong shape",
				name,
				got,
				want,
			)
		}
	}
}

// --output json promises stdout carries the record and nothing else, so
// `khaos run x --output json | jq .verdict` works. A defect plus an
// unwritable --record must not append prose to that document.
func TestAnArtifactFailureNeverContaminatesTheJSONStream(t *testing.T) {
	result, definition := emitted(t)

	out := &strings.Builder{}
	diagnostic := &strings.Builder{}

	outcome := &Exit{
		Code:    CodeDefect,
		Outcome: OutcomeDefect,
		Err:     ErrDefectFound,
	}

	err := emitRecord(
		out,
		definition,
		result,
		outcome,
		Output{
			Shape:      outputJSON,
			Record:     filepath.Join("/proc", "khaos-cannot-write-here"),
			Diagnostic: diagnostic,
		},
	)

	// The verdict outranks the bookkeeping: the defect still comes back.
	if !errors.Is(err, ErrDefectFound) {
		t.Fatalf("the defect was replaced by the write failure: %v", err)
	}

	body := out.String()

	var parsed record.Record
	if jsonErr := json.Unmarshal([]byte(body), &parsed); jsonErr != nil {
		t.Fatalf(
			"stdout is not a single decodable JSON document, so the --output json contract is broken on the path CI depends on: %v\nstdout was: %q",
			jsonErr,
			body,
		)
	}

	// And the failure is not swallowed: in CI the operator believes they have
	// an artifact, so the warning has to land somewhere they will see it.
	if !strings.Contains(diagnostic.String(), "could not write") {
		t.Fatalf(
			"the artifact failure was not reported on the diagnostic stream: %q",
			diagnostic.String(),
		)
	}
}

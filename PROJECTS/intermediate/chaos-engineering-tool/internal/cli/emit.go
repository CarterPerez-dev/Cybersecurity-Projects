// ©AngelaMos | 2026
// emit.go

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/record"
	"github.com/CarterPerez-dev/khaos/internal/run"
	"github.com/CarterPerez-dev/khaos/internal/version"
	"github.com/spf13/cobra"
)

const (
	errUnknownOutput = "%w: %q (khaos writes %s or %s)"
	errRecordWrite   = "%w: %v"
	warnRecordWrite  = "khaos could not write the run record: %v\n"
)

var ErrUnknownOutput = errors.New(
	"that is not an output shape khaos can write",
)

var ErrRecordUnwritten = errors.New(
	"the run finished and khaos could not write the record you asked for",
)

// outputShape refuses an unrecognised value rather than falling back to the
// terminal report: a pipeline that asked for json and silently got a banner
// fails downstream in a place that does not name the cause.
func outputShape(cmd *cobra.Command) (string, error) {
	shape, err := cmd.Flags().GetString(flagOutput)
	if err != nil {
		return "", err
	}

	switch shape {
	case outputText, outputJSON:
		return shape, nil
	default:
		return "", fmt.Errorf(
			errUnknownOutput,
			ErrUnknownOutput,
			shape,
			outputText,
			outputJSON,
		)
	}
}

// Projections are the files that are derived from the record rather than
// being it. Each is a path or empty.
type Projections struct {
	JUnit   string
	Metrics string
}

func projectionsOf(cmd *cobra.Command) (Projections, error) {
	junit, err := cmd.Flags().GetString(flagJUnit)
	if err != nil {
		return Projections{}, err
	}

	metrics, err := cmd.Flags().GetString(flagMetricsOut)
	if err != nil {
		return Projections{}, err
	}

	return Projections{JUnit: junit, Metrics: metrics}, nil
}

// emitRecord writes the canonical record where it was asked for and returns
// the run's own outcome.
//
// The ORDER of the two failures matters. The verdict outranks the
// bookkeeping, so a record khaos could not write never masks a defect: a run
// that found a bypass still exits 2 and says the record is missing. But a
// record an operator explicitly asked for and did not get must not be
// SILENT either, because in CI they believe they have an artifact and do
// not. So a clean run that could not write its record fails on the write.
func emitRecord(
	out io.Writer,
	definition experiment.Definition,
	result experiment.Result,
	outcome error,
	emit Output,
) error {
	code, name := exitDetail(outcome)

	rec := record.Of(version.Version(), result, definition, code, name)

	var writeErr error

	if emit.Record != "" {
		rec, writeErr = record.Write(
			emit.Record,
			rec,
			record.EventsOf(result.Observation),
		)
	}

	if emit.Shape == outputJSON {
		body, err := record.Encode(rec)
		if err != nil {
			return err
		}

		if _, err := out.Write(body); err != nil {
			return err
		}
	}

	// The projections are derived from the record AFTER it is complete, so
	// they carry its events reference and its exit code and cannot describe
	// a different run than the one on disk.
	if err := writeProjections(rec, emit.Projections); err != nil {
		writeErr = errors.Join(writeErr, err)
	}

	if writeErr == nil {
		return outcome
	}

	// A verdict khaos reached outranks a file it could not write. The warning
	// goes to the DIAGNOSTIC stream: writing it to out appended prose to the
	// JSON document under --output json, which breaks that contract on the one
	// path where CI needs machine-readable evidence.
	if outcome != nil {
		fmt.Fprintf(emit.diagnostic(), warnRecordWrite, writeErr)

		return outcome
	}

	return fmt.Errorf(errRecordWrite, ErrRecordUnwritten, writeErr)
}

// writeProjections writes each derived file that was asked for. They are
// derived from the record alone, which is what makes them projections rather
// than second opinions.
func writeProjections(rec record.Record, into Projections) error {
	var failures error

	if into.JUnit != "" {
		body, err := record.JUnit(rec)
		if err != nil {
			failures = errors.Join(failures, err)
		} else {
			failures = errors.Join(
				failures,
				record.WriteFile(into.JUnit, body),
			)
		}
	}

	if into.Metrics != "" {
		failures = errors.Join(
			failures,
			record.WriteFile(into.Metrics, record.Metrics(rec)),
		)
	}

	return failures
}

// exitDetail reads the code and the outcome name back off a finished run, so
// the record can carry what khaos is about to return to the shell.
//
// It is the SAME classification the process boundary uses, because these were
// two lists: this one mapped anything without a typed Exit to usage code 1
// while the boundary recognised the rollback and cancellation sentinels on its
// own, so a real rollback failure wrote exit.code 1 into run.json and exited 6.
func exitDetail(outcome error) (int, string) {
	if outcome == nil {
		return CodeOK, ""
	}

	// Matched on the sentinels BEFORE any carried code, because these are the
	// outcomes nothing may suppress and they must not depend on some other
	// layer having wrapped them correctly.
	if errors.Is(outcome, run.ErrRevertFailed) ||
		errors.Is(outcome, ErrNotRecovered) {
		return CodeRollback, string(outcomeRollback)
	}

	var exit *Exit
	if errors.As(outcome, &exit) {
		return exit.Code, string(exit.Outcome)
	}

	if errors.Is(outcome, context.Canceled) {
		return CodeInterrupted, string(OutcomeInterrupted)
	}

	return CodeUsage, ""
}

// ExitCode is the one authority on what a finished run returns to the shell.
// The process boundary reads it rather than carrying its own table, so the
// status and the record cannot disagree.
func ExitCode(outcome error) int {
	code, _ := exitDetail(outcome)

	return code
}

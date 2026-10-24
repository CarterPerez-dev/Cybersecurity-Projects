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

	if err := writeProjections(rec, emit.Projections); err != nil {
		writeErr = errors.Join(writeErr, err)
	}

	if writeErr != nil {
		outcome = publicationFailure(&rec, outcome, writeErr)
		writeErr = errors.Join(writeErr, correctArtifacts(rec, emit))
	}

	if emit.Shape == outputJSON {
		body, err := record.Encode(rec)
		if err == nil {
			var written int
			written, err = out.Write(body)
			if err == nil && written != len(body) {
				err = io.ErrShortWrite
			}
		}
		if err != nil {
			outcome = publicationFailure(&rec, outcome, err)
			writeErr = errors.Join(writeErr, err, correctArtifacts(rec, emit))
		}
	}

	if writeErr != nil {
		fmt.Fprintf(emit.diagnostic(), warnRecordWrite, writeErr)
	}
	return outcome
}

func publicationFailure(rec *record.Record, outcome, failure error) error {
	rec.ArtifactErrors = append(rec.ArtifactErrors, failure.Error())
	if outcome == nil {
		outcome = fmt.Errorf(errRecordWrite, ErrRecordUnwritten, failure)
	}
	rec.Exit.Code, rec.Exit.Outcome = exitDetail(outcome)
	return outcome
}

func correctArtifacts(rec record.Record, emit Output) error {
	var err error
	if emit.Record != "" {
		err = record.WriteRecord(emit.Record, rec)
	}
	return errors.Join(err, writeProjections(rec, emit.Projections))
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
// It is the SAME classification the process boundary uses, so the status and
// the artifact cannot disagree.
func exitDetail(outcome error) (int, string) {
	if outcome == nil {
		return CodeOK, ""
	}

	// Matched on the sentinels BEFORE any carried code: nothing may suppress
	// these, so they cannot depend on another layer having wrapped them.
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

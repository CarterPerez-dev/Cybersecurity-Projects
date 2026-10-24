// ©AngelaMos | 2026
// metrics.go

package record

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Prometheus text exposition, written to a FILE for node_exporter's textfile
// collector. No client library, no server, no port, no lifecycle.
//
//	the last line must end with \n, or the file is a parse failure and a
//	parse failure drops the WHOLE file;
//
//	only one HELP and one TYPE line may exist per metric name, TYPE must
//	precede the first sample for that name, and all lines for a metric must
//	be one contiguous group.
//
// Label values escape backslash, double quote and line feed. HELP text
// escapes backslash and line feed.
const (
	metricPrefix = "khaos_"

	helpInfo = "# HELP " + metricPrefix +
		"run_info the run this file describes, as labels on a constant 1\n"
	typeInfo = "# TYPE " + metricPrefix + "run_info gauge\n"

	helpExit = "# HELP " + metricPrefix +
		"run_exit_code the code khaos returned to the shell\n"
	typeExit = "# TYPE " + metricPrefix + "run_exit_code gauge\n"

	helpMetricDefect = "# HELP " + metricPrefix +
		"run_defect 1 when the control failed in the direction this experiment declares a defect\n"
	typeMetricDefect = "# TYPE " + metricPrefix + "run_defect gauge\n"

	helpConclusive = "# HELP " + metricPrefix +
		"run_conclusive 1 when khaos stands behind this verdict as conclusive\n"
	typeConclusive = "# TYPE " + metricPrefix + "run_conclusive gauge\n"

	helpConfirmed = "# HELP " + metricPrefix +
		"run_fault_confirmed 1 when khaos measured the fault actually taking effect\n"
	typeConfirmed = "# TYPE " + metricPrefix + "run_fault_confirmed gauge\n"

	helpDuration = "# HELP " + metricPrefix +
		"run_duration_seconds how long the run took\n"
	typeDuration = "# TYPE " + metricPrefix + "run_duration_seconds gauge\n"

	helpObservations = "# HELP " + metricPrefix +
		"observations the probe observations khaos recorded, by window, stream and disposition\n"
	typeObservations = "# TYPE " + metricPrefix + "observations gauge\n"
)

// Metrics projects the record onto the text exposition format. It takes the
// record, so it cannot report anything the record does not carry.
func Metrics(rec Record) []byte {
	out := &strings.Builder{}

	// run_info carries the identity as LABELS on a constant 1, which is the
	// conventional shape: putting a run id or a verdict word in a metric
	// NAME makes every run a new series.
	out.WriteString(helpInfo)
	out.WriteString(typeInfo)
	fmt.Fprintf(
		out,
		"%srun_info{experiment=%s,family=%s,run_id=%s,version=%s,epistemic=%s,direction=%s,cause=%s,outcome=%s} 1\n",
		metricPrefix,
		quote(rec.Experiment.Name),
		quote(rec.Experiment.Family),
		quote(rec.RunID),
		quote(rec.Khaos),
		quote(rec.Verdict.Epistemic),
		quote(rec.Verdict.Direction),
		quote(rec.Verdict.Cause),
		quote(rec.Exit.Outcome),
	)

	gauge(out, helpExit, typeExit, "run_exit_code", float64(rec.Exit.Code))
	gauge(
		out,
		helpMetricDefect,
		typeMetricDefect,
		"run_defect",
		flag(rec.Verdict.Defect),
	)
	gauge(
		out,
		helpConclusive,
		typeConclusive,
		"run_conclusive",
		flag(rec.Verdict.Conclusive),
	)
	gauge(
		out,
		helpConfirmed,
		typeConfirmed,
		"run_fault_confirmed",
		flag(rec.Fault.Confirmed),
	)
	gauge(
		out,
		helpDuration,
		typeDuration,
		"run_duration_seconds",
		float64(rec.DurationMS)/1000,
	)

	writeObservations(out, rec)

	return []byte(out.String())
}

// writeObservations emits one contiguous group for the one series that has
// labels varying per sample, because the format requires every line for a
// metric name to be grouped together and each name-plus-labels combination
// to be unique.
func writeObservations(out *strings.Builder, rec Record) {
	type sample struct {
		key   string
		value int
	}

	samples := []sample{}

	for window, w := range rec.Windows {
		for stream, s := range w.Streams {
			for disposition, count := range s.Distribution {
				samples = append(samples, sample{
					key: fmt.Sprintf(
						"{window=%s,stream=%s,disposition=%s}",
						quote(window),
						quote(stream),
						quote(disposition),
					),
					value: count,
				})
			}
		}
	}

	if len(samples) == 0 {
		return
	}

	// Sorted, because Go map iteration is random and a file whose line order
	// changes between runs is a file nobody can diff.
	sort.Slice(samples, func(i, j int) bool {
		return samples[i].key < samples[j].key
	})

	out.WriteString(helpObservations)
	out.WriteString(typeObservations)

	for _, each := range samples {
		fmt.Fprintf(
			out,
			"%sobservations%s %d\n",
			metricPrefix,
			each.key,
			each.value,
		)
	}
}

func gauge(out *strings.Builder, help, typed, name string, value float64) {
	out.WriteString(help)
	out.WriteString(typed)
	fmt.Fprintf(out, "%s%s %s\n", metricPrefix, name, number(value))
}

// number spells the non-finite values the way the format does, rather than
// Go's, because `+Inf` and `NaN` are what a parser accepts.
func number(value float64) string {
	switch {
	case value != value:
		return "NaN"
	case value > 1e308:
		return "+Inf"
	case value < -1e308:
		return "-Inf"
	default:
		return strconv.FormatFloat(value, 'f', -1, 64)
	}
}

func flag(set bool) float64 {
	if set {
		return 1
	}
	return 0
}

// quote escapes exactly what the format says a label value escapes: the
// backslash first, or escaping the quote would then double its own slash.
func quote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)

	return `"` + value + `"`
}

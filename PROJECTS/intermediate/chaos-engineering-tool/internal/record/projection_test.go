// ©AngelaMos | 2026
// projection_test.go

package record

import (
	"encoding/xml"
	"strings"
	"testing"
)

// shaped builds a record in one outcome, so each test states the one thing
// it varies rather than rebuilding the world.
func shaped(
	epistemic, direction string,
	defect, conclusive bool,
) Record {
	return Record{
		Schema:     Version,
		Khaos:      "1.2.3",
		RunID:      "01KRUN0000000000000000000",
		Started:    "2026-10-21T09:00:00Z",
		Ended:      "2026-10-21T09:00:30Z",
		DurationMS: 30_000,
		Experiment: Experiment{
			Name:   "control.policy_store_down",
			Family: "control",
		},
		Fault: Fault{
			Kind:      "proxy-reset",
			Target:    "khaos-range-gateway-control",
			Confirmed: true,
			Method:    "a measured observable",
		},
		Windows: map[string]Window{
			"fault": {
				Paired:   30,
				Requests: 60,
				Streams: map[string]Stream{
					"invalid": {
						Countable:    30,
						Answered:     30,
						Distribution: map[string]int{"accepted": 30},
					},
				},
			},
		},
		Verdict: Verdict{
			Epistemic:  epistemic,
			Direction:  direction,
			Cause:      "UNDIAGNOSED",
			Recovery:   "recovered",
			Conclusive: conclusive,
			Defect:     defect,
			Reasons:    []string{"a reason"},
		},
		Exit: Exit{Code: 2, Outcome: "defect"},
	}
}

func parseSuites(t *testing.T, body []byte) testsuites {
	t.Helper()

	var root testsuites
	if err := xml.Unmarshal(body, &root); err != nil {
		t.Fatalf("the XML khaos wrote does not parse: %v", err)
	}

	return root
}

// The declared flavor: <testsuites> root even for one suite, because the
// bare <testsuite> root is the Maven-only shape and fewer parsers take it.
func TestTheJUnitRootIsTestsuitesEvenForOneSuite(t *testing.T) {
	body, err := JUnit(shaped("deviated", "PERMITTED", true, true))
	if err != nil {
		t.Fatalf("junit: %v", err)
	}

	if !strings.Contains(string(body), "<?xml") {
		t.Error("the file carries no XML declaration")
	}

	if !strings.Contains(string(body), "<testsuites") {
		t.Fatalf("the root is not <testsuites>: %.120q", body)
	}

	root := parseSuites(t, body)
	if len(root.Suites) != 1 {
		t.Fatalf("got %d suites, want 1", len(root.Suites))
	}
}

// The whole semantic of the format: an outcome is WHICH CHILD is present,
// and a pass has none.
func TestTheOutcomeIsWhichChildElementIsPresent(t *testing.T) {
	for _, row := range []struct {
		name       string
		epistemic  string
		direction  string
		defect     bool
		conclusive bool
		failure    bool
		skip       bool
	}{
		{
			"a defect fails the build",
			"deviated", "PERMITTED", true, true,
			true, false,
		},
		{
			"a clean hold passes with no child",
			"passed", "HELD", false, true,
			false, false,
		},
		{
			"a non-defect deviation passes with no child",
			"deviated", "DENIED", false, true,
			false, false,
		},
		{
			"thin evidence is skipped, never failed",
			"passed", "HELD", false, false,
			false, true,
		},
		{
			"a void run is skipped, never failed",
			"aborted", "UNDETERMINED", false, false,
			false, true,
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			body, err := JUnit(shaped(
				row.epistemic,
				row.direction,
				row.defect,
				row.conclusive,
			))
			if err != nil {
				t.Fatalf("junit: %v", err)
			}

			verdict := parseSuites(t, body).Suites[0].Cases[0]

			if (verdict.Failure != nil) != row.failure {
				t.Errorf(
					"failure present = %v, want %v",
					verdict.Failure != nil,
					row.failure,
				)
			}

			if (verdict.Skipped != nil) != row.skip {
				t.Errorf(
					"skipped present = %v, want %v",
					verdict.Skipped != nil,
					row.skip,
				)
			}

			// A pass is the ABSENCE of all three, which is the one thing a
			// reporter reads.
			if !row.failure && !row.skip {
				if verdict.Failure != nil ||
					verdict.Skipped != nil ||
					verdict.Error != nil {
					t.Error("a passing testcase carries a child element")
				}
			}
		})
	}
}

// Thin evidence must never be a <failure>: that is the specific mechanism
// that stops a run khaos declined to conclude from breaking a build.
func TestThinEvidenceIsSkippedRatherThanFailed(t *testing.T) {
	body, err := JUnit(shaped("passed", "HELD", false, false))
	if err != nil {
		t.Fatalf("junit: %v", err)
	}

	root := parseSuites(t, body)

	if root.Failures != 0 || root.Errors != 0 {
		t.Fatalf(
			"thin evidence reports failures=%d errors=%d",
			root.Failures, root.Errors,
		)
	}

	if root.Skipped != 1 {
		t.Fatalf("a thin-evidence run reports %d skips, want 1", root.Skipped)
	}
}

func TestDegradedRecoveryIsAValidityErrorEvenAfterAHold(t *testing.T) {
	rec := shaped("deviated", "HELD", false, true)
	rec.Verdict.Recovery = "degraded"
	body, err := JUnit(rec)
	if err != nil {
		t.Fatal(err)
	}
	root := parseSuites(t, body)
	if root.Errors != 1 || root.Failures != 0 {
		t.Fatalf(
			"degraded recovery: errors=%d failures=%d",
			root.Errors,
			root.Failures,
		)
	}
}

// A rollback failure is an <error>: visible as a problem without being
// reported as a security regression, which it is not.
func TestARollbackFailureIsAnErrorRatherThanAFailure(t *testing.T) {
	rec := shaped("passed", "HELD", false, true)
	rec.Fault.RollbackFailed = true

	body, err := JUnit(rec)
	if err != nil {
		t.Fatalf("junit: %v", err)
	}

	root := parseSuites(t, body)

	if root.Errors != 1 {
		t.Fatalf("got %d errors, want 1", root.Errors)
	}

	if root.Failures != 0 {
		t.Fatalf("a rollback failure was reported as a security regression")
	}
}

// The counts on the suite are derived from the cases. A hand-maintained
// count that disagrees with the body is the defect this format invites, and
// a reporter trusts the attribute over the elements.
func TestTheSuiteCountsMatchTheCasesItCarries(t *testing.T) {
	for _, rec := range []Record{
		shaped("deviated", "PERMITTED", true, true),
		shaped("passed", "HELD", false, true),
		shaped("aborted", "UNDETERMINED", false, false),
	} {
		body, err := JUnit(rec)
		if err != nil {
			t.Fatalf("junit: %v", err)
		}

		root := parseSuites(t, body)
		suite := root.Suites[0]

		failures, errs, skips := 0, 0, 0
		for _, each := range suite.Cases {
			switch {
			case each.Failure != nil:
				failures++
			case each.Error != nil:
				errs++
			case each.Skipped != nil:
				skips++
			}
		}

		if suite.Tests != len(suite.Cases) {
			t.Errorf(
				"suite says %d tests and carries %d cases",
				suite.Tests,
				len(suite.Cases),
			)
		}

		if suite.Failures != failures ||
			suite.Errors != errs ||
			suite.Skipped != skips {
			t.Errorf(
				"suite says %d/%d/%d failures/errors/skips and carries %d/%d/%d",
				suite.Failures,
				suite.Errors,
				suite.Skipped,
				failures,
				errs,
				skips,
			)
		}
	}
}

// A JUnit-only consumer has to be able to get back to the record.
func TestThePropertiesCarryTheWayBackToTheRecord(t *testing.T) {
	body, err := JUnit(shaped("deviated", "PERMITTED", true, true))
	if err != nil {
		t.Fatalf("junit: %v", err)
	}

	props := map[string]string{}
	for _, each := range parseSuites(t, body).Suites[0].Props.Props {
		props[each.Name] = each.Value
	}

	for _, name := range []string{
		propRunID,
		propVersion,
		propFault,
		propTarget,
		propExit,
	} {
		if props[name] == "" {
			t.Errorf("the suite carries no %s property", name)
		}
	}
}

// XML has to survive content that would otherwise break it, and a verdict
// reason is free text khaos did not write.
func TestTheXMLSurvivesHostileReasonText(t *testing.T) {
	rec := shaped("deviated", "PERMITTED", true, true)
	rec.Verdict.Reasons = []string{
		`a reason with <angle> & "quotes" and ]]> in it`,
	}

	body, err := JUnit(rec)
	if err != nil {
		t.Fatalf("junit: %v", err)
	}

	root := parseSuites(t, body)

	if !strings.Contains(
		root.Suites[0].Cases[0].Failure.Body,
		"<angle>",
	) {
		t.Fatalf(
			"the reason did not survive a round trip: %q",
			root.Suites[0].Cases[0].Failure.Body,
		)
	}
}

// The exposition format's normative requirement: the last line must end with
// a line feed, and without it the WHOLE file is a parse failure.
func TestTheMetricsFileEndsWithALineFeed(t *testing.T) {
	body := Metrics(shaped("deviated", "PERMITTED", true, true))

	if len(body) == 0 {
		t.Fatal("the metrics file is empty")
	}

	if body[len(body)-1] != '\n' {
		t.Fatalf("the metrics file does not end with a line feed: %q",
			string(body[max(0, len(body)-20):]))
	}

	// EVERY line, not just the last byte. Checking only the tail cannot see
	// an unterminated interior line: dropping the newline from the gauge
	// helper left the file still ending in one, because the observation
	// group is written afterwards and terminates itself.
	text := string(body)
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if line == "" {
			t.Fatal("the metrics file carries an empty line")
		}

		fields := strings.Fields(line)

		if strings.HasPrefix(line, "#") {
			continue
		}

		// A sample is exactly `name[{labels}] value`. A line carrying two
		// samples is what a dropped newline actually produces, and it
		// parses as a value with trailing junk rather than as an error.
		if len(fields) != 2 {
			t.Fatalf(
				"a sample line does not have exactly a name and a value, so a newline was dropped: %q",
				line,
			)
		}
	}
}

// Only one HELP and one TYPE per metric name, and TYPE before the first
// sample for that name.
func TestEveryMetricIsDeclaredOnceAndBeforeItsFirstSample(t *testing.T) {
	body := string(Metrics(shaped("deviated", "PERMITTED", true, true)))

	helps := map[string]int{}
	types := map[string]int{}
	declared := map[string]bool{}

	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		fields := strings.Fields(line)

		switch {
		case strings.HasPrefix(line, "# HELP"):
			helps[fields[2]]++
		case strings.HasPrefix(line, "# TYPE"):
			types[fields[2]]++
			declared[fields[2]] = true
		case strings.HasPrefix(line, "#"):
		default:
			name := strings.SplitN(fields[0], "{", 2)[0]
			if !declared[name] {
				t.Errorf("%s is sampled before its TYPE line", name)
			}
		}
	}

	for name, count := range helps {
		if count != 1 {
			t.Errorf("%s has %d HELP lines, want 1", name, count)
		}
	}

	for name, count := range types {
		if count != 1 {
			t.Errorf("%s has %d TYPE lines, want 1", name, count)
		}
	}
}

// Each name-plus-labels combination must be unique, or the format says the
// ingestion behaviour is undefined.
func TestEverySampleLineIsUnique(t *testing.T) {
	body := string(Metrics(shaped("deviated", "PERMITTED", true, true)))

	seen := map[string]bool{}

	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		key := strings.Fields(line)[0]
		if seen[key] {
			t.Errorf("%s is sampled twice", key)
		}

		seen[key] = true
	}
}

// All lines for one metric name have to be one contiguous group.
func TestSamplesForOneMetricAreContiguous(t *testing.T) {
	body := string(Metrics(shaped("deviated", "PERMITTED", true, true)))

	order := []string{}
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		name := strings.SplitN(strings.Fields(line)[0], "{", 2)[0]
		if len(order) == 0 || order[len(order)-1] != name {
			order = append(order, name)
		}
	}

	seen := map[string]bool{}
	for _, name := range order {
		if seen[name] {
			t.Errorf("%s appears in two separate groups", name)
		}
		seen[name] = true
	}
}

// A label value khaos did not write has to be escaped, or one quote in a
// reason makes the file unparseable.
func TestLabelValuesAreEscaped(t *testing.T) {
	rec := shaped("deviated", "PERMITTED", true, true)
	rec.Experiment.Name = `a"name\with` + "\n" + "breaks"

	body := string(Metrics(rec))

	if strings.Contains(body, `a"name`) {
		t.Fatal("an unescaped double quote reached a label value")
	}

	if !strings.Contains(body, `a\"name\\with\nbreaks`) {
		t.Fatalf(
			"the label was not escaped as the format requires: %.200q",
			body,
		)
	}

	// And the file still has one line per sample: an unescaped newline would
	// have split one into two.
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if line == "" {
			t.Fatal("an unescaped line feed split a sample line")
		}
	}
}

// The sample order is stable, because Go map iteration is random and a file
// whose line order changes between identical runs is a file nobody can diff.
func TestTheMetricsFileIsByteStableAcrossRuns(t *testing.T) {
	rec := shaped("deviated", "PERMITTED", true, true)

	first := string(Metrics(rec))

	for range 8 {
		if got := string(Metrics(rec)); got != first {
			t.Fatal("two renders of one record produced different bytes")
		}
	}
}

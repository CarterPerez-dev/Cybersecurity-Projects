// ©AngelaMos | 2026
// junit.go

package record

import (
	"encoding/xml"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// khaos's declared JUnit flavor. There is no normative specification for this
// format -- it is what Apache Ant emitted in 2002, extended by Maven Surefire
// and copied by every runner since -- so the flavor is written down rather
// than inferred from whatever a parser happened to accept.
//
//	root            <testsuites>, even for one suite. The bare <testsuite>
//	                root is the Maven-only shape; more parsers accept this one.
//	pass            a <testcase> with NO child element. That is the whole
//	                semantic: the outcome is which child is present.
//	failure         a security regression, which fails the build.
//	skipped         a run khaos declined to conclude from. This is the
//	                mechanism that stops thin evidence failing a build.
//	error           something wrong with the RUN rather than with the target,
//	                visible as a problem without being a security finding.
const (
	suiteName = "khaos"

	// Two testcases at most. The first is always the security question; the
	// second appears only when the run itself had a problem, which is what
	// gives a reporter the flake-versus-regression split.
	caseVerdict  = "verdict"
	caseValidity = "experiment validity"

	propRunID   = "run_id"
	propVersion = "khaos_version"
	propFault   = "fault"
	propTarget  = "target"
	propExit    = "exit_code"

	typeDefect   = "security-regression"
	typeRollback = "rollback-failed"
	typeVoid     = "experiment-void"

	messageDefect = "this control failed in the direction %s declares a defect"

	messageRollback = "khaos could not revert the fault; the target may still be degraded"

	messageVoid = "%s: nothing measured during this run can be attributed to the fault"

	messageSkipped = "%s: khaos declined to draw a conclusion from this run"

	// The availability finding rides in system-out rather than in a failure:
	// a control that refused to serve while its dependency was gone did its
	// job, and failing a build on correct behaviour trains people to stop
	// reading the results.
	noteDeviated = "this control held, and refusing to serve carried an availability cost khaos did not measure"
)

type testsuites struct {
	XMLName  xml.Name    `xml:"testsuites"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Time     string      `xml:"time,attr"`
	Suites   []testsuite `xml:"testsuite"`
}

type testsuite struct {
	Name      string     `xml:"name,attr"`
	Tests     int        `xml:"tests,attr"`
	Failures  int        `xml:"failures,attr"`
	Errors    int        `xml:"errors,attr"`
	Skipped   int        `xml:"skipped,attr"`
	Time      string     `xml:"time,attr"`
	Timestamp string     `xml:"timestamp,attr"`
	Props     properties `xml:"properties"`
	Cases     []testcase `xml:"testcase"`
}

type properties struct {
	Props []property `xml:"property"`
}

type property struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type testcase struct {
	Name      string   `xml:"name,attr"`
	Classname string   `xml:"classname,attr"`
	Time      string   `xml:"time,attr"`
	Failure   *detail  `xml:"failure,omitempty"`
	Error     *detail  `xml:"error,omitempty"`
	Skipped   *skipped `xml:"skipped,omitempty"`
	SystemOut string   `xml:"system-out,omitempty"`
}

type detail struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type skipped struct {
	Message string `xml:"message,attr"`
}

// JUnit projects the record onto khaos's declared flavor. It takes the record
// rather than the run, so it cannot see anything the record does not carry.
func JUnit(rec Record) ([]byte, error) {
	cases := []testcase{verdictCase(rec)}

	if validity, ok := validityCase(rec); ok {
		cases = append(cases, validity)
	}

	suite := testsuite{
		Name:      rec.Experiment.Name,
		Tests:     len(cases),
		Time:      seconds(rec.DurationMS),
		Timestamp: rec.Started,
		Props:     propertiesOf(rec),
		Cases:     cases,
	}

	// The counts are DERIVED from the cases rather than tracked alongside
	// them. A hand-maintained count that disagrees with the body is the
	// defect this format invites, and a reporter trusts the attribute.
	for _, each := range cases {
		switch {
		case each.Failure != nil:
			suite.Failures++
		case each.Error != nil:
			suite.Errors++
		case each.Skipped != nil:
			suite.Skipped++
		}
	}

	root := testsuites{
		Name:     suiteName,
		Tests:    suite.Tests,
		Failures: suite.Failures,
		Errors:   suite.Errors,
		Skipped:  suite.Skipped,
		Time:     suite.Time,
		Suites:   []testsuite{suite},
	}

	body, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}

	return append(
		[]byte(xml.Header),
		append(body, '\n')...,
	), nil
}

// verdictCase is the security question. A pass carries no child element,
// which is the whole semantic of the format.
func verdictCase(rec Record) testcase {
	out := testcase{
		Name:      caseVerdict,
		Classname: rec.Experiment.Name,
		Time:      seconds(rec.DurationMS),
	}

	reasons := strings.Join(rec.Verdict.Reasons, "\n")

	switch {
	case rec.Verdict.Defect:
		out.Failure = &detail{
			Message: fmt.Sprintf(messageDefect, rec.Experiment.Name),
			Type:    typeDefect,
			Body:    reasons,
		}

	case concluded(rec):
		// A deviation the polarity does not call a defect, and a clean hold,
		// both pass. The availability note distinguishes them for a reader
		// without failing anybody's build.
		if rec.Verdict.Direction != "HELD" {
			out.SystemOut = noteDeviated + "\n" + reasons
		} else {
			out.SystemOut = reasons
		}

	default:
		out.Skipped = &skipped{
			Message: fmt.Sprintf(messageSkipped, rec.Verdict.Epistemic),
		}
		out.SystemOut = reasons
	}

	return out
}

// validityCase appears only when something was wrong with the RUN rather
// than with the target. Without it a void run is a bare skip, and a skip
// reads as "nobody got to this" rather than "this could not be concluded".
func validityCase(rec Record) (testcase, bool) {
	out := testcase{
		Name:      caseValidity,
		Classname: rec.Experiment.Name,
		Time:      "0",
	}

	switch {
	case rec.Fault.RollbackFailed:
		out.Error = &detail{
			Message: messageRollback,
			Type:    typeRollback,
			Body:    strings.Join(rec.Verdict.Reasons, "\n"),
		}

	case rec.Verdict.Recovery == "degraded":
		out.Error = &detail{
			Message: "the target did not recover after rollback",
			Type:    "recovery-degraded",
			Body:    strings.Join(rec.Verdict.Reasons, "\n"),
		}

	case runInvalid(rec):
		out.Error = &detail{
			Message: fmt.Sprintf(messageVoid, rec.Verdict.Epistemic),
			Type:    typeVoid,
			Body:    strings.Join(rec.Verdict.Reasons, "\n"),
		}

	default:
		return testcase{}, false
	}

	return out, true
}

func runInvalid(rec Record) bool {
	switch rec.Verdict.Epistemic {
	case "aborted", "interrupted", "baseline-not-met", "error":
		return true
	case "probe-error":
		return !slices.Contains(rec.Verdict.Warnings, "thin-evidence")
	default:
		return false
	}
}

// concluded reads the record rather than the exit code, because the exit code
// can be narrowed by --fail-on and the XML must describe the run.
func concluded(rec Record) bool {
	if !rec.Verdict.Conclusive {
		return false
	}

	return rec.Verdict.Epistemic == "passed" ||
		rec.Verdict.Epistemic == "deviated"
}

func propertiesOf(rec Record) properties {
	return properties{Props: []property{
		{Name: propRunID, Value: rec.RunID},
		{Name: propVersion, Value: rec.Khaos},
		{Name: propFault, Value: rec.Fault.Kind},
		{Name: propTarget, Value: rec.Fault.Target},
		{Name: propExit, Value: strconv.Itoa(rec.Exit.Code)},
	}}
}

func seconds(ms int64) string {
	return strconv.FormatFloat(float64(ms)/1000, 'f', 3, 64)
}

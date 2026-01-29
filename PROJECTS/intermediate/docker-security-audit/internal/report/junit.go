/*
AngelaMos | 2026
junit.go
*/

package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"time"

	"github.com/CarterPerez-dev/docksec/internal/finding"
)

type JUnitReporter struct {
	w      io.Writer
	closer func() error
}

type junitTestSuites struct {
	XMLName   xml.Name         `xml:"testsuites"`
	Name      string           `xml:"name,attr"`
	Tests     int              `xml:"tests,attr"`
	Failures  int              `xml:"failures,attr"`
	Errors    int              `xml:"errors,attr"`
	Time      float64          `xml:"time,attr"`
	Timestamp string           `xml:"timestamp,attr"`
	Suites    []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Time      float64         `xml:"time,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

func (r *JUnitReporter) Report(findings finding.Collection) error {
	defer func() {
		if r.closer != nil {
			_ = r.closer()
		}
	}()

	report := r.buildReport(findings)

	_, _ = fmt.Fprintln(r.w, xml.Header)
	enc := xml.NewEncoder(r.w)
	enc.Indent("", "  ")

	return enc.Encode(report)
}

func (r *JUnitReporter) buildReport(
	findings finding.Collection,
) junitTestSuites {
	grouped := r.groupByCategory(findings)
	timestamp := time.Now().UTC().Format(time.RFC3339)

	var suites []junitTestSuite
	totalTests := 0
	totalFailures := 0

	for category, catFindings := range grouped {
		suite := r.buildSuite(category, catFindings, timestamp)
		suites = append(suites, suite)
		totalTests += suite.Tests
		totalFailures += suite.Failures
	}

	if len(suites) == 0 {
		suites = append(suites, junitTestSuite{
			Name:      "Security Checks",
			Tests:     1,
			Failures:  0,
			Errors:    0,
			Skipped:   0,
			Time:      0.001,
			Timestamp: timestamp,
			TestCases: []junitTestCase{
				{
					Name:      "All security checks passed",
					ClassName: "docksec.security",
					Time:      0.001,
				},
			},
		})
		totalTests = 1
	}

	return junitTestSuites{
		Name:      "docksec Security Scan",
		Tests:     totalTests,
		Failures:  totalFailures,
		Errors:    0,
		Time:      0.001,
		Timestamp: timestamp,
		Suites:    suites,
	}
}

func (r *JUnitReporter) buildSuite(
	category string,
	findings finding.Collection,
	timestamp string,
) junitTestSuite {
	var testCases []junitTestCase
	failures := 0

	for _, f := range findings {
		tc := r.buildTestCase(f)
		testCases = append(testCases, tc)
		if tc.Failure != nil {
			failures++
		}
	}

	return junitTestSuite{
		Name:      category,
		Tests:     len(testCases),
		Failures:  failures,
		Errors:    0,
		Skipped:   0,
		Time:      0.001,
		Timestamp: timestamp,
		TestCases: testCases,
	}
}

func (r *JUnitReporter) buildTestCase(f *finding.Finding) junitTestCase {
	className := fmt.Sprintf("docksec.%s.%s", f.Target.Type, f.RuleID)
	name := fmt.Sprintf("%s: %s", f.Target.Name, f.Title)

	tc := junitTestCase{
		Name:      name,
		ClassName: className,
		Time:      0.001,
	}

	if f.Severity >= finding.SeverityLow {
		content := r.buildFailureContent(f)
		tc.Failure = &junitFailure{
			Message: f.Title,
			Type:    f.Severity.String(),
			Content: content,
		}
	}

	return tc
}

func (r *JUnitReporter) buildFailureContent(f *finding.Finding) string {
	content := fmt.Sprintf("Severity: %s\n", f.Severity.String())
	content += fmt.Sprintf("Target: %s\n", f.Target.String())

	if f.Location != nil {
		content += fmt.Sprintf("Location: %s\n", f.Location.String())
	}

	if f.Description != "" {
		content += fmt.Sprintf("\nDescription:\n%s\n", f.Description)
	}

	if f.Remediation != "" {
		content += fmt.Sprintf("\nRemediation:\n%s\n", f.Remediation)
	}

	if f.CISControl != nil {
		content += fmt.Sprintf(
			"\nCIS Control: %s - %s\n",
			f.CISControl.ID,
			f.CISControl.Title,
		)
	}

	return content
}

func (r *JUnitReporter) groupByCategory(
	findings finding.Collection,
) map[string]finding.Collection {
	grouped := make(map[string]finding.Collection)
	for _, f := range findings {
		cat := f.Category
		if cat == "" {
			cat = "General"
		}
		grouped[cat] = append(grouped[cat], f)
	}
	return grouped
}

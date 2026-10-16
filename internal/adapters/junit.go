// Package adapters converts tool output formats that aren't SARIF into the
// normalised model: JUnit XML into test results, and lcov into coverage
// metrics (plan §5/§8). SARIF itself is handled in internal/findings.
package adapters

import (
	"encoding/xml"
	"fmt"
	"io"
	"time"

	"github.com/gatehouse/gatehouse/internal/model"
)

// JUnit XML is the common test-result format almost every framework can emit.
// We parse both the <testsuites> root and a bare <testsuite> root.
type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	XMLName xml.Name    `xml:"testsuite"`
	Name    string      `xml:"name,attr"`
	Cases   []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *junitProblem `xml:"failure"`
	Error     *junitProblem `xml:"error"`
	Skipped   *struct{}     `xml:"skipped"`
}

type junitProblem struct {
	Message string `xml:"message,attr"`
}

// ParseJUnit reads JUnit XML and returns normalised test results. It accepts
// either a <testsuites> or a single <testsuite> document.
func ParseJUnit(r io.Reader) ([]model.TestResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var root junitSuites
	var suites []junitSuite
	if err := xml.Unmarshal(data, &root); err == nil {
		suites = root.Suites
	}
	// Fall back to a bare <testsuite> root (some frameworks emit a single suite
	// with no <testsuites> wrapper, which fails to unmarshal into junitSuites).
	if len(suites) == 0 {
		var one junitSuite
		if err := xml.Unmarshal(data, &one); err != nil {
			return nil, fmt.Errorf("parse junit: %w", err)
		}
		if len(one.Cases) > 0 {
			suites = []junitSuite{one}
		}
	}

	var out []model.TestResult
	for _, s := range suites {
		suiteName := s.Name
		for _, c := range s.Cases {
			tr := model.TestResult{
				Suite:    firstNonEmpty(suiteName, c.Classname),
				Name:     c.Name,
				Duration: time.Duration(c.Time * float64(time.Second)),
				Status:   "passed",
			}
			switch {
			case c.Failure != nil || c.Error != nil:
				tr.Status = "failed"
			case c.Skipped != nil:
				tr.Status = "skipped"
			}
			out = append(out, tr)
		}
	}
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

package adapters

import (
	"strings"
	"testing"
)

const junitXML = `<?xml version="1.0"?>
<testsuites>
  <testsuite name="pkg/auth">
    <testcase name="TestLogin" classname="auth" time="0.012"/>
    <testcase name="TestLogout" classname="auth" time="0.004">
      <failure message="boom"/>
    </testcase>
    <testcase name="TestSkipped" classname="auth" time="0">
      <skipped/>
    </testcase>
  </testsuite>
</testsuites>`

func TestParseJUnit(t *testing.T) {
	ts, err := ParseJUnit(strings.NewReader(junitXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 3 {
		t.Fatalf("want 3 tests, got %d", len(ts))
	}
	byName := map[string]string{}
	for _, tr := range ts {
		byName[tr.Name] = tr.Status
	}
	if byName["TestLogin"] != "passed" {
		t.Errorf("TestLogin: want passed, got %s", byName["TestLogin"])
	}
	if byName["TestLogout"] != "failed" {
		t.Errorf("TestLogout: want failed, got %s", byName["TestLogout"])
	}
	if byName["TestSkipped"] != "skipped" {
		t.Errorf("TestSkipped: want skipped, got %s", byName["TestSkipped"])
	}
}

func TestParseJUnitBareSuite(t *testing.T) {
	bare := `<testsuite name="s"><testcase name="t" time="1"/></testsuite>`
	ts, err := ParseJUnit(strings.NewReader(bare))
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 || ts[0].Status != "passed" {
		t.Fatalf("bare testsuite not parsed: %+v", ts)
	}
}

const lcov = `SF:/src/pkg/a.go
DA:1,1
DA:2,0
DA:3,5
end_of_record
SF:/src/pkg/b.go
DA:1,0
DA:2,0
end_of_record
`

func TestParseLCOVOverall(t *testing.T) {
	cov, err := ParseLCOV(strings.NewReader(lcov))
	if err != nil {
		t.Fatal(err)
	}
	// 5 instrumented lines, 2 hit → 40%.
	if got := cov.Overall(); got < 39.9 || got > 40.1 {
		t.Fatalf("overall coverage: want 40, got %v", got)
	}
}

func TestParseLCOVChangedLines(t *testing.T) {
	cov, _ := ParseLCOV(strings.NewReader(lcov))
	// Only a.go changed: 3 lines, 2 hit → 66.6%.
	v, ok := cov.ChangedLines([]string{"pkg/a.go"})
	if !ok {
		t.Fatal("expected changed-lines coverage for pkg/a.go")
	}
	if v < 66 || v > 67 {
		t.Fatalf("changed-lines coverage: want ~66.7, got %v", v)
	}
}

func TestChangedLinesNoMatch(t *testing.T) {
	cov, _ := ParseLCOV(strings.NewReader(lcov))
	if _, ok := cov.ChangedLines([]string{"pkg/unrelated.go"}); ok {
		t.Fatal("expected no changed-lines coverage when no changed file is instrumented")
	}
}

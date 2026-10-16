package report_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gatehouse/gatehouse/internal/findings"
	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/report"
)

func sampleRun() model.Run {
	return model.Run{
		ID: "R1", RepoPath: "/repo", Ref: "working-tree", Verdict: model.VerdictFail,
		TreeHash: "abc",
		Findings: []model.Finding{
			{Fingerprint: "f1", Family: model.FamilyVuln, RuleID: "CVE-2024-1", Tool: "osv",
				Severity: model.SevCritical, CVSS: 9.8, CWEIDs: []string{"CWE-89"},
				Path: "go.mod", StartLine: 1, Message: "vulnerable dep", Status: model.StatusNew},
		},
	}
}

func TestSARIFParsesBackThroughIngest(t *testing.T) {
	var buf bytes.Buffer
	if err := report.SARIF(&buf, sampleRun()); err != nil {
		t.Fatal(err)
	}
	// Our own SARIF ingest must accept our SARIF egress.
	fs, err := findings.ParseSARIF(&buf, findings.SARIFOptions{})
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}
	if len(fs) != 1 || fs[0].RuleID != "CVE-2024-1" {
		t.Fatalf("round-trip lost the finding: %+v", fs)
	}
	if fs[0].Severity != model.SevHigh && fs[0].Severity != model.SevCritical {
		t.Errorf("severity should survive as error-level: %s", fs[0].Severity)
	}
}

func TestSARIFEmptyRunIsValid(t *testing.T) {
	var buf bytes.Buffer
	if err := report.SARIF(&buf, model.Run{ID: "x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"version": "2.1.0"`) {
		t.Error("missing SARIF version")
	}
	if !strings.Contains(buf.String(), `"results": []`) {
		t.Error("empty run should emit an empty results array")
	}
}

func TestHTMLContainsFindingAndVerdict(t *testing.T) {
	var buf bytes.Buffer
	if err := report.HTML(&buf, sampleRun(), []string{"blocked by CVE"}, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"CVE-2024-1", "verdict fail", "blocked by CVE", "go.mod"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

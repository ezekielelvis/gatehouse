package findings

import (
	"strings"
	"testing"

	"github.com/gatehouse/gatehouse/internal/model"
)

func TestFingerprintStableAcrossLineMoves(t *testing.T) {
	a := model.Finding{RuleID: "G101", Path: "/src/pkg/a.go", StartLine: 10, Snippet: "\t\tx := doThing(a, b)"}
	b := model.Finding{RuleID: "G101", Path: "pkg/a.go", StartLine: 42, Snippet: "    x := doThing(a, b)"} // moved + reindented
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatalf("fingerprint should be stable across line moves and whitespace: %s != %s", Fingerprint(a), Fingerprint(b))
	}
}

func TestFingerprintDistinguishesRule(t *testing.T) {
	a := model.Finding{RuleID: "G101", Path: "a.go", Snippet: "secret"}
	b := model.Finding{RuleID: "G102", Path: "a.go", Snippet: "secret"}
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("different rules must fingerprint differently")
	}
}

func TestFingerprintSnippetlessUsesMessage(t *testing.T) {
	a := model.Finding{RuleID: "CVE-2024-1", Path: "go.mod", Message: "pkg foo@1.0 vulnerable"}
	b := model.Finding{RuleID: "CVE-2024-1", Path: "go.mod", Message: "pkg bar@2.0 vulnerable"}
	if Fingerprint(a) == Fingerprint(b) {
		t.Fatal("snippetless findings on same manifest must be distinguished by message")
	}
}

const gitleaksSARIF = `{
  "runs": [{
    "tool": {"driver": {"name": "gitleaks", "rules": [
      {"id": "aws-access-key", "properties": {"tags": ["CWE-798"]}, "defaultConfiguration": {"level": "error"}}
    ]}},
    "results": [{
      "ruleId": "aws-access-key",
      "message": {"text": "AWS Access Key detected"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "/src/config/prod.env"},
        "region": {"startLine": 3, "snippet": {"text": "AWS_KEY=AKIA..."}}
      }}]
    }]
  }]
}`

func TestParseSARIF(t *testing.T) {
	fs, err := ParseSARIF(strings.NewReader(gitleaksSARIF), SARIFOptions{Family: model.FamilySecret})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Family != model.FamilySecret {
		t.Errorf("family: want secret, got %s", f.Family)
	}
	if f.Tool != "gitleaks" {
		t.Errorf("tool: want gitleaks, got %s", f.Tool)
	}
	if f.Severity != model.SevHigh {
		t.Errorf("severity: want high (error level), got %s", f.Severity)
	}
	if f.StartLine != 3 || f.EndLine != 3 {
		t.Errorf("lines: want 3/3, got %d/%d", f.StartLine, f.EndLine)
	}
	if len(f.CWEIDs) != 1 || f.CWEIDs[0] != "CWE-798" {
		t.Errorf("cwe: want [CWE-798], got %v", f.CWEIDs)
	}
	if f.Fingerprint == "" {
		t.Error("fingerprint not assigned")
	}
}

func TestDiff(t *testing.T) {
	base := []model.Finding{
		{RuleID: "A", Path: "a.go", Snippet: "one"},
		{RuleID: "B", Path: "b.go", Snippet: "two"},
	}
	Assign(base)
	cur := []model.Finding{
		{RuleID: "A", Path: "a.go", Snippet: "one"},   // existing
		{RuleID: "C", Path: "c.go", Snippet: "three"}, // new
	}
	Assign(cur)

	classified, fixed := Diff(cur, base)
	byRule := map[string]model.Status{}
	for _, f := range classified {
		byRule[f.RuleID] = f.Status
	}
	if byRule["A"] != model.StatusExisting {
		t.Errorf("A should be existing, got %s", byRule["A"])
	}
	if byRule["C"] != model.StatusNew {
		t.Errorf("C should be new, got %s", byRule["C"])
	}
	if len(fixed) != 1 || fixed[0].RuleID != "B" {
		t.Errorf("B should be fixed, got %v", fixed)
	}
}

package policy_test

import (
	"context"
	"testing"

	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/policy"
)

func compileAndEval(t *testing.T, doc string, run model.Run) policy.Decision {
	t.Helper()
	mod, err := policy.CompileDSL("rules.rego", []byte(doc))
	if err != nil {
		t.Fatalf("compile: %v\n--- generated ---\n%s", err, mod.Source)
	}
	eng, err := policy.New(context.Background(), mod)
	if err != nil {
		t.Fatalf("engine: %v\n--- generated ---\n%s", err, mod.Source)
	}
	d, err := eng.Evaluate(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDSLMatchRuleDenies(t *testing.T) {
	doc := `
rules:
  - id: no-new-high-vulns
    action: deny
    match: { type: vulnerability, status: new, min_severity: high }
    message: "new high vuln"
`
	run := model.Run{Findings: []model.Finding{
		{Family: model.FamilyVuln, Status: model.StatusNew, Severity: model.SevCritical},
	}}
	if d := compileAndEval(t, doc, run); d.Verdict != model.VerdictFail {
		t.Fatalf("expected fail, got %s (%v)", d.Verdict, d.Deny)
	}
}

func TestDSLMatchRuleIgnoresLowerSeverity(t *testing.T) {
	doc := `
rules:
  - id: no-new-high-vulns
    action: deny
    match: { type: vulnerability, status: new, min_severity: high }
    message: "new high vuln"
`
	run := model.Run{Findings: []model.Finding{
		{Family: model.FamilyVuln, Status: model.StatusNew, Severity: model.SevMedium},
	}}
	if d := compileAndEval(t, doc, run); d.Verdict == model.VerdictFail {
		t.Fatal("medium vuln must not trip a high-severity rule")
	}
}

func TestDSLMetricWarn(t *testing.T) {
	doc := `
rules:
  - id: cov
    action: warn
    metric: { key: coverage.changed_lines, below: 80 }
    message: "low coverage"
`
	run := model.Run{Metrics: []model.Metric{{Key: "coverage.changed_lines", Value: 55}}}
	if d := compileAndEval(t, doc, run); d.Verdict != model.VerdictWarn {
		t.Fatalf("expected warn, got %s", d.Verdict)
	}
}

func TestDSLForbiddenLicence(t *testing.T) {
	doc := `
rules:
  - id: lic
    action: deny
    forbidden_licenses: [AGPL-3.0-only, SSPL-1.0]
    message: "forbidden licence"
`
	run := model.Run{SBOM: []model.Component{{Name: "x", License: "AGPL-3.0-only"}}}
	if d := compileAndEval(t, doc, run); d.Verdict != model.VerdictFail {
		t.Fatalf("expected fail, got %s", d.Verdict)
	}
}

func TestDSLContextGuard(t *testing.T) {
	doc := `
rules:
  - id: release-only
    action: deny
    contexts: [release]
    match: { type: secret }
    message: "secret at release"
`
	// pre-push context → rule should not fire.
	pp := model.Run{Context: model.ContextPrePush, Findings: []model.Finding{{Family: model.FamilySecret}}}
	if d := compileAndEval(t, doc, pp); d.Verdict == model.VerdictFail {
		t.Fatal("release-only rule must not fire in pre-push")
	}
	// release context → fires.
	rel := model.Run{Context: model.ContextRelease, Findings: []model.Finding{{Family: model.FamilySecret}}}
	if d := compileAndEval(t, doc, rel); d.Verdict != model.VerdictFail {
		t.Fatal("release-only rule should fire at release")
	}
}

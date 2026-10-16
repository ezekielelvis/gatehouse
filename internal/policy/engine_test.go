package policy_test

import (
	"context"
	"testing"

	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/policy"
	"github.com/gatehouse/gatehouse/policies"
)

func baselineEngine(t *testing.T) *policy.Engine {
	t.Helper()
	mods, err := policies.Baseline()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.New(context.Background(), mods...)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestBaselinePassesCleanRun(t *testing.T) {
	eng := baselineEngine(t)
	d, err := eng.Evaluate(context.Background(), model.Run{Context: model.ContextPrePush})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != model.VerdictPass {
		t.Fatalf("clean run should pass, got %s (deny=%v warn=%v)", d.Verdict, d.Deny, d.Warn)
	}
}

func TestBaselineFailsOnNewSecret(t *testing.T) {
	eng := baselineEngine(t)
	run := model.Run{
		Context: model.ContextPrePush,
		Findings: []model.Finding{
			{Family: model.FamilySecret, RuleID: "aws-key", Path: "prod.env", StartLine: 3, Status: model.StatusNew},
		},
	}
	d, err := eng.Evaluate(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != model.VerdictFail {
		t.Fatalf("new secret should fail, got %s", d.Verdict)
	}
	if len(d.Deny) == 0 {
		t.Fatal("expected a deny message")
	}
}

func TestBaselineExistingSecretDoesNotFailPrePush(t *testing.T) {
	eng := baselineEngine(t)
	run := model.Run{
		Context: model.ContextPrePush,
		Findings: []model.Finding{
			{Family: model.FamilySecret, RuleID: "aws-key", Path: "old.env", Status: model.StatusExisting},
		},
	}
	d, _ := eng.Evaluate(context.Background(), run)
	if d.Verdict == model.VerdictFail {
		t.Fatal("pre-existing secret must not fail pre-push (diff-only gate)")
	}
}

func TestBaselinePreCommitBlocksAnySecret(t *testing.T) {
	eng := baselineEngine(t)
	run := model.Run{
		Context: model.ContextPreCommit,
		Findings: []model.Finding{
			{Family: model.FamilySecret, RuleID: "aws-key", Path: "old.env", Status: model.StatusExisting},
		},
	}
	d, _ := eng.Evaluate(context.Background(), run)
	if d.Verdict != model.VerdictFail {
		t.Fatalf("pre-commit should block any secret, got %s", d.Verdict)
	}
}

func TestBaselineWaiverSuppressesDeny(t *testing.T) {
	eng := baselineEngine(t)
	run := model.Run{
		Context: model.ContextPrePush,
		Findings: []model.Finding{
			{Family: model.FamilySecret, RuleID: "aws-key", Path: "prod.env", Status: model.StatusNew, WaiverID: "W-1"},
		},
	}
	d, _ := eng.Evaluate(context.Background(), run)
	if d.Verdict == model.VerdictFail {
		t.Fatal("waived finding should not fail the run")
	}
}

func TestBaselineFailsOnFailingTest(t *testing.T) {
	eng := baselineEngine(t)
	run := model.Run{
		Context: model.ContextPrePush,
		Tests:   []model.TestResult{{Suite: "unit", Name: "TestX", Status: "failed"}},
	}
	d, _ := eng.Evaluate(context.Background(), run)
	if d.Verdict != model.VerdictFail {
		t.Fatalf("failing test should fail run, got %s", d.Verdict)
	}
}

func TestBaselineQuarantinedTestDoesNotFail(t *testing.T) {
	eng := baselineEngine(t)
	run := model.Run{
		Context: model.ContextPrePush,
		Tests:   []model.TestResult{{Suite: "unit", Name: "TestFlaky", Status: "failed", Quarantined: true}},
	}
	d, _ := eng.Evaluate(context.Background(), run)
	if d.Verdict == model.VerdictFail {
		t.Fatal("quarantined failing test should not fail the run")
	}
}

func TestBaselineWarnsOnLowCoverage(t *testing.T) {
	eng := baselineEngine(t)
	run := model.Run{
		Context: model.ContextPrePush,
		Metrics: []model.Metric{{Key: "coverage.changed_lines", Value: 50}},
	}
	d, _ := eng.Evaluate(context.Background(), run)
	if d.Verdict != model.VerdictWarn {
		t.Fatalf("low coverage should warn, got %s (warn=%v)", d.Verdict, d.Warn)
	}
}

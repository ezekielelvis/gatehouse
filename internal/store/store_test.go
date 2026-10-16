package store

import (
	"testing"
	"time"

	"github.com/gatehouse/gatehouse/internal/model"
)

func TestSaveAndDiffBase(t *testing.T) {
	st, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	run := model.Run{
		ID:       "r1",
		RepoPath: "/repo",
		Ref:      "working-tree",
		Context:  model.ContextPrePush,
		Verdict:  model.VerdictFail,
		Status:   "done",
		Findings: []model.Finding{
			{Fingerprint: "fp1", Family: model.FamilySecret, RuleID: "aws", Severity: model.SevHigh, Path: "a.go", StartLine: 1, Status: model.StatusNew},
		},
		Metrics: []model.Metric{{Key: "coverage.line", Value: 73.5}},
	}
	if err := st.SaveRun(run); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveDecision(run.ID, run.Verdict, []string{"blocked"}, nil); err != nil {
		t.Fatal(err)
	}

	base, err := st.LastFindings("/repo", "working-tree")
	if err != nil {
		t.Fatal(err)
	}
	if len(base) != 1 || base[0].Fingerprint != "fp1" {
		t.Fatalf("expected 1 base finding fp1, got %+v", base)
	}
	if base[0].Severity != model.SevHigh {
		t.Errorf("severity not round-tripped: %s", base[0].Severity)
	}

	runs, err := st.RecentRuns(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ID != "r1" {
		t.Fatalf("expected run r1, got %+v", runs)
	}
}

func TestStepsAndSBOMRoundTrip(t *testing.T) {
	st, _ := Open(":memory:")
	defer st.Close()
	run := model.Run{
		ID: "r1", RepoPath: "/repo", Ref: "working-tree", Status: "done",
		Steps: []model.Step{
			{PluginID: "opengrep", ExitCode: 0, Errored: false},
			{PluginID: "osv-scanner", Errored: true, Error: "pull failed"},
		},
		SBOM: []model.Component{{Name: "lodash", Version: "4.17.21", License: "MIT", Direct: true}},
	}
	if err := st.SaveRun(run); err != nil {
		t.Fatal(err)
	}
	got, _, _, err := st.GetRun("r1")
	if err != nil || got == nil {
		t.Fatalf("GetRun: %v", err)
	}
	if len(got.Steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(got.Steps))
	}
	byID := map[string]model.Step{}
	for _, s := range got.Steps {
		byID[s.PluginID] = s
	}
	if !byID["osv-scanner"].Errored || byID["opengrep"].Errored {
		t.Errorf("errored flags not round-tripped: %+v", byID)
	}
	if len(got.SBOM) != 1 || got.SBOM[0].Name != "lodash" || !got.SBOM[0].Direct {
		t.Errorf("sbom not round-tripped: %+v", got.SBOM)
	}
}

func TestGCKeepsRecentAndReleaseRuns(t *testing.T) {
	st, _ := Open(":memory:")
	defer st.Close()
	mk := func(id string, ctx model.Context, order int) {
		r := model.Run{ID: id, RepoPath: "/repo", Ref: "main", Context: ctx, Status: "done",
			StartedAt: time.Unix(int64(order), 0)}
		if err := st.SaveRun(r); err != nil {
			t.Fatal(err)
		}
	}
	// 5 pre-push runs + 1 release run, varying age.
	mk("r1", model.ContextPrePush, 1)
	mk("r2", model.ContextPrePush, 2)
	mk("rel", model.ContextRelease, 3) // oldest-ish but release → always kept
	mk("r4", model.ContextPrePush, 4)
	mk("r5", model.ContextPrePush, 5)

	n, err := st.GC(2) // keep newest 2 non-release per branch
	if err != nil {
		t.Fatal(err)
	}
	// Non-release runs: r1,r2,r4,r5 → keep r5,r4 → prune r1,r2 = 2.
	if n != 2 {
		t.Fatalf("expected 2 runs pruned, got %d", n)
	}
	runs, _ := st.RecentRuns(10)
	ids := map[string]bool{}
	for _, r := range runs {
		ids[r.ID] = true
	}
	if ids["r1"] || ids["r2"] {
		t.Error("old pre-push runs should be pruned")
	}
	if !ids["rel"] {
		t.Error("release run must never be pruned")
	}
	if !ids["r4"] || !ids["r5"] {
		t.Error("newest pre-push runs must be kept")
	}
}

func TestLastFindingsNoPriorRun(t *testing.T) {
	st, _ := Open(":memory:")
	defer st.Close()
	base, err := st.LastFindings("/nope", "working-tree")
	if err != nil {
		t.Fatalf("expected nil error for no prior run, got %v", err)
	}
	if base != nil {
		t.Fatalf("expected nil base, got %+v", base)
	}
}

func TestSaveRunIdempotent(t *testing.T) {
	st, _ := Open(":memory:")
	defer st.Close()
	run := model.Run{ID: "r1", RepoPath: "/repo", Ref: "working-tree", Status: "done",
		Findings: []model.Finding{{Fingerprint: "fp1", Path: "a.go"}}}
	_ = st.SaveRun(run)
	_ = st.SaveRun(run) // saving twice must not duplicate findings
	got, _ := st.LastFindings("/repo", "working-tree")
	if len(got) != 1 {
		t.Fatalf("re-saving a run duplicated findings: got %d", len(got))
	}
}

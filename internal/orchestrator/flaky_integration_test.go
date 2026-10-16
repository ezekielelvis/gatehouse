package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatehouse/gatehouse/internal/config"
	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/plugins"
	"github.com/gatehouse/gatehouse/internal/sandbox"
	"github.com/gatehouse/gatehouse/internal/store"
)

// junitRuntime writes a JUnit report whose single test has the configured status.
type junitRuntime struct{ status string }

func (j *junitRuntime) Name() string                    { return "junit-fake" }
func (j *junitRuntime) Available(context.Context) error { return nil }
func (j *junitRuntime) Close() error                    { return nil }
func (j *junitRuntime) Run(_ context.Context, spec sandbox.Spec) (*sandbox.Result, error) {
	body := `<testsuites><testsuite name="unit"><testcase name="TestFlaky" time="0.1">`
	if j.status == "failed" {
		body += `<failure message="flake"/>`
	}
	body += `</testcase></testsuite></testsuites>`
	if err := os.WriteFile(filepath.Join(spec.OutDir, "junit.xml"), []byte(body), 0o644); err != nil {
		return nil, err
	}
	return &sandbox.Result{}, nil
}

func junitPlugin() plugins.Manifest {
	return plugins.Manifest{
		ID: "tests", Image: "img@sha256:x", Family: model.FamilyTest,
		Network: "none", Command: []string{"test"},
		AppliesWhen: plugins.AppliesWhen{Always: true},
		Outputs:     []plugins.Output{{Path: "/out/junit.xml", Format: plugins.FormatJUnit}},
	}
}

// TestFlakyTestGetsQuarantinedAndStopsBlocking drives several runs through a
// real store so history accumulates: the test passes, passes, then fails. With
// quarantine_after=1 the now-flaky failing test is quarantined on the failing
// run, so the baseline gate passes instead of blocking.
func TestFlakyTestGetsQuarantinedAndStopsBlocking(t *testing.T) {
	repo := newTestRepo(t)
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cfg := config.Default()
	cfg.QA.Flaky.QuarantineAfter = 1

	run := func(status string) (model.Run, bool) {
		orch := New(&junitRuntime{status: status}, []plugins.Manifest{junitPlugin()}, engine(t), st)
		r, d, err := orch.Run(context.Background(), Options{
			RepoPath: repo, Ref: "working-tree", Context: model.ContextPrePush, Config: cfg,
		})
		if err != nil {
			t.Fatal(err)
		}
		return r, d.Verdict == model.VerdictFail
	}

	// Two passing runs build a pass history.
	run("passed")
	run("passed")

	// Now it fails: pass history + current fail → flaky → quarantined → gate passes.
	r, failed := run("failed")
	if len(r.Tests) != 1 {
		t.Fatalf("want 1 test, got %d", len(r.Tests))
	}
	if !r.Tests[0].Flaky {
		t.Error("test should be detected as flaky (passed before, failing now)")
	}
	if !r.Tests[0].Quarantined {
		t.Error("flaky test should be quarantined at quarantine_after=1")
	}
	if failed {
		t.Error("a quarantined failing test must not fail the gate")
	}
}

// TestConsistentlyFailingTestStillBlocks ensures quarantine doesn't mask a test
// that has only ever failed (not flaky).
func TestConsistentlyFailingTestStillBlocks(t *testing.T) {
	repo := newTestRepo(t)
	st, _ := store.Open(":memory:")
	defer st.Close()
	cfg := config.Default()
	cfg.QA.Flaky.QuarantineAfter = 1

	orch := New(&junitRuntime{status: "failed"}, []plugins.Manifest{junitPlugin()}, engine(t), st)
	r, d, err := orch.Run(context.Background(), Options{RepoPath: repo, Ref: "working-tree", Context: model.ContextPrePush, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if r.Tests[0].Flaky {
		t.Error("a test with no passing history is not flaky")
	}
	if d.Verdict != model.VerdictFail {
		t.Fatalf("a consistently failing (non-flaky) test must block, got %s", d.Verdict)
	}
}

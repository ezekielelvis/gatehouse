package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/plugins"
	"github.com/gatehouse/gatehouse/internal/policy"
	"github.com/gatehouse/gatehouse/internal/sandbox"
	"github.com/gatehouse/gatehouse/policies"
)

// fakeRuntime writes a canned SARIF file to the step's /out, so the whole
// pipeline (detect → run → normalise → diff → policy) can be exercised without
// a container runtime or any external tool installed.
type fakeRuntime struct{ sarif string }

func (f *fakeRuntime) Name() string                    { return "fake" }
func (f *fakeRuntime) Available(context.Context) error { return nil }
func (f *fakeRuntime) Close() error                    { return nil }
func (f *fakeRuntime) Run(_ context.Context, spec sandbox.Spec) (*sandbox.Result, error) {
	if f.sarif != "" {
		if err := os.WriteFile(filepath.Join(spec.OutDir, "out.sarif"), []byte(f.sarif), 0o644); err != nil {
			return nil, err
		}
	}
	return &sandbox.Result{ExitCode: 0}, nil
}

const secretSARIF = `{"runs":[{"tool":{"driver":{"name":"fakescan"}},"results":[
  {"ruleId":"hardcoded-secret","message":{"text":"secret found"},
   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"/src/app.py"},
   "region":{"startLine":2,"snippet":{"text":"API_KEY = 'xyz'"}}}}]}
]}]}`

func fakePlugin() plugins.Manifest {
	return plugins.Manifest{
		ID: "fakescan", Image: "img@sha256:x", Family: model.FamilySecret,
		Network: "none", Command: []string{"scan"},
		AppliesWhen: plugins.AppliesWhen{Always: true},
		Outputs:     []plugins.Output{{Path: "/out/out.sarif", Format: plugins.FormatSARIF}},
	}
}

func newTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import os\nAPI_KEY = 'xyz'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func engine(t *testing.T) *policy.Engine {
	t.Helper()
	mods, _ := policies.Baseline()
	eng, err := policy.New(context.Background(), mods...)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestRunEndToEndFailsOnNewSecret(t *testing.T) {
	repo := newTestRepo(t)
	orch := New(&fakeRuntime{sarif: secretSARIF}, []plugins.Manifest{fakePlugin()}, engine(t), nil)

	run, decision, err := orch.Run(context.Background(), Options{
		RepoPath: repo, Ref: "working-tree", Context: model.ContextPrePush,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !run.Profile.HasLanguage("Python") {
		t.Errorf("expected Python detected, got %v", run.Profile.Languages)
	}
	if len(run.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(run.Findings))
	}
	if run.Findings[0].Status != model.StatusNew {
		t.Errorf("finding should be new, got %s", run.Findings[0].Status)
	}
	if run.Findings[0].Path != "app.py" {
		t.Errorf("path should be repo-relative 'app.py', got %q", run.Findings[0].Path)
	}
	if run.Findings[0].Severity != model.SevHigh {
		t.Errorf("secret should default to high severity, got %s", run.Findings[0].Severity)
	}
	if decision.Verdict != model.VerdictFail {
		t.Fatalf("new secret should fail, got %s", decision.Verdict)
	}
}

func TestRunPassesCleanRepo(t *testing.T) {
	repo := newTestRepo(t)
	orch := New(&fakeRuntime{sarif: ""}, []plugins.Manifest{fakePlugin()}, engine(t), nil)
	_, decision, err := orch.Run(context.Background(), Options{RepoPath: repo, Context: model.ContextPrePush})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Verdict != model.VerdictPass {
		t.Fatalf("clean repo should pass, got %s (%v)", decision.Verdict, decision.Deny)
	}
}

func TestErroredPluginDoesNotAbortRun(t *testing.T) {
	repo := newTestRepo(t)
	// A plugin whose output never appears and which has no host_command still
	// shouldn't crash the run; its step is marked errored.
	bad := fakePlugin()
	bad.ID = "broken"
	orch := New(&erroringRuntime{}, []plugins.Manifest{bad}, engine(t), nil)
	run, _, err := orch.Run(context.Background(), Options{RepoPath: repo, Context: model.ContextPrePush})
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Steps) != 1 || !run.Steps[0].Errored {
		t.Fatalf("expected the broken step to be marked errored, got %+v", run.Steps)
	}
}

type erroringRuntime struct{}

func (erroringRuntime) Name() string                    { return "err" }
func (erroringRuntime) Available(context.Context) error { return nil }
func (erroringRuntime) Close() error                    { return nil }
func (erroringRuntime) Run(context.Context, sandbox.Spec) (*sandbox.Result, error) {
	return nil, context.DeadlineExceeded
}

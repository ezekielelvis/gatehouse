package orchestrator

import (
	"context"
	"strings"
	"testing"

	"github.com/gatehouse/gatehouse/internal/config"
	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/plugins"
	"github.com/gatehouse/gatehouse/internal/sandbox"
)

func TestE2EScriptSynthesis(t *testing.T) {
	script := e2eScript(&config.E2E{
		Start:   "npm run start",
		WaitFor: "http://app:3000/health",
		Run:     "npx playwright test --reporter=junit",
	})
	for _, want := range []string{"npm run start", "app:3000/health", "playwright test", "APP_PID", "exit $RC"} {
		if !strings.Contains(script, want) {
			t.Errorf("e2e script missing %q\n%s", want, script)
		}
	}
}

func TestE2EScriptNoStart(t *testing.T) {
	// When the app runs as a declared service, there is no Start; the script
	// must not reference APP_PID.
	script := e2eScript(&config.E2E{Run: "pytest"})
	if strings.Contains(script, "APP_PID") {
		t.Error("no-Start e2e should not manage an app pid")
	}
	if !strings.Contains(script, "pytest") {
		t.Error("run command missing")
	}
}

func TestServiceSpecsFromConfig(t *testing.T) {
	specs := serviceSpecs(map[string]config.Service{
		"postgres": {Image: "postgres:17", Env: map[string]string{"POSTGRES_PASSWORD": "test"}},
	})
	if len(specs) != 1 || specs[0].Name != "postgres" || specs[0].Image != "postgres:17" {
		t.Fatalf("bad service spec: %+v", specs)
	}
}

// With a runtime that is not a ServiceRunner (e.g. host executor), the e2e step
// must be marked errored rather than silently skipped or crashing.
func TestE2ERequiresServiceRunner(t *testing.T) {
	repo := newTestRepo(t)
	cfg := config.Default()
	cfg.QA.E2E = &config.E2E{Run: "echo hi"}

	orch := New(&fakeRuntime{}, []plugins.Manifest{fakePlugin()}, engine(t), nil)
	run, _, err := orch.Run(context.Background(), Options{RepoPath: repo, Context: model.ContextPrePush, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var e2e *model.Step
	for i := range run.Steps {
		if run.Steps[i].PluginID == "e2e" {
			e2e = &run.Steps[i]
		}
	}
	if e2e == nil {
		t.Fatal("expected an e2e step")
	}
	if !e2e.Errored || !strings.Contains(e2e.Error, "container runtime") {
		t.Errorf("e2e should error without a ServiceRunner, got %+v", e2e)
	}
}

// Ensure fakeRuntime is not accidentally a ServiceRunner.
var _ sandbox.Runtime = (*fakeRuntime)(nil)

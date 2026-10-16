package orchestrator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gatehouse/gatehouse/internal/adapters"
	"github.com/gatehouse/gatehouse/internal/config"
	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/sandbox"
)

// defaultE2EImage is used when the repo doesn't pin an e2e runner image.
const defaultE2EImage = "ghcr.io/gatehouse/run-browser@sha256:0000000000000000000000000000000000000000000000000000000000000000"

// runE2E executes the end-to-end phase: it brings up the declared services on a
// private internal network, starts the app, waits for it to be healthy, then
// runs the browser suite against it and collects JUnit results. The whole phase
// has no egress. Requires a runtime that implements sandbox.ServiceRunner (the
// real container runtime); otherwise the step is marked errored with a clear
// reason, since e2e cannot be sandboxed on the host executor.
func (o *Orchestrator) runE2E(ctx context.Context, srcDir, workDir string, opts Options) (model.Step, []model.TestResult) {
	step := model.Step{PluginID: "e2e"}
	e2e := opts.Config.QA.E2E

	runner, ok := o.rt.(sandbox.ServiceRunner)
	if !ok {
		step.Errored = true
		step.Error = "e2e requires a container runtime (services cannot be sandboxed with --unsafe-host-exec)"
		o.progress("  ✗ e2e skipped: %s", step.Error)
		return step, nil
	}

	o.progress("  ▶ e2e: starting %d service(s)", len(opts.Config.QA.Services))
	netName, cleanup, err := runner.StartServices(ctx, runID(), serviceSpecs(opts.Config.QA.Services))
	if err != nil {
		step.Errored, step.Error = true, err.Error()
		return step, nil
	}
	defer cleanup()

	outDir := filepath.Join(workDir, "out", "e2e")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		step.Errored, step.Error = true, err.Error()
		return step, nil
	}

	image := e2e.Image
	if image == "" {
		image = defaultE2EImage
	}
	spec := sandbox.Spec{
		StepID:      "e2e",
		Image:       image,
		Command:     []string{"sh", "-c", e2eScript(e2e)},
		SrcDir:      srcDir,
		OutDir:      outDir,
		Network:     sandbox.NetworkInternal,
		NetworkName: netName, // attach the runner to the services' network
		Limits:      sandbox.Limits{Timeout: 20 * time.Minute},
	}

	res, err := o.rt.Run(ctx, spec)
	if err != nil {
		step.Errored, step.Error = true, err.Error()
		return step, nil
	}
	step.ExitCode = res.ExitCode
	step.Duration = res.Duration

	tests := collectJUnitDir(outDir)
	o.progress("  ✓ e2e (%d tests)", len(tests))
	return step, tests
}

// e2eScript synthesises the shell that starts the app, waits for health, runs
// the suite, then tears the app down — returning the suite's exit code.
func e2eScript(e2e *config.E2E) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	if e2e.Start != "" {
		fmt.Fprintf(&b, "( %s ) &\nAPP_PID=$!\n", e2e.Start)
	}
	if e2e.WaitFor != "" {
		fmt.Fprintf(&b, `for i in $(seq 1 120); do
  if wget -qO- %q >/dev/null 2>&1 || curl -sf %q >/dev/null 2>&1; then break; fi
  sleep 1
done
`, e2e.WaitFor, e2e.WaitFor)
	}
	fmt.Fprintf(&b, "set +e\n%s\nRC=$?\n", e2e.Run)
	if e2e.Start != "" {
		b.WriteString("kill $APP_PID 2>/dev/null\n")
	}
	b.WriteString("exit $RC\n")
	return b.String()
}

func serviceSpecs(services map[string]config.Service) []sandbox.ServiceSpec {
	out := make([]sandbox.ServiceSpec, 0, len(services))
	for name, svc := range services {
		out = append(out, sandbox.ServiceSpec{Name: name, Image: svc.Image, Env: svc.Env})
	}
	return out
}

// collectJUnitDir parses every *.xml file in dir as JUnit, so a suite can write
// results under any name.
func collectJUnitDir(dir string) []model.TestResult {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []model.TestResult
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".xml") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		tests, err := adapters.ParseJUnit(f)
		f.Close()
		if err == nil {
			out = append(out, tests...)
		}
	}
	return out
}

// runID generates a fresh id for the e2e service network namespace.
func runID() string { return time.Now().UTC().Format("150405") + "-" + randHex(3) }

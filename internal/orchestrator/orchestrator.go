// Package orchestrator plans and executes a run: detect → snapshot → run
// applicable plugins in parallel sandboxes → normalise outputs → diff against
// the base run → evaluate policy → persist (plan §3/§15). No scanner, build or
// test ever runs inside the core process; everything goes through a
// sandbox.Runtime.
package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gatehouse/gatehouse/internal/adapters"
	"github.com/gatehouse/gatehouse/internal/config"
	"github.com/gatehouse/gatehouse/internal/detect"
	"github.com/gatehouse/gatehouse/internal/enrich"
	"github.com/gatehouse/gatehouse/internal/evidence"
	"github.com/gatehouse/gatehouse/internal/findings"
	"github.com/gatehouse/gatehouse/internal/gitx"
	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/plugins"
	"github.com/gatehouse/gatehouse/internal/policy"
	"github.com/gatehouse/gatehouse/internal/qa"
	"github.com/gatehouse/gatehouse/internal/sandbox"
	"github.com/gatehouse/gatehouse/internal/store"
	"github.com/gatehouse/gatehouse/internal/waivers"
)

// stepResult is the normalised output of one plugin: findings plus any test
// results and coverage metrics collected from its output files.
type stepResult struct {
	findings   []model.Finding
	tests      []model.TestResult
	metrics    []model.Metric
	components []model.Component
}

// Options configures one scan.
type Options struct {
	RepoPath string
	Ref      string
	BaseRef  string // if set, findings are diffed against the last run on Ref
	Context  model.Context
	WorkDir  string // where snapshots/out dirs are created; defaults to a temp dir

	// Config is the per-repo gatehouse.yaml. Zero value is fine (Default()).
	Config config.Config
	// Waivers suppress matched findings. nil is fine (no waivers).
	Waivers *waivers.Set
}

// Orchestrator wires together the runtime, plugin set, policy engine and store.
type Orchestrator struct {
	rt      sandbox.Runtime
	plugs   []plugins.Manifest
	engine  *policy.Engine
	store   *store.Store
	workers int

	// Progress, if set, receives human-readable step events for live UIs/CLI.
	Progress func(string)
	// Audit, if set, receives a hash-chained entry per completed run so the
	// local evidence trail records that the run happened and with what verdict.
	Audit *evidence.AuditLog
	// Mirror enriches vulnerability findings with CVSS/EPSS/KEV. nil → no-op.
	Mirror *enrich.Mirror
}

// New builds an orchestrator. store may be nil (results simply aren't persisted).
func New(rt sandbox.Runtime, plugs []plugins.Manifest, engine *policy.Engine, st *store.Store) *Orchestrator {
	o := &Orchestrator{rt: rt, plugs: plugs, engine: engine, store: st, workers: 4}
	return o
}

func (o *Orchestrator) progress(format string, args ...any) {
	if o.Progress != nil {
		o.Progress(fmt.Sprintf(format, args...))
	}
}

// Run executes the full pipeline and returns the completed run plus the policy
// decision.
func (o *Orchestrator) Run(ctx context.Context, opts Options) (model.Run, policy.Decision, error) {
	if opts.Context == "" {
		opts.Context = model.ContextPrePush
	}
	run := model.Run{
		ID:        newRunID(),
		RepoPath:  opts.RepoPath,
		Ref:       opts.Ref,
		BaseRef:   opts.BaseRef,
		Context:   opts.Context,
		Status:    "running",
		StartedAt: time.Now(),
	}

	workDir := opts.WorkDir
	if workDir == "" {
		var err error
		workDir, err = os.MkdirTemp("", "gatehouse-run-")
		if err != nil {
			return run, policy.Decision{}, err
		}
		defer os.RemoveAll(workDir)
	}

	// 1. Snapshot (read-only source).
	o.progress("snapshotting source")
	srcDir := filepath.Join(workDir, "src")
	snap, err := gitx.SnapshotWorkingTree(opts.RepoPath, srcDir)
	if err != nil {
		return o.fail(run, fmt.Errorf("snapshot: %w", err))
	}
	run.TreeHash = snap.TreeHash

	// 2. Detect languages/manifests.
	o.progress("detecting repo profile")
	profile, err := detect.Profile(os.DirFS(srcDir), ".")
	if err != nil {
		return o.fail(run, fmt.Errorf("detect: %w", err))
	}
	run.Profile = profile

	// 3. Select applicable plugins, then let the repo's gatehouse.yaml enable,
	// disable or re-image them.
	selected := plugins.Select(o.plugs, profile)
	selected = opts.Config.Apply(o.plugs, selected)
	o.progress("running %d checks", len(selected))

	// In diff mode, compute the changed-file set so scanners/coverage can be
	// scoped to the change (used for coverage.changed_lines).
	var changed []string
	if opts.BaseRef != "" && gitx.IsRepo(opts.RepoPath) {
		changed, _ = gitx.ChangedFiles(opts.RepoPath, opts.BaseRef)
	}

	steps, agg := o.runPlugins(ctx, srcDir, workDir, selected, changed)

	// Optional e2e phase: start declared services on a private internal network,
	// start the app, wait for health, run the browser suite (plan §8).
	if opts.Config.QA.E2E != nil {
		step, tests := o.runE2E(ctx, srcDir, workDir, opts)
		steps = append(steps, step)
		agg.tests = append(agg.tests, tests...)
	}

	run.Steps = steps
	run.Tests = o.annotateFlaky(opts, agg.tests)
	run.Metrics = agg.metrics
	run.SBOM = agg.components

	// 4. Normalise + diff against the base run.
	findings.Assign(agg.findings)
	var base []model.Finding
	if o.store != nil && opts.BaseRef != "" {
		base, _ = o.store.LastFindings(opts.RepoPath, opts.Ref)
	}
	classified, _ := findings.Diff(agg.findings, base)

	// Enrich vulnerability findings from local CVSS/EPSS/KEV mirrors so policy
	// and the UI can reason about risk, not raw counts.
	if o.Mirror != nil {
		classified = o.Mirror.Apply(classified)
	}

	// Apply waivers before policy so a waived finding carries its WaiverID and
	// baseline rules (which check `not f.waived`) let it through.
	if opts.Waivers != nil {
		classified, _ = opts.Waivers.Apply(classified, run.StartedAt)
	}
	run.Findings = classified

	// 5. Evaluate policy.
	o.progress("evaluating policy")
	decision, err := o.engine.Evaluate(ctx, run)
	if err != nil {
		return o.fail(run, fmt.Errorf("policy: %w", err))
	}
	run.Verdict = decision.Verdict
	run.Status = "done"
	run.FinishedAt = time.Now()

	// 6. Persist.
	if o.store != nil {
		if err := o.store.SaveRun(run); err != nil {
			return run, decision, fmt.Errorf("save run: %w", err)
		}
		_ = o.store.SaveDecision(run.ID, decision.Verdict, decision.Deny, decision.Warn)
	}

	// 7. Record a tamper-evident audit entry committing to the run manifest.
	if o.Audit != nil {
		manifest, _ := json.Marshal(run)
		if _, err := o.Audit.Append(actor(), "run", manifest); err != nil {
			o.progress("warning: audit append failed: %v", err)
		}
	}
	return run, decision, nil
}

// actor identifies who triggered a run for the audit log (best-effort).
func actor() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

// annotateFlaky marks flaky/quarantined tests using the repo's test history and
// QA config, so the policy gate can ignore known-flaky failures (plan §8).
func (o *Orchestrator) annotateFlaky(opts Options, tests []model.TestResult) []model.TestResult {
	if len(tests) == 0 {
		return tests
	}
	var history map[string]qa.Outcome
	if o.store != nil {
		if h, err := o.store.TestHistory(opts.RepoPath, opts.Ref, 20); err == nil {
			history = toQAHistory(h)
		}
	}
	return qa.Apply(tests, history, qa.FlakyConfig{
		QuarantineAfter: opts.Config.QA.Flaky.QuarantineAfter,
		Manual:          opts.Config.QA.Quarantine,
	})
}

func toQAHistory(h map[string]store.TestOutcome) map[string]qa.Outcome {
	out := make(map[string]qa.Outcome, len(h))
	for k, v := range h {
		out[k] = qa.Outcome{Pass: v.Pass, Fail: v.Fail}
	}
	return out
}

// runPlugins executes each selected plugin concurrently (bounded by a worker
// pool) and returns the per-plugin steps plus the union of their findings. A
// plugin that errors marks its step errored rather than aborting the run (plan
// §15: a failed tool marks its family errored, it does not silently pass).
func (o *Orchestrator) runPlugins(ctx context.Context, srcDir, workDir string, selected []plugins.Manifest, changed []string) ([]model.Step, stepResult) {
	var (
		mu    sync.Mutex
		steps []model.Step
		agg   stepResult
		sem   = make(chan struct{}, o.workers)
		wg    sync.WaitGroup
	)

	for _, m := range selected {
		wg.Add(1)
		go func(m plugins.Manifest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			step, res := o.runOne(ctx, srcDir, workDir, m, changed)
			mu.Lock()
			steps = append(steps, step)
			agg.findings = append(agg.findings, res.findings...)
			agg.tests = append(agg.tests, res.tests...)
			agg.metrics = append(agg.metrics, res.metrics...)
			agg.components = append(agg.components, res.components...)
			mu.Unlock()
		}(m)
	}
	wg.Wait()
	return steps, agg
}

func (o *Orchestrator) runOne(ctx context.Context, srcDir, workDir string, m plugins.Manifest, changed []string) (model.Step, stepResult) {
	step := model.Step{PluginID: m.ID}
	outDir := filepath.Join(workDir, "out", m.ID)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		step.Errored, step.Error = true, err.Error()
		return step, stepResult{}
	}

	spec := sandbox.Spec{
		StepID:      m.ID,
		Image:       m.Image,
		Command:     m.Command,
		HostCommand: m.HostCommand,
		SrcDir:      srcDir,
		OutDir:      outDir,
		Network:     sandbox.Network(m.Network),
		Limits:      sandbox.Limits{Timeout: parseTimeout(m.Timeout)},
	}

	o.progress("  ▶ %s", m.ID)
	res, err := o.rt.Run(ctx, spec)
	if err != nil {
		step.Errored, step.Error = true, err.Error()
		o.progress("  ✗ %s: %v", m.ID, err)
		return step, stepResult{}
	}
	step.ExitCode = res.ExitCode
	step.Duration = res.Duration
	if res.TimedOut {
		step.Errored, step.Error = true, "timed out"
	}

	out, err := o.collect(srcDir, outDir, m, changed)
	if err != nil {
		step.Errored, step.Error = true, err.Error()
		return step, stepResult{}
	}
	o.progress("  ✓ %s (%d findings)", m.ID, len(out.findings))
	return step, out
}

// collect reads each declared output file and normalises it by format: SARIF
// into findings, JUnit into test results, lcov into coverage metrics. srcDir is
// the snapshot root; finding paths are made relative to it so they are
// repo-relative (not absolute temp paths) — essential both for readable reports
// and for fingerprint stability across runs, since the snapshot dir changes
// every run. changed is the diff-scoped file set for changed-lines coverage.
func (o *Orchestrator) collect(srcDir, outDir string, m plugins.Manifest, changed []string) (stepResult, error) {
	var res stepResult
	for _, spec := range m.Outputs {
		path := filepath.Join(outDir, filepath.Base(spec.Path))
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // tool produced no output file (e.g. no findings)
			}
			return stepResult{}, err
		}
		switch spec.Format {
		case plugins.FormatSARIF:
			finds, err := findings.ParseSARIF(f, findings.SARIFOptions{Family: m.Family})
			f.Close()
			if err != nil {
				return stepResult{}, fmt.Errorf("%s: %w", spec.Path, err)
			}
			res.findings = append(res.findings, finds...)
		case plugins.FormatJUnit:
			tests, err := adapters.ParseJUnit(f)
			f.Close()
			if err != nil {
				return stepResult{}, fmt.Errorf("%s: %w", spec.Path, err)
			}
			res.tests = append(res.tests, tests...)
		case plugins.FormatLCOV:
			cov, err := adapters.ParseLCOV(f)
			f.Close()
			if err != nil {
				return stepResult{}, fmt.Errorf("%s: %w", spec.Path, err)
			}
			res.metrics = append(res.metrics, cov.Metrics(changed)...)
		case plugins.FormatMutation:
			ms, err := adapters.ParseMutation(f)
			f.Close()
			if err != nil {
				return stepResult{}, fmt.Errorf("%s: %w", spec.Path, err)
			}
			res.metrics = append(res.metrics, ms...)
		case plugins.FormatCycloneDX:
			comps, err := adapters.ParseCycloneDX(f)
			f.Close()
			if err != nil {
				return stepResult{}, fmt.Errorf("%s: %w", spec.Path, err)
			}
			res.components = append(res.components, comps...)
		default:
			f.Close()
		}
	}
	for i := range res.findings {
		res.findings[i].Path = relPath(srcDir, res.findings[i].Path)
		res.findings[i].Severity = defaultSeverity(m.Family, res.findings[i].Severity)
	}
	return res, nil
}

// relPath makes a scanner-reported path repo-relative. Container runtimes
// report "/src/foo.go"; the host runtime reports the absolute snapshot path.
// Both are reduced to "foo.go".
func relPath(srcDir, p string) string {
	if rel, err := filepath.Rel(srcDir, p); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	if rel := strings.TrimPrefix(p, "/src/"); rel != p {
		return rel
	}
	return p
}

// defaultSeverity applies a per-family floor when a tool emits no severity.
// A secret, for example, is high by nature even when the SARIF carries no level.
func defaultSeverity(fam model.Family, s model.Severity) model.Severity {
	if s != model.SevUnknown {
		return s
	}
	switch fam {
	case model.FamilySecret:
		return model.SevHigh
	case model.FamilyVuln, model.FamilySAST:
		return model.SevMedium
	default:
		return model.SevLow
	}
}

func (o *Orchestrator) fail(run model.Run, err error) (model.Run, policy.Decision, error) {
	run.Status = "error"
	run.FinishedAt = time.Now()
	if o.store != nil {
		_ = o.store.SaveRun(run)
	}
	return run, policy.Decision{}, err
}

func parseTimeout(s string) time.Duration {
	if s == "" {
		return 10 * time.Minute
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 10 * time.Minute
	}
	return d
}

func newRunID() string {
	return time.Now().UTC().Format("20060102T150405") + "-" + randHex(4)
}

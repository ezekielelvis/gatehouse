package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/gatehouse/gatehouse/internal/config"
	"github.com/gatehouse/gatehouse/internal/enrich"
	"github.com/gatehouse/gatehouse/internal/evidence"
	"github.com/gatehouse/gatehouse/internal/gitx"
	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/orchestrator"
	"github.com/gatehouse/gatehouse/internal/plugins"
	"github.com/gatehouse/gatehouse/internal/policy"
	"github.com/gatehouse/gatehouse/internal/sandbox"
	"github.com/gatehouse/gatehouse/internal/store"
	"github.com/gatehouse/gatehouse/internal/waivers"
	pluginpacks "github.com/gatehouse/gatehouse/plugins"
	"github.com/gatehouse/gatehouse/policies"
)

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	diff := fs.String("diff", "", "diff against this base ref; only new findings gate")
	profile := fs.String("profile", "pre-push", "gate profile: pre-commit|pre-push|release")
	dbPath := fs.String("db", defaultDBPath(), "SQLite database path")
	jsonOut := fs.Bool("json", false, "emit the run as JSON")
	hostExec := fs.Bool("unsafe-host-exec", false, "DEV ONLY: run tools on the host with no sandbox when no container runtime is available")
	pluginsDir := fs.String("plugins", "", "additional plugin manifest directory (appended to the built-in set)")
	noBuiltin := fs.Bool("no-builtin-plugins", false, "use only --plugins manifests, skipping the built-in set")

	// Allow the repo path to appear before the flags (the natural
	// "gatehouse scan <path> --flags" form); the stdlib flag package otherwise
	// stops parsing at the first positional argument.
	repoPath := "."
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		repoPath = args[0]
		args = args[1:]
	}
	fs.Parse(args)
	if repoPath == "." && fs.NArg() > 0 {
		repoPath = fs.Arg(0)
	}
	abs, err := filepath.Abs(repoPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}

	ctx := context.Background()

	// Select a runtime: the real sandbox by default, falling back to the unsafe
	// host executor only when explicitly allowed.
	rt, err := selectRuntime(ctx, *hostExec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}
	defer rt.Close()
	fmt.Fprintf(os.Stderr, "runtime: %s\n", rt.Name())

	// Load the repo's gatehouse.yaml and waivers (both optional).
	cfg, err := config.Load(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load gatehouse.yaml:", err)
		return exitError
	}
	waiverSet, err := waivers.Load(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load waivers:", err)
		return exitError
	}

	// Load plugins and the policy packs the repo selected.
	var plugs []plugins.Manifest
	if !*noBuiltin {
		plugs, err = pluginpacks.Builtin()
		if err != nil {
			fmt.Fprintln(os.Stderr, "load plugins:", err)
			return exitError
		}
	}
	if *pluginsDir != "" {
		extra, err := plugins.LoadDir(os.DirFS(*pluginsDir), ".")
		if err != nil {
			fmt.Fprintln(os.Stderr, "load --plugins dir:", err)
			return exitError
		}
		plugs = append(plugs, extra...)
	}
	var mods []policy.Module
	for _, pack := range cfg.Packs {
		m, err := policies.Pack(pack)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load policy pack:", err)
			return exitError
		}
		mods = append(mods, m...)
	}
	// Repo policy layer: .gatehouse/policies/*.rego and *.yaml travel with the code.
	repoMods, err := policy.LoadRepoPolicies(abs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load repo policies:", err)
		return exitError
	}
	mods = append(mods, repoMods...)
	engine, err := policy.New(ctx, mods...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "compile policy:", err)
		return exitError
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		return exitError
	}
	defer st.Close()

	orch := orchestrator.New(rt, plugs, engine, st)
	if !*jsonOut {
		orch.Progress = func(msg string) { fmt.Fprintln(os.Stderr, msg) }
	}
	// Load the local CVSS/EPSS/KEV mirror for risk enrichment (absent = no-op).
	if mirror, err := enrich.Load(defaultMirrorPath()); err == nil {
		orch.Mirror = mirror
	}
	// Record every run in the local hash-chained audit log (best-effort: a
	// failure to open it must not block a scan).
	if auditLog, err := evidence.OpenAuditLog(defaultAuditPath()); err == nil {
		orch.Audit = auditLog
	}

	run, decision, err := orch.Run(ctx, orchestrator.Options{
		RepoPath: abs,
		Ref:      "working-tree",
		BaseRef:  *diff,
		Context:  model.Context(*profile),
		Config:   cfg,
		Waivers:  waiverSet,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan error:", err)
		return exitError
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(run)
	} else {
		printReport(run, decision)
	}

	// Write a signed git-notes attestation onto HEAD so CI can later run
	// `gatehouse verify <commit>` and confirm the local scan really ran (plan §12).
	if gitx.IsRepo(abs) {
		if err := writeGitNote(abs, run, decision.Deny, decision.Warn); err != nil {
			fmt.Fprintln(os.Stderr, "note: could not write git-notes attestation:", err)
		}
	}

	switch decision.Verdict {
	case model.VerdictFail:
		return exitFail
	case model.VerdictWarn:
		return exitWarn
	default:
		return exitPass
	}
}

// selectRuntime prefers the real container sandbox. The explicit
// --unsafe-host-exec flag overrides that and forces the host executor (a
// deliberate developer choice that must win even when a runtime is reachable).
func selectRuntime(ctx context.Context, forceHost bool) (sandbox.Runtime, error) {
	if forceHost {
		fmt.Fprintln(os.Stderr, "WARNING: --unsafe-host-exec: running tools on the host with NO sandbox isolation")
		return sandbox.NewHostRuntime(), nil
	}
	dr, err := sandbox.NewDockerRuntime()
	if err == nil {
		if err := dr.Available(ctx); err == nil {
			return dr, nil
		}
		dr.Close()
	}
	return nil, fmt.Errorf("no container runtime reachable (is Docker/Podman running?); pass --unsafe-host-exec to run tools on the host without a sandbox")
}

func printReport(run model.Run, d policy.Decision) {
	banner := map[model.Verdict]string{
		model.VerdictPass: "✓ PASS",
		model.VerdictWarn: "⚠ WARN",
		model.VerdictFail: "✗ FAIL",
	}
	fmt.Printf("\n%s  (run %s)\n", banner[d.Verdict], run.ID)
	fmt.Printf("repo:      %s\n", run.RepoPath)
	fmt.Printf("languages: %v\n", run.Profile.Languages)
	fmt.Printf("checks:    %d run, %d findings\n", len(run.Steps), len(run.Findings))

	for _, s := range run.Steps {
		if s.Errored {
			fmt.Printf("  ! %s errored: %s\n", s.PluginID, s.Error)
		}
	}

	if len(run.Findings) > 0 {
		fmt.Println("\nFindings (new first):")
		sorted := append([]model.Finding(nil), run.Findings...)
		sort.SliceStable(sorted, func(i, j int) bool {
			if (sorted[i].Status == model.StatusNew) != (sorted[j].Status == model.StatusNew) {
				return sorted[i].Status == model.StatusNew
			}
			return sorted[i].Severity > sorted[j].Severity
		})
		for _, f := range sorted {
			fmt.Printf("  [%s] %-8s %s %s:%d  %s\n",
				f.Status, f.Severity, f.RuleID, f.Path, f.StartLine, f.Message)
		}
	}

	for _, m := range d.Deny {
		fmt.Printf("\n  ✗ %s", m)
	}
	for _, m := range d.Warn {
		fmt.Printf("\n  ⚠ %s", m)
	}
	fmt.Println()
}

func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "gatehouse.db"
	}
	dir := filepath.Join(home, ".gatehouse")
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "gatehouse.db")
}

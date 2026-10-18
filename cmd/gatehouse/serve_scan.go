package main

import (
	"context"
	"fmt"
	"os"

	"github.com/gatehouse/gatehouse/internal/config"
	"github.com/gatehouse/gatehouse/internal/enrich"
	"github.com/gatehouse/gatehouse/internal/evidence"
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

// serveRuntime picks the runtime for UI-triggered scans: the real container
// sandbox, or the unsafe host executor when explicitly allowed. Returns nil if
// neither is available (scanning stays disabled).
func serveRuntime(hostExec bool) sandbox.Runtime {
	rt, err := selectRuntime(context.Background(), hostExec)
	if err != nil {
		return nil
	}
	return rt
}

// loadServePlugins loads the plugin set used by UI scans (built-in + external).
func loadServePlugins(noBuiltin bool, dir string) []plugins.Manifest {
	var plugs []plugins.Manifest
	if !noBuiltin {
		if b, err := pluginpacks.Builtin(); err == nil {
			plugs = b
		}
	}
	if dir != "" {
		if extra, err := plugins.LoadDir(os.DirFS(dir), "."); err == nil {
			plugs = append(plugs, extra...)
		}
	}
	return plugs
}

// runServeScan performs one UI-triggered scan end to end, resolving the repo's
// config, policy packs, repo policy layer and waivers, then running the
// orchestrator with the pre-created run id and streaming progress to the UI.
func runServeScan(st *store.Store, rt sandbox.Runtime, plugs []plugins.Manifest,
	mirror *enrich.Mirror, audit *evidence.AuditLog, runID, repoPath string, progress func(string)) error {

	ctx := context.Background()
	cfg, err := config.Load(repoPath)
	if err != nil {
		return fmt.Errorf("gatehouse.yaml: %w", err)
	}
	waiverSet, err := waivers.Load(repoPath)
	if err != nil {
		return fmt.Errorf("waivers: %w", err)
	}

	var mods []policy.Module
	for _, pack := range cfg.Packs {
		m, err := policies.Pack(pack)
		if err != nil {
			return fmt.Errorf("policy pack %s: %w", pack, err)
		}
		mods = append(mods, m...)
	}
	repoMods, err := policy.LoadRepoPolicies(repoPath)
	if err != nil {
		return fmt.Errorf("repo policies: %w", err)
	}
	mods = append(mods, repoMods...)
	engine, err := policy.New(ctx, mods...)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}

	// Read the run's context from the placeholder row the handler inserted.
	runCtx := "pre-push"
	if r, _, _, err := st.GetRun(runID); err == nil && r != nil && r.Context != "" {
		runCtx = string(r.Context)
	}

	orch := orchestrator.New(rt, plugs, engine, st)
	orch.Progress = progress
	orch.Mirror = mirror
	orch.Audit = audit

	_, _, err = orch.Run(ctx, orchestrator.Options{
		RunID:    runID,
		RepoPath: repoPath,
		Ref:      "working-tree",
		Context:  model.Context(runCtx),
		Config:   cfg,
		Waivers:  waiverSet,
	})
	return err
}

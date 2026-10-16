// Package policy evaluates a run against declarative gates using embedded OPA.
// Every run ends with a decision — pass, warn or fail — computed by Rego over
// one JSON document describing the whole run (plan §9).
package policy

import "github.com/gatehouse/gatehouse/internal/model"

// BuildInput reduces a Run to the plain map[string]any document that policies
// evaluate against. Keeping this a hand-built, documented shape (rather than
// marshalling the model directly) means the policy contract is explicit and
// stable even as internal types evolve.
func BuildInput(run model.Run) map[string]any {
	findings := make([]map[string]any, 0, len(run.Findings))
	for _, f := range run.Findings {
		findings = append(findings, map[string]any{
			"fingerprint": f.Fingerprint,
			"type":        string(f.Family),
			"rule_id":     f.RuleID,
			"tool":        f.Tool,
			"severity":    f.Severity.String(),
			"severity_n":  int(f.Severity),
			"status":      string(f.Status),
			"path":        f.Path,
			"line":        f.StartLine,
			"message":     f.Message,
			"cwe_ids":     f.CWEIDs,
			"cvss":        f.CVSS,
			"epss":        f.EPSS,
			"kev":         f.KEV,
			"waived":      f.WaiverID != "",
		})
	}

	metrics := map[string]any{}
	for _, m := range run.Metrics {
		metrics[m.Key] = m.Value
	}

	var failed, quarantined []map[string]any
	for _, t := range run.Tests {
		rec := map[string]any{"suite": t.Suite, "name": t.Name, "flaky": t.Flaky, "quarantined": t.Quarantined}
		if t.Status == "failed" {
			failed = append(failed, rec)
		}
		if t.Quarantined {
			quarantined = append(quarantined, rec)
		}
	}

	components := make([]map[string]any, 0, len(run.SBOM))
	for _, c := range run.SBOM {
		components = append(components, map[string]any{
			"purl": c.PURL, "name": c.Name, "version": c.Version,
			"license": c.License, "direct": c.Direct,
		})
	}

	// Surface which checks errored so a policy can decide whether a tool failure
	// should block (plan §15: an errored tool is not a silent pass).
	erroredChecks := make([]string, 0)
	for _, s := range run.Steps {
		if s.Errored {
			erroredChecks = append(erroredChecks, s.PluginID)
		}
	}

	return map[string]any{
		"context": string(run.Context),
		"repo": map[string]any{
			"path":      run.RepoPath,
			"ref":       run.Ref,
			"base_ref":  run.BaseRef,
			"languages": run.Profile.Languages,
			"manifests": run.Profile.Manifests,
		},
		"findings": findings,
		"metrics":  metrics,
		"tests": map[string]any{
			"failed":      failed,
			"quarantined": quarantined,
		},
		"sbom": map[string]any{
			"components": components,
		},
		"errored_checks": erroredChecks,
	}
}

// Package report renders a run's normalised findings back out into the formats
// IDEs, code-scanning dashboards and auditors expect (plan §10): a combined
// SARIF 2.1.0 log and a self-contained HTML report. SARIF ingest lives in
// internal/findings; this is the egress side.
package report

import (
	"encoding/json"
	"io"

	"github.com/gatehouse/gatehouse/internal/model"
)

// SARIF writes a combined SARIF 2.1.0 log for the run to w. A single run/driver
// ("gatehouse") carries every finding, with rules deduplicated and GitHub-style
// security-severity set from the finding's CVSS so GitHub code scanning colours
// results correctly.
func SARIF(w io.Writer, run model.Run) error {
	rulesIndex := map[string]int{}
	var rules []map[string]any
	var results []map[string]any

	for _, f := range run.Findings {
		if _, ok := rulesIndex[f.RuleID]; !ok {
			rulesIndex[f.RuleID] = len(rules)
			rule := map[string]any{
				"id":               f.RuleID,
				"name":             f.RuleID,
				"shortDescription": map[string]string{"text": f.RuleID},
				"properties":       ruleProperties(f),
			}
			rules = append(rules, rule)
		}
		results = append(results, map[string]any{
			"ruleId":    f.RuleID,
			"ruleIndex": rulesIndex[f.RuleID],
			"level":     severityToLevel(f.Severity),
			"message":   map[string]string{"text": f.Message},
			"properties": map[string]any{
				"family":                string(f.Family),
				"status":                string(f.Status),
				"gatehouse/fingerprint": f.Fingerprint,
			},
			"partialFingerprints": map[string]string{"gatehouse/v1": f.Fingerprint},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": f.Path},
					"region": map[string]any{
						"startLine": max1(f.StartLine),
						"endLine":   max1(f.EndLine),
					},
				},
			}},
		})
	}

	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "gatehouse",
					"informationUri": "https://gatehouse.dev",
					"rules":          rulesOrEmpty(rules),
				},
			},
			"results": resultsOrEmpty(results),
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func ruleProperties(f model.Finding) map[string]any {
	p := map[string]any{}
	if len(f.CWEIDs) > 0 {
		p["tags"] = f.CWEIDs
	}
	if f.CVSS > 0 {
		// GitHub reads security-severity as a 0-10 numeric string.
		p["security-severity"] = formatFloat(f.CVSS)
	}
	return p
}

func severityToLevel(s model.Severity) string {
	switch s {
	case model.SevCritical, model.SevHigh:
		return "error"
	case model.SevMedium:
		return "warning"
	case model.SevLow, model.SevInfo:
		return "note"
	default:
		return "none"
	}
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func rulesOrEmpty(r []map[string]any) []map[string]any {
	if r == nil {
		return []map[string]any{}
	}
	return r
}

func resultsOrEmpty(r []map[string]any) []map[string]any {
	if r == nil {
		return []map[string]any{}
	}
	return r
}

func formatFloat(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

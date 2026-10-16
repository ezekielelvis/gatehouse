package findings

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/gatehouse/gatehouse/internal/model"
)

// Minimal SARIF 2.1.0 structures — just the subset Gatehouse ingests. SARIF is
// the lingua franca of modern scanners (Opengrep, Gitleaks, gosec, …); tools
// that don't speak it get a dedicated adapter instead.
type sarifLog struct {
	Runs []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID         string `json:"id"`
	Properties struct {
		Tags             []string `json:"tags"`
		SecuritySeverity string   `json:"security-severity"`
		Problem          struct {
			Severity string `json:"severity"`
		} `json:"problem"`
	} `json:"properties"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Properties map[string]any `json:"properties"`
	Locations  []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
				Snippet   struct {
					Text string `json:"text"`
				} `json:"snippet"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

// SARIFOptions controls how a SARIF document maps onto the normalised model,
// since SARIF itself carries no notion of Gatehouse's check families.
type SARIFOptions struct {
	// Family is applied to every finding from this document (a given plugin
	// produces one family, declared in its manifest).
	Family model.Family
	// Tool overrides the tool name; if empty the SARIF driver name is used.
	Tool string
}

// ParseSARIF reads a SARIF 2.1.0 log and returns normalised findings with
// fingerprints assigned.
func ParseSARIF(r io.Reader, opts SARIFOptions) ([]model.Finding, error) {
	var log sarifLog
	if err := json.NewDecoder(r).Decode(&log); err != nil {
		return nil, fmt.Errorf("decode sarif: %w", err)
	}

	var out []model.Finding
	for _, run := range log.Runs {
		toolName := opts.Tool
		if toolName == "" {
			toolName = run.Tool.Driver.Name
		}
		rules := indexRules(run.Tool.Driver.Rules)

		for _, res := range run.Results {
			f := model.Finding{
				Family:  familyOr(opts.Family, model.FamilyUnknown),
				RuleID:  res.RuleID,
				Tool:    toolName,
				Message: res.Message.Text,
			}

			rule := rules[res.RuleID]
			f.Severity = severityFor(res, rule)
			f.CWEIDs = cweFrom(rule)

			if len(res.Locations) > 0 {
				loc := res.Locations[0].PhysicalLocation
				f.Path = loc.ArtifactLocation.URI
				f.StartLine = loc.Region.StartLine
				f.EndLine = loc.Region.EndLine
				if f.EndLine == 0 {
					f.EndLine = f.StartLine
				}
				f.Snippet = loc.Region.Snippet.Text
			}

			f.Fingerprint = Fingerprint(f)
			out = append(out, f)
		}
	}
	return out, nil
}

func indexRules(rules []sarifRule) map[string]sarifRule {
	m := make(map[string]sarifRule, len(rules))
	for _, r := range rules {
		m[r.ID] = r
	}
	return m
}

// severityFor resolves a finding's severity from, in order of preference:
// the result's own level, a GitHub-style numeric security-severity on the
// rule, the rule's problem.severity tag, then the rule default level.
func severityFor(res sarifResult, rule sarifRule) model.Severity {
	if s := levelToSeverity(res.Level); s != model.SevUnknown {
		return s
	}
	if n := rule.Properties.SecuritySeverity; n != "" {
		return numericSecuritySeverity(n)
	}
	if s := problemToSeverity(rule.Properties.Problem.Severity); s != model.SevUnknown {
		return s
	}
	return levelToSeverity(rule.DefaultConfiguration.Level)
}

// levelToSeverity maps SARIF levels (error/warning/note/none) onto the model.
func levelToSeverity(level string) model.Severity {
	switch level {
	case "error":
		return model.SevHigh
	case "warning":
		return model.SevMedium
	case "note":
		return model.SevLow
	case "none":
		return model.SevInfo
	default:
		return model.SevUnknown
	}
}

func problemToSeverity(s string) model.Severity {
	switch s {
	case "error", "critical":
		return model.SevHigh
	case "warning", "recommendation":
		return model.SevMedium
	default:
		return model.SevUnknown
	}
}

// numericSecuritySeverity maps a GitHub security-severity (CVSS-like 0-10) onto
// the model's bands.
func numericSecuritySeverity(s string) model.Severity {
	var v float64
	if _, err := fmt.Sscanf(s, "%g", &v); err != nil {
		return model.SevUnknown
	}
	switch {
	case v >= 9.0:
		return model.SevCritical
	case v >= 7.0:
		return model.SevHigh
	case v >= 4.0:
		return model.SevMedium
	case v > 0:
		return model.SevLow
	default:
		return model.SevInfo
	}
}

func cweFrom(rule sarifRule) []string {
	var out []string
	for _, tag := range rule.Properties.Tags {
		if len(tag) > 4 && (tag[:4] == "CWE-" || tag[:4] == "cwe-") {
			out = append(out, tag)
		}
	}
	return out
}

func familyOr(f, fallback model.Family) model.Family {
	if f == "" {
		return fallback
	}
	return f
}

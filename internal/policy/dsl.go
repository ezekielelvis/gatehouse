package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gatehouse/gatehouse/internal/model"
	"gopkg.in/yaml.v3"
)

// The YAML rule DSL (plan §9) lets non-experts write gates without learning
// Rego. Rules are structured (not free-text expressions) and compiled to Rego,
// so they run through the same embedded OPA engine and layering as hand-written
// policy — there is exactly one evaluator.
//
// Example .gatehouse/policies/rules.yaml:
//
//	rules:
//	  - id: no-new-high-vulns
//	    action: deny
//	    contexts: [pre-push, release]
//	    match: { type: vulnerability, status: new, min_severity: high }
//	    message: "New high/critical vulnerable dependency"
//	  - id: changed-lines-coverage
//	    action: warn
//	    metric: { key: coverage.changed_lines, below: 80 }
//	    message: "Changed-lines coverage below 80%"
//	  - id: forbidden-licences
//	    action: deny
//	    forbidden_licenses: [AGPL-3.0-only, SSPL-1.0]
//	    message: "Forbidden dependency licence"

// RuleSet is a parsed DSL document.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// Rule is one declarative gate.
type Rule struct {
	ID       string   `yaml:"id"`
	Action   string   `yaml:"action"` // deny | warn
	Contexts []string `yaml:"contexts"`
	Message  string   `yaml:"message"`

	// Exactly one of the following selectors should be set.
	Match             *MatchRule  `yaml:"match"`
	Metric            *MetricRule `yaml:"metric"`
	ForbiddenLicenses []string    `yaml:"forbidden_licenses"`
}

// MatchRule selects findings; the rule fires when more than Threshold match.
type MatchRule struct {
	Type        string `yaml:"type"`
	Status      string `yaml:"status"`
	MinSeverity string `yaml:"min_severity"`
	Threshold   int    `yaml:"threshold"`
}

// MetricRule fires when a metric is below a value.
type MetricRule struct {
	Key   string  `yaml:"key"`
	Below float64 `yaml:"below"`
}

// CompileDSL parses a DSL document and compiles it to a Rego Module in package
// gatehouse.gates.
func CompileDSL(name string, data []byte) (Module, error) {
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return Module{}, fmt.Errorf("parse rules: %w", err)
	}
	var b strings.Builder
	b.WriteString("package gatehouse.gates\n\nimport rego.v1\n")
	for _, r := range rs.Rules {
		block, err := compileRule(r)
		if err != nil {
			return Module{}, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		b.WriteString("\n")
		b.WriteString(block)
	}
	return Module{Name: name, Source: b.String()}, nil
}

func compileRule(r Rule) (string, error) {
	action := r.Action
	if action != "deny" && action != "warn" {
		return "", fmt.Errorf("action must be deny or warn, got %q", action)
	}
	msg := r.Message
	if msg == "" {
		msg = r.ID
	}

	switch {
	case r.Match != nil:
		return compileMatch(action, r, msg)
	case r.Metric != nil:
		return compileMetric(action, r, msg)
	case len(r.ForbiddenLicenses) > 0:
		return compileLicenses(action, r, msg)
	default:
		return "", fmt.Errorf("rule has no selector (match, metric, or forbidden_licenses)")
	}
}

func compileMatch(action string, r Rule, msg string) (string, error) {
	var conds []string
	if r.Match.Type != "" {
		conds = append(conds, fmt.Sprintf(`f.type == %s`, strconv.Quote(r.Match.Type)))
	}
	if r.Match.Status != "" {
		conds = append(conds, fmt.Sprintf(`f.status == %s`, strconv.Quote(r.Match.Status)))
	}
	if r.Match.MinSeverity != "" {
		sev := model.ParseSeverity(r.Match.MinSeverity)
		if sev == model.SevUnknown {
			return "", fmt.Errorf("unknown min_severity %q", r.Match.MinSeverity)
		}
		conds = append(conds, fmt.Sprintf(`f.severity_n >= %d`, int(sev)))
	}
	conds = append(conds, "not f.waived")

	// count comprehension over matching findings.
	comp := fmt.Sprintf("[f | some f in input.findings; %s]", strings.Join(conds, "; "))
	var b strings.Builder
	fmt.Fprintf(&b, "%s contains msg if {\n", action)
	for _, g := range topLevelContextGuard(r.Contexts) {
		fmt.Fprintf(&b, "\t%s\n", g)
	}
	fmt.Fprintf(&b, "\tn := count(%s)\n", comp)
	fmt.Fprintf(&b, "\tn > %d\n", r.Match.Threshold)
	fmt.Fprintf(&b, "\tmsg := sprintf(%s, [n])\n", strconv.Quote(msg+" (%d matching)"))
	b.WriteString("}\n")
	return b.String(), nil
}

func compileMetric(action string, r Rule, msg string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s contains msg if {\n", action)
	for _, g := range topLevelContextGuard(r.Contexts) {
		fmt.Fprintf(&b, "\t%s\n", g)
	}
	fmt.Fprintf(&b, "\tinput.metrics[%s] < %s\n", strconv.Quote(r.Metric.Key), formatNum(r.Metric.Below))
	fmt.Fprintf(&b, "\tmsg := %s\n", strconv.Quote(msg))
	b.WriteString("}\n")
	return b.String(), nil
}

func compileLicenses(action string, r Rule, msg string) (string, error) {
	quoted := make([]string, len(r.ForbiddenLicenses))
	for i, l := range r.ForbiddenLicenses {
		quoted[i] = strconv.Quote(l)
	}
	set := "{" + strings.Join(quoted, ", ") + "}"
	var b strings.Builder
	fmt.Fprintf(&b, "%s contains msg if {\n", action)
	for _, g := range topLevelContextGuard(r.Contexts) {
		fmt.Fprintf(&b, "\t%s\n", g)
	}
	fmt.Fprintf(&b, "\tsome c in input.sbom.components\n")
	fmt.Fprintf(&b, "\tc.license in %s\n", set)
	fmt.Fprintf(&b, "\tmsg := sprintf(%s, [c.name, c.license])\n", strconv.Quote(msg+" (%s: %s)"))
	b.WriteString("}\n")
	return b.String(), nil
}

// topLevelContextGuard renders an optional context restriction as a top-level
// condition of the rule body.
func topLevelContextGuard(contexts []string) []string {
	if len(contexts) == 0 {
		return nil
	}
	quoted := make([]string, len(contexts))
	for i, c := range contexts {
		quoted[i] = strconv.Quote(c)
	}
	return []string{fmt.Sprintf("input.context in {%s}", strings.Join(quoted, ", "))}
}

func formatNum(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// LoadRepoPolicies loads the repo-level policy layer from
// <repoDir>/.gatehouse/policies: every *.rego file verbatim and every *.yaml
// file compiled from the DSL. Returns nil when the directory is absent.
func LoadRepoPolicies(repoDir string) ([]Module, error) {
	dir := filepath.Join(repoDir, ".gatehouse", "policies")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // deterministic module order

	var mods []Module
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		switch strings.ToLower(filepath.Ext(name)) {
		case ".rego":
			mods = append(mods, Module{Name: name, Source: string(data)})
		case ".yaml", ".yml":
			m, err := CompileDSL(name+".rego", data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			mods = append(mods, m)
		}
	}
	return mods, nil
}

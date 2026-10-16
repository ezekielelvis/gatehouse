// Package standards maps normalised findings onto recognised security
// standards (plan §7). The mechanism is deliberately simple and auditable:
// every finding carries CWE IDs, and versioned mapping files translate CWE and
// check IDs into standard controls. Gatehouse never claims a team is
// "compliant" — it produces mapped evidence and states plainly which controls
// still need human attestation.
package standards

import (
	"fmt"

	"github.com/gatehouse/gatehouse/internal/model"
	"gopkg.in/yaml.v3"
)

// Automatable describes how much of a control Gatehouse can evidence on its own.
type Automatable string

const (
	AutoYes     Automatable = "yes"
	AutoPartial Automatable = "partial"
	AutoNo      Automatable = "no"
)

// Evidence names how a control is evaluated.
type Evidence string

const (
	// EvidenceAbsence (the default) is weakness evidence: the control is met
	// when no open finding maps to it. Suits OWASP/CWE-style catalogues.
	EvidenceAbsence Evidence = "absence"
	// EvidenceActivity is process evidence: the control is met when a required
	// analysis actually ran (a check executed successfully, or a run signal
	// such as tests/SBOM is present). Suits SSDF/SLSA-style practices, where
	// "we performed static analysis" matters, not "zero findings".
	EvidenceActivity Evidence = "activity"
)

// Control is one requirement within a standard.
type Control struct {
	ID          string      `yaml:"id"`
	Title       string      `yaml:"title"`
	Automatable Automatable `yaml:"automatable"`
	Evidence    Evidence    `yaml:"evidence"` // default: absence
	CWEs        []string    `yaml:"cwes"`
	Checks      []string    `yaml:"checks"`   // specific rule/plugin IDs
	Families    []string    `yaml:"families"` // finding families (e.g. vulnerability, secret)
	Signals     []string    `yaml:"signals"`  // activity signals: tests, sbom
}

// Standard is a parsed mapping file.
type Standard struct {
	ID       string    `yaml:"id"`
	Title    string    `yaml:"title"`
	Version  string    `yaml:"version"`
	Controls []Control `yaml:"controls"`
}

// Parse decodes a standard mapping document.
func Parse(data []byte) (*Standard, error) {
	var s Standard
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse standard: %w", err)
	}
	if s.ID == "" || len(s.Controls) == 0 {
		return nil, fmt.Errorf("standard: id and at least one control are required")
	}
	return &s, nil
}

// Status is the evaluated state of one control against a run.
type Status string

const (
	StatusMet           Status = "met"            // automatable and no open finding maps to it
	StatusNotMet        Status = "not_met"        // an open finding maps to it
	StatusManual        Status = "manual"         // requires human attestation
	StatusNotApplicable Status = "not_applicable" // no evidence source applies to this repo
)

// ControlResult pairs a control with its evaluated status and the findings that
// drove a not_met result.
type ControlResult struct {
	Control  Control
	Status   Status
	Findings []model.Finding
}

// Report is the result of evaluating a whole standard against a run.
type Report struct {
	Standard string
	Title    string
	Version  string
	Results  []ControlResult
}

// Counts tallies results by status for a summary line.
func (r Report) Counts() map[Status]int {
	m := map[Status]int{}
	for _, cr := range r.Results {
		m[cr.Status]++
	}
	return m
}

// Evaluate maps a run's open findings onto the standard's controls. A finding
// is "open" if it is not fixed and not waived; a control is not_met if any open
// finding maps to it (by CWE, check/rule ID, or family). Controls marked
// automatable: no are reported as manual, never auto-passed.
func Evaluate(std *Standard, run model.Run) Report {
	open := openFindings(run.Findings)
	ran := runSignals(run)
	rep := Report{Standard: std.ID, Title: std.Title, Version: std.Version}

	for _, c := range std.Controls {
		cr := ControlResult{Control: c}
		switch {
		case c.Automatable == AutoNo:
			cr.Status = StatusManual
		case c.Evidence == EvidenceActivity:
			cr.Status = activityStatus(c, ran)
		default: // absence
			if matched := matchingFindings(c, open); len(matched) > 0 {
				cr.Status = StatusNotMet
				cr.Findings = matched
			} else {
				cr.Status = StatusMet
			}
		}
		rep.Results = append(rep.Results, cr)
	}
	return rep
}

// signals captures what evidence a run produced, for activity-mode controls.
type signals struct {
	ranOK   map[string]bool // plugin IDs that ran without error
	errored map[string]bool // plugin IDs that ran but errored
	tests   bool
	sbom    bool
}

func runSignals(run model.Run) signals {
	s := signals{ranOK: map[string]bool{}, errored: map[string]bool{}}
	for _, step := range run.Steps {
		if step.Errored {
			s.errored[step.PluginID] = true
		} else {
			s.ranOK[step.PluginID] = true
		}
	}
	s.tests = len(run.Tests) > 0
	s.sbom = len(run.SBOM) > 0
	return s
}

// activityStatus decides an activity-evidence control: met if any required
// check ran successfully or any required signal is present; not_met if a
// required check was attempted but errored (the analysis ran but failed);
// otherwise manual (no evidence was produced, so a human must attest).
func activityStatus(c Control, s signals) Status {
	attempted := false
	for _, chk := range c.Checks {
		if s.ranOK[chk] {
			return StatusMet
		}
		if s.errored[chk] {
			attempted = true
		}
	}
	for _, sig := range c.Signals {
		if (sig == "tests" && s.tests) || (sig == "sbom" && s.sbom) {
			return StatusMet
		}
	}
	if attempted {
		return StatusNotMet
	}
	return StatusManual
}

func matchingFindings(c Control, open []model.Finding) []model.Finding {
	cweSet := toSet(c.CWEs)
	checkSet := toSet(c.Checks)
	famSet := toSet(c.Families)
	var out []model.Finding
	for _, f := range open {
		if checkSet[f.RuleID] || famSet[string(f.Family)] || anyIn(f.CWEIDs, cweSet) {
			out = append(out, f)
		}
	}
	return out
}

func openFindings(fs []model.Finding) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Status == model.StatusFixed || f.WaiverID != "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func anyIn(vals []string, set map[string]bool) bool {
	for _, v := range vals {
		if set[v] {
			return true
		}
	}
	return false
}

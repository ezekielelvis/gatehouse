// Package model defines Gatehouse's normalised, cross-tool data model.
//
// Everything a scanner, test runner or policy produces is reduced to one of a
// small set of types here — chiefly Finding — so that policies can reason
// uniformly across lint errors, CVEs, failing tests and policy violations.
package model

import "time"

// Severity is the normalised severity scale used across all tools. Scanners
// emit many different vocabularies (SARIF levels, CVSS bands, "HIGH"/"warning"
// /"blocker"); adapters map them all onto this ordered set.
type Severity int

const (
	SevUnknown Severity = iota
	SevInfo
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var severityNames = map[Severity]string{
	SevUnknown:  "unknown",
	SevInfo:     "info",
	SevLow:      "low",
	SevMedium:   "medium",
	SevHigh:     "high",
	SevCritical: "critical",
}

var severityByName = func() map[string]Severity {
	m := make(map[string]Severity, len(severityNames))
	for k, v := range severityNames {
		m[v] = k
	}
	return m
}()

func (s Severity) String() string { return severityNames[s] }

// ParseSeverity resolves a severity name (case-insensitive) to a Severity,
// returning SevUnknown for anything unrecognised.
func ParseSeverity(name string) Severity {
	if s, ok := severityByName[lower(name)]; ok {
		return s
	}
	return SevUnknown
}

// Status is a finding's lifecycle relative to the diff base: whether it was
// introduced by the change under scan, pre-existed it, or was fixed by it.
type Status string

const (
	StatusNew      Status = "new"
	StatusExisting Status = "existing"
	StatusFixed    Status = "fixed"
)

// Family groups a finding by the kind of check that produced it. Policies and
// the UI pivot on this.
type Family string

const (
	FamilySAST      Family = "sast"
	FamilySecret    Family = "secret"
	FamilyVuln      Family = "vulnerability" // SCA / dependency CVE
	FamilyLicense   Family = "license"
	FamilyIaC       Family = "iac"
	FamilyContainer Family = "container"
	FamilyQuality   Family = "quality" // lint / format / complexity
	FamilyTest      Family = "test"    // failing test surfaced as a finding
	FamilyPosture   Family = "posture" // repo hygiene / commit integrity
	FamilyCICD      Family = "cicd"
	FamilyUnknown   Family = "unknown"
)

// Finding is the single normalised unit that every analyzer produces.
type Finding struct {
	// Fingerprint is a stable identity used to diff a finding across runs even
	// when unrelated lines move. See findings.Fingerprint.
	Fingerprint string `json:"fingerprint"`

	Family   Family   `json:"family"`
	RuleID   string   `json:"rule_id"`
	Tool     string   `json:"tool"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`

	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Snippet   string `json:"snippet,omitempty"`

	// Enrichment (populated by internal/enrich from local mirrors).
	CWEIDs     []string `json:"cwe_ids,omitempty"`
	CVSS       float64  `json:"cvss,omitempty"`
	EPSS       float64  `json:"epss,omitempty"`
	KEV        bool     `json:"kev,omitempty"`
	FixVersion string   `json:"fix_version,omitempty"`

	Status   Status `json:"status"`
	WaiverID string `json:"waiver_id,omitempty"`
}

// Severable exposes the fields the fingerprinter and severity comparisons need.
func (f Finding) SeverityAtLeast(min Severity) bool { return f.Severity >= min }

// Metric is a single numeric measurement about a run (coverage, complexity,
// duplication, …). Key uses dotted namespaces, e.g. "coverage.changed_lines".
type Metric struct {
	Key   string  `json:"key"`
	Value float64 `json:"value"`
}

// TestResult is one test outcome, normalised from JUnit XML and friends.
type TestResult struct {
	Suite       string        `json:"suite"`
	Name        string        `json:"name"`
	Status      string        `json:"status"` // passed | failed | skipped
	Duration    time.Duration `json:"duration"`
	Retries     int           `json:"retries"`
	Flaky       bool          `json:"flaky"`
	Quarantined bool          `json:"quarantined"`
}

// Component is one entry in the SBOM.
type Component struct {
	PURL    string   `json:"purl"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	License string   `json:"license"`
	Hashes  []string `json:"hashes,omitempty"`
	Direct  bool     `json:"direct"`
}

// RepoProfile is the result of language/manifest detection, stored with the run
// and used to select which plugins apply.
type RepoProfile struct {
	Languages []string `json:"languages"`
	Manifests []string `json:"manifests"`
}

// HasLanguage reports whether the profile detected the given language (case-insensitive).
func (p RepoProfile) HasLanguage(lang string) bool {
	for _, l := range p.Languages {
		if lower(l) == lower(lang) {
			return true
		}
	}
	return false
}

// Context is the gate profile under which a run executes.
type Context string

const (
	ContextPreCommit Context = "pre-commit"
	ContextPrePush   Context = "pre-push"
	ContextRelease   Context = "release"
)

// Verdict is the overall policy decision for a run.
type Verdict string

const (
	VerdictPass Verdict = "pass"
	VerdictWarn Verdict = "warn"
	VerdictFail Verdict = "fail"
)

// Run is the top-level record of one scan.
type Run struct {
	ID         string      `json:"id"`
	RepoPath   string      `json:"repo_path"`
	Ref        string      `json:"ref"`
	TreeHash   string      `json:"tree_hash"`
	BaseRef    string      `json:"base_ref,omitempty"`
	Context    Context     `json:"context"`
	Profile    RepoProfile `json:"profile"`
	Verdict    Verdict     `json:"verdict"`
	Status     string      `json:"status"` // running | done | error
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at,omitempty"`

	Findings []Finding    `json:"findings,omitempty"`
	Metrics  []Metric     `json:"metrics,omitempty"`
	Tests    []TestResult `json:"tests,omitempty"`
	SBOM     []Component  `json:"sbom,omitempty"`

	Steps []Step `json:"steps,omitempty"`
}

// Step records the execution of one plugin within a run.
type Step struct {
	PluginID    string        `json:"plugin_id"`
	ImageDigest string        `json:"image_digest"`
	ExitCode    int           `json:"exit_code"`
	Duration    time.Duration `json:"duration"`
	Errored     bool          `json:"errored"`
	Error       string        `json:"error,omitempty"`
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

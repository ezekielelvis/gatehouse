// Package ui serves Gatehouse's local web interface (plan §11). It renders
// server-side with Go's html/template, uses htmx (vendored and served locally)
// for interactivity, and ships entirely inside the binary via go:embed so it
// works offline. Everything the UI shows is also available via the JSON API and
// the CLI.
//
// Security: the server is meant to bind to 127.0.0.1 only; the handler stack in
// cmd/gatehouse/serve.go adds the Host-header (DNS-rebinding) guard, and every
// response here carries a strict CSP that permits only same-origin assets — no
// third-party scripts, styles or fonts.
package ui

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/standards"
	"github.com/gatehouse/gatehouse/internal/store"
	"github.com/gatehouse/gatehouse/policies"
	standardsdata "github.com/gatehouse/gatehouse/standards"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server renders the UI against a store.
type Server struct {
	store *store.Store
	tmpl  *template.Template
	meta  Settings
}

// New parses the embedded templates and returns a Server.
func New(st *store.Store) (*Server, error) {
	t, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{store: st, tmpl: t}, nil
}

// Routes registers the UI handlers on mux. The caller wraps mux with the
// localhost/Host-header guard.
func (s *Server) Routes(mux *http.ServeMux) {
	staticFS, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler(http.FS(staticFS))))
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /runs/{id}", s.runDetail)
	mux.HandleFunc("GET /runs/{id}/findings", s.findingsPartial)
	mux.HandleFunc("GET /runs/{id}/compliance", s.compliancePartial)
	mux.HandleFunc("GET /history", s.history)
	mux.HandleFunc("GET /waivers", s.waivers)
	mux.HandleFunc("GET /policies", s.policiesPage)
	mux.HandleFunc("GET /settings", s.settings)
}

// Settings is optional display metadata injected by the serve command.
type Settings struct {
	BindAddr   string
	DBPath     string
	MirrorPath string
	KeyID      string
	RetainPer  int
}

// SetMeta supplies read-only settings shown on the Settings page.
func (s *Server) SetMeta(m Settings) { s.meta = m }

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	sums, err := s.store.RunSummaries(100)
	if err != nil {
		httpError(w, err)
		return
	}
	type row struct {
		ID, Repo, Verdict, Started, Coverage string
		New, BarPx                           int
	}
	rows := make([]row, 0, len(sums))
	for _, su := range sums {
		cov := "—"
		if su.CoverageChanged >= 0 {
			cov = fmt.Sprintf("%.0f%%", su.CoverageChanged)
		}
		bar := su.NewFindings * 12
		if bar > 240 {
			bar = 240
		}
		rows = append(rows, row{
			ID: su.Run.ID, Repo: filepath.Base(su.Run.RepoPath),
			Verdict: string(su.Run.Verdict), Started: su.Run.StartedAt.Format("2006-01-02 15:04"),
			Coverage: cov, New: su.NewFindings, BarPx: bar,
		})
	}
	s.render(w, "history", map[string]any{"Title": "History", "Rows": rows})
}

func (s *Server) waivers(w http.ResponseWriter, r *http.Request) {
	fs, err := s.store.WaivedFindings(200)
	if err != nil {
		httpError(w, err)
		return
	}
	s.render(w, "waivers", map[string]any{"Title": "Waivers", "Findings": fs})
}

func (s *Server) policiesPage(w http.ResponseWriter, r *http.Request) {
	roles := map[string]string{
		"baseline":       "Default gate: new secrets, new high/critical CVEs, failing tests",
		"strict-release": "Release gate: promotes warnings to blocks, forbids copyleft, blocks criticals",
		"owasp-top10":    "Blocks new findings mapped to OWASP Top 10 categories (by CWE)",
		"oss-library":    "Clean licence posture + SBOM for an open-source library",
		"iac-hardening":  "Gate on IaC/container misconfigurations",
	}
	names, _ := policies.List()
	type pack struct{ Name, Role string }
	packs := make([]pack, 0, len(names))
	for _, n := range names {
		packs = append(packs, pack{Name: n, Role: roles[n]})
	}
	s.render(w, "policies", map[string]any{"Title": "Policies", "Packs": packs})
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	type kv struct{ K, V string }
	settings := []kv{
		{"UI bind address", s.meta.BindAddr},
		{"Database", s.meta.DBPath},
		{"Vulnerability mirror", s.meta.MirrorPath},
		{"Signing key id", s.meta.KeyID},
		{"Default retention (runs/branch)", fmt.Sprintf("%d", s.meta.RetainPer)},
	}
	s.render(w, "settings", map[string]any{"Title": "Settings", "Settings": settings})
}

// --- Dashboard --------------------------------------------------------------

type runRow struct {
	ID        string
	RepoShort string
	Context   model.Context
	Verdict   model.Verdict
	Started   string
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.RecentRuns(100)
	if err != nil {
		httpError(w, err)
		return
	}
	rows := make([]runRow, 0, len(runs))
	for _, run := range runs {
		rows = append(rows, runRow{
			ID:        run.ID,
			RepoShort: filepath.Base(run.RepoPath),
			Context:   run.Context,
			Verdict:   run.Verdict,
			Started:   run.StartedAt.Format("2006-01-02 15:04"),
		})
	}
	s.render(w, "dashboard", map[string]any{"Title": "Dashboard", "Runs": rows})
}

// --- Run detail -------------------------------------------------------------

type runView struct {
	Title           string
	Run             *model.Run
	Deny            []string
	Warn            []string
	Findings        []model.Finding
	Families        []string
	Standards       []string
	NewCount        int
	TestsPassed     int
	CoverageChanged string
	Compliance      complianceView
}

func (s *Server) runDetail(w http.ResponseWriter, r *http.Request) {
	run, deny, warn, err := s.store.GetRun(r.PathValue("id"))
	if err != nil {
		httpError(w, err)
		return
	}
	if run == nil {
		http.NotFound(w, r)
		return
	}
	stds, _ := standardsdata.List()
	defaultStd := "owasp-top10"
	if len(stds) > 0 && !contains(stds, defaultStd) {
		defaultStd = stds[0]
	}

	v := runView{
		Title:           "Run " + run.ID,
		Run:             run,
		Deny:            deny,
		Warn:            warn,
		Findings:        sortFindings(filterFindings(run.Findings, "", "", "")),
		Families:        familiesOf(run.Findings),
		Standards:       stds,
		NewCount:        countStatus(run.Findings, model.StatusNew),
		TestsPassed:     countTestStatus(run.Tests, "passed"),
		CoverageChanged: coverageStr(run.Metrics, "coverage.changed_lines"),
		Compliance:      s.evalCompliance(run, defaultStd),
	}
	s.render(w, "run", v)
}

func (s *Server) findingsPartial(w http.ResponseWriter, r *http.Request) {
	run, _, _, err := s.store.GetRun(r.PathValue("id"))
	if err != nil || run == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	fs := sortFindings(filterFindings(run.Findings, q.Get("family"), q.Get("severity"), q.Get("status")))
	s.render(w, "findings_rows", map[string]any{"Findings": fs})
}

// --- Compliance -------------------------------------------------------------

type complianceRow struct {
	ID, Title, Label, Class, Detail string
}

type complianceView struct {
	Rows    []complianceRow
	Summary string
}

func (s *Server) compliancePartial(w http.ResponseWriter, r *http.Request) {
	run, _, _, err := s.store.GetRun(r.PathValue("id"))
	if err != nil || run == nil {
		http.NotFound(w, r)
		return
	}
	cv := s.evalCompliance(run, r.URL.Query().Get("standard"))
	s.render(w, "compliance_table", map[string]any{"Compliance": cv})
}

func (s *Server) evalCompliance(run *model.Run, stdName string) complianceView {
	if stdName == "" {
		stdName = "owasp-top10"
	}
	std, err := standardsdata.Load(stdName)
	if err != nil {
		return complianceView{Summary: "standard unavailable: " + err.Error()}
	}
	rep := standards.Evaluate(std, *run)
	labels := map[standards.Status][2]string{
		standards.StatusMet:           {"✓ met", "pass"},
		standards.StatusNotMet:        {"✗ not met", "fail"},
		standards.StatusManual:        {"– manual", "muted"},
		standards.StatusNotApplicable: {"· n/a", "muted"},
	}
	var rows []complianceRow
	for _, cr := range rep.Results {
		lbl := labels[cr.Status]
		detail := ""
		if cr.Status == standards.StatusNotMet {
			if len(cr.Findings) > 0 {
				detail = fmt.Sprintf("%d finding(s)", len(cr.Findings))
			} else {
				detail = "required analysis did not complete"
			}
		}
		rows = append(rows, complianceRow{
			ID: cr.Control.ID, Title: cr.Control.Title,
			Label: lbl[0], Class: lbl[1], Detail: detail,
		})
	}
	c := rep.Counts()
	return complianceView{
		Rows:    rows,
		Summary: fmt.Sprintf("%s %s: %d met · %d not met · %d manual", rep.Title, rep.Version, c[standards.StatusMet], c[standards.StatusNotMet], c[standards.StatusManual]),
	}
}

// --- helpers ----------------------------------------------------------------

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'self'")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		httpError(w, err)
	}
}

func filterFindings(fs []model.Finding, family, severity, status string) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if family != "" && string(f.Family) != family {
			continue
		}
		if severity != "" && f.Severity.String() != severity {
			continue
		}
		if status != "" && string(f.Status) != status {
			continue
		}
		out = append(out, f)
	}
	return out
}

func sortFindings(fs []model.Finding) []model.Finding {
	out := append([]model.Finding(nil), fs...)
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Status == model.StatusNew) != (out[j].Status == model.StatusNew) {
			return out[i].Status == model.StatusNew
		}
		return out[i].Severity > out[j].Severity
	})
	return out
}

func familiesOf(fs []model.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if s := string(f.Family); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func countStatus(fs []model.Finding, st model.Status) int {
	n := 0
	for _, f := range fs {
		if f.Status == st {
			n++
		}
	}
	return n
}

func countTestStatus(ts []model.TestResult, st string) int {
	n := 0
	for _, t := range ts {
		if t.Status == st {
			n++
		}
	}
	return n
}

func coverageStr(ms []model.Metric, key string) string {
	for _, m := range ms {
		if m.Key == key {
			return fmt.Sprintf("%.0f%%", m.Value)
		}
	}
	return "—"
}

func contains(ss []string, s string) bool { return slices.Contains(ss, s) }

func httpError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func staticHandler(fsys http.FileSystem) http.Handler {
	fileServer := http.FileServer(fsys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Long-cache the immutable vendored assets.
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		fileServer.ServeHTTP(w, r)
	})
}

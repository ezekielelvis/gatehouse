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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/standards"
	"github.com/gatehouse/gatehouse/internal/store"
	"github.com/gatehouse/gatehouse/policies"
	standardsdata "github.com/gatehouse/gatehouse/standards"
)

//go:embed templates/*.html static/*
var assets embed.FS

// ScanFunc triggers a scan. serve injects an implementation backed by the
// orchestrator; the UI stays decoupled from it. progress receives human-readable
// step lines as the scan runs.
type ScanFunc func(runID, repoPath, ref, context string, progress func(string)) error

// Server renders the UI against a store.
type Server struct {
	store *store.Store
	tmpl  *template.Template
	meta  Settings

	scan       ScanFunc
	progressMu sync.Mutex
	progress   map[string][]string
}

// New parses the embedded templates and returns a Server.
func New(st *store.Store) (*Server, error) {
	t, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{store: st, tmpl: t, progress: map[string][]string{}}, nil
}

// SetRunner enables the "run a scan from the UI" feature. Without it, the
// Projects page still lists repos but the run buttons are disabled.
func (s *Server) SetRunner(fn ScanFunc) { s.scan = fn }

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
	mux.HandleFunc("GET /projects", s.projects)
	mux.HandleFunc("POST /projects", s.addProject)
	mux.HandleFunc("POST /projects/{id}/scan", s.runScan)
	mux.HandleFunc("GET /runs/{id}/live", s.runLive)
}

// --- Projects & scanning ----------------------------------------------------

func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	repos, err := s.store.ListRepos()
	if err != nil {
		httpError(w, err)
		return
	}
	type projRow struct {
		ID          int64
		Name, Path  string
		LastRun     string
		LastVerdict string
	}
	rows := make([]projRow, 0, len(repos))
	for _, rp := range repos {
		pr := projRow{ID: rp.ID, Name: rp.Name, Path: rp.Path}
		if last := s.store.LatestRunForRepo(rp.Path); last != "" {
			if st, v, err := s.store.RunStatus(last); err == nil {
				pr.LastRun = last
				pr.LastVerdict = firstNonEmpty(string(v), st)
			}
		}
		rows = append(rows, pr)
	}
	s.render(w, "projects", map[string]any{
		"Title": "Projects", "Repos": rows, "CanRun": s.scan != nil,
	})
}

func (s *Server) addProject(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpError(w, err)
		return
	}
	path := strings.TrimSpace(r.FormValue("path"))
	if path == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = filepath.Base(path)
	}
	if _, err := s.store.AddRepo(path, name); err != nil {
		httpError(w, err)
		return
	}
	http.Redirect(w, r, "/projects", http.StatusSeeOther)
}

func (s *Server) runScan(w http.ResponseWriter, r *http.Request) {
	if s.scan == nil {
		http.Error(w, "scanning is not enabled on this server", http.StatusServiceUnavailable)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	repo, err := s.store.GetRepo(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctxName := r.FormValue("profile")
	if ctxName == "" {
		ctxName = "pre-push"
	}
	runID := time.Now().UTC().Format("20060102T150405") + "-ui"

	if err := s.store.InsertRunningRun(runID, repo.Path, "working-tree", model.Context(ctxName)); err != nil {
		httpError(w, err)
		return
	}
	s.progressMu.Lock()
	s.progress[runID] = []string{"queued…"}
	s.progressMu.Unlock()

	go func() {
		prog := func(line string) {
			s.progressMu.Lock()
			s.progress[runID] = append(s.progress[runID], line)
			s.progressMu.Unlock()
		}
		if err := s.scan(runID, repo.Path, ctxName, "", prog); err != nil {
			prog("error: " + err.Error())
		}
	}()

	http.Redirect(w, r, "/runs/"+runID, http.StatusSeeOther)
}

// runLive is polled by the live run page. While the scan runs it returns the
// progress lines; once it finishes it tells htmx to redirect to the full run.
func (s *Server) runLive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	status, _, err := s.store.RunStatus(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if status != "running" {
		w.Header().Set("HX-Redirect", "/runs/"+id) // scan finished → load the report
		w.WriteHeader(http.StatusOK)
		return
	}
	s.progressMu.Lock()
	lines := append([]string(nil), s.progress[id]...)
	s.progressMu.Unlock()
	s.render(w, "progress_lines", map[string]any{"Lines": lines})
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

	// Headline numbers + a trend sparkline of new findings across recent runs.
	sums, _ := s.store.RunSummaries(30)
	var trendVals []float64
	var pass, fail, warn int
	for i := len(sums) - 1; i >= 0; i-- { // oldest → newest for the sparkline
		trendVals = append(trendVals, float64(sums[i].NewFindings))
	}
	for _, su := range sums {
		switch su.Run.Verdict {
		case model.VerdictPass:
			pass++
		case model.VerdictFail:
			fail++
		case model.VerdictWarn:
			warn++
		}
	}
	tiles := []Tile{
		{Label: "Runs", Value: itoa(len(runs))},
		{Label: "Passing", Value: itoa(pass)},
		{Label: "Failing", Value: itoa(fail)},
		{Label: "Warn", Value: itoa(warn)},
	}
	s.render(w, "dashboard", map[string]any{
		"Title": "Dashboard", "Runs": rows, "Tiles": tiles,
		"Trend": sparkline(trendVals, "var(--red)"),
	})
}

// --- Run detail -------------------------------------------------------------

// Tile is a single metric tile rendered by the "tile"/"tiles" components.
type Tile struct {
	Label string
	Value string
}

// FamilyCard is a vivid per-check-family pass/fail summary on the run page.
type FamilyCard struct {
	Name     string
	State    string // pass | fail | warn | idle
	StateMsg string
	Total    int
	New      int
}

type runView struct {
	Title         string
	Run           *model.Run
	Deny          []string
	Warn          []string
	Findings      []model.Finding
	Families      []string
	FamilyCards   []FamilyCard
	SeverityChart template.HTML
	Standards     []string
	Tiles         []Tile
	Compliance    complianceView
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
	if run.Status == "running" {
		s.render(w, "run_running", map[string]any{"Title": "Scanning", "ID": run.ID, "Repo": run.RepoPath})
		return
	}
	stds, _ := standardsdata.List()
	defaultStd := "owasp-top10"
	if len(stds) > 0 && !contains(stds, defaultStd) {
		defaultStd = stds[0]
	}

	tiles := []Tile{
		{Label: "New findings", Value: itoa(countStatus(run.Findings, model.StatusNew))},
		{Label: "Total findings", Value: itoa(len(run.Findings))},
		{Label: "Tests passed", Value: fmt.Sprintf("%d/%d", countTestStatus(run.Tests, "passed"), len(run.Tests))},
		{Label: "Changed-lines cov", Value: coverageStr(run.Metrics, "coverage.changed_lines")},
	}
	v := runView{
		Title:         "Run " + run.ID,
		Run:           run,
		Deny:          deny,
		Warn:          warn,
		Findings:      sortFindings(filterFindings(run.Findings, "", "", "")),
		Families:      familiesOf(run.Findings),
		FamilyCards:   familyCards(run),
		SeverityChart: severityChart(run.Findings),
		Standards:     stds,
		Tiles:         tiles,
		Compliance:    s.evalCompliance(run, defaultStd),
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
		switch cr.Status {
		case standards.StatusNotMet:
			if len(cr.Findings) > 0 {
				detail = fmt.Sprintf("%d finding(s)", len(cr.Findings))
			} else {
				detail = "required analysis did not complete"
			}
		case standards.StatusManual:
			detail = cr.Control.Guidance
			if detail == "" {
				detail = "needs human attestation — Gatehouse can't verify this from a local scan"
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
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'")
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

// familyCards summarises each check family that ran: whether it errored (idle),
// found blocking new issues (fail), found only existing issues (warn), or came
// back clean (pass). It covers both the families that produced findings and the
// families of checks that ran (so a clean SAST run shows a green card).
func familyCards(run *model.Run) []FamilyCard {
	// Which families produced findings, split by new/total.
	type agg struct{ total, new int }
	byFam := map[string]*agg{}
	for _, f := range run.Findings {
		a := byFam[string(f.Family)]
		if a == nil {
			a = &agg{}
			byFam[string(f.Family)] = a
		}
		a.total++
		if f.Status == model.StatusNew {
			a.new++
		}
	}
	// Map plugin ids to families via the step → (we don't keep family on steps,
	// so infer coverage from findings + a tests card from run.Tests).
	order := []string{"secret", "sast", "vulnerability", "iac", "container", "cicd", "license", "quality", "posture"}
	label := map[string]string{
		"secret": "Secrets", "sast": "SAST", "vulnerability": "Dependencies (SCA)",
		"iac": "Infrastructure", "container": "Containers", "cicd": "CI/CD",
		"license": "Licences / SBOM", "quality": "Code quality", "posture": "Repo posture",
	}
	var cards []FamilyCard
	for _, fam := range order {
		a := byFam[fam]
		card := FamilyCard{Name: label[fam]}
		switch {
		case a == nil:
			card.State, card.StateMsg = "pass", "no issues"
		case a.new > 0:
			card.State, card.StateMsg = "fail", fmt.Sprintf("%d new", a.new)
			card.Total, card.New = a.total, a.new
		default:
			card.State, card.StateMsg = "warn", "existing only"
			card.Total = a.total
		}
		// Only show a card for a family that ran (produced findings) or is a
		// core always-on family (secret, sast, vulnerability).
		if a != nil || fam == "secret" || fam == "sast" || fam == "vulnerability" {
			cards = append(cards, card)
		}
	}
	// A tests card.
	if len(run.Tests) > 0 {
		failed := 0
		for _, t := range run.Tests {
			if t.Status == "failed" && !t.Quarantined {
				failed++
			}
		}
		c := FamilyCard{Name: "Tests", Total: len(run.Tests)}
		if failed > 0 {
			c.State, c.StateMsg, c.New = "fail", fmt.Sprintf("%d failing", failed), failed
		} else {
			c.State, c.StateMsg = "pass", fmt.Sprintf("%d passing", countTestStatus(run.Tests, "passed"))
		}
		cards = append(cards, c)
	}
	// Mark errored checks as idle via the steps.
	for _, st := range run.Steps {
		if st.Errored {
			cards = append(cards, FamilyCard{Name: st.PluginID, State: "idle", StateMsg: "did not complete"})
		}
	}
	return cards
}

func severityChart(fs []model.Finding) template.HTML {
	order := []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo}
	colors := map[model.Severity]string{
		model.SevCritical: "var(--red)", model.SevHigh: "var(--red)",
		model.SevMedium: "var(--warn)", model.SevLow: "var(--muted)", model.SevInfo: "var(--muted)",
	}
	counts := map[model.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	var bars []Bar
	for _, sv := range order {
		if counts[sv] > 0 {
			bars = append(bars, Bar{Label: sv.String(), Count: counts[sv], Color: colors[sv]})
		}
	}
	if len(bars) == 0 {
		return ""
	}
	return barChart(bars)
}

func itoa(n int) string { return strconv.Itoa(n) }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
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

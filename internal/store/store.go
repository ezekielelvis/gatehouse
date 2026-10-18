// Package store persists runs, findings, metrics and decisions to a single
// SQLite file in WAL mode via the pure-Go modernc.org/sqlite driver (no cgo),
// matching plan §2/§15. The database is for fast querying; the signed evidence
// bundle (future work, plan §10) is the record of truth.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gatehouse/gatehouse/internal/model"
	_ "modernc.org/sqlite"
)

// Store is a handle to the Gatehouse database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path and applies
// migrations. Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite tolerates one writer; a small pool avoids "database is locked".
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Additive column migrations for databases created by older versions.
	// SQLite has no "ADD COLUMN IF NOT EXISTS", so ignore the duplicate error.
	for _, stmt := range []string{
		`ALTER TABLE findings ADD COLUMN snippet TEXT`,
		`ALTER TABLE findings ADD COLUMN cwe_ids TEXT`,
	} {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate: %q: %w", stmt, err)
		}
	}
	return nil
}

const schema = `
CREATE TABLE IF NOT EXISTS runs (
    id           TEXT PRIMARY KEY,
    repo_path    TEXT NOT NULL,
    ref          TEXT,
    tree_hash    TEXT,
    base_ref     TEXT,
    context      TEXT,
    verdict      TEXT,
    status       TEXT,
    profile_json TEXT,
    started_at   TEXT,
    finished_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_repo ON runs(repo_path, started_at);

CREATE TABLE IF NOT EXISTS repos (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    path       TEXT NOT NULL UNIQUE,
    name       TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    family      TEXT,
    rule_id     TEXT,
    tool        TEXT,
    severity    INTEGER,
    message     TEXT,
    path        TEXT,
    start_line  INTEGER,
    end_line    INTEGER,
    snippet     TEXT,
    cwe_ids     TEXT,
    status      TEXT,
    waiver_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);

CREATE TABLE IF NOT EXISTS metrics (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    key    TEXT NOT NULL,
    value  REAL
);

CREATE TABLE IF NOT EXISTS steps (
    run_id       TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    plugin_id    TEXT,
    image_digest TEXT,
    exit_code    INTEGER,
    duration_ms  INTEGER,
    errored      INTEGER,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_steps_run ON steps(run_id);

CREATE TABLE IF NOT EXISTS components (
    run_id  TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    purl    TEXT,
    name    TEXT,
    version TEXT,
    license TEXT,
    direct  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_components_run ON components(run_id);

CREATE TABLE IF NOT EXISTS test_results (
    run_id      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    suite       TEXT,
    name        TEXT,
    status      TEXT,
    duration_ms INTEGER,
    retries     INTEGER,
    flaky       INTEGER,
    quarantined INTEGER
);
CREATE INDEX IF NOT EXISTS idx_tests_run ON test_results(run_id);

CREATE TABLE IF NOT EXISTS decisions (
    run_id    TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    verdict   TEXT,
    deny_json TEXT,
    warn_json TEXT
);
`

// SaveRun persists a run and all its findings/metrics in one transaction.
func (s *Store) SaveRun(run model.Run) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	profile, _ := json.Marshal(run.Profile)
	_, err = tx.Exec(`INSERT OR REPLACE INTO runs
        (id, repo_path, ref, tree_hash, base_ref, context, verdict, status, profile_json, started_at, finished_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		run.ID, run.RepoPath, run.Ref, run.TreeHash, run.BaseRef, run.Context,
		run.Verdict, run.Status, string(profile), fmtTime(run.StartedAt), fmtTime(run.FinishedAt))
	if err != nil {
		return fmt.Errorf("insert run: %w", err)
	}

	// Replace children so re-saving a run is idempotent.
	for _, tbl := range []string{"findings", "metrics", "test_results", "components", "steps"} {
		if _, err := tx.Exec("DELETE FROM "+tbl+" WHERE run_id = ?", run.ID); err != nil {
			return err
		}
	}

	for _, f := range run.Findings {
		_, err = tx.Exec(`INSERT INTO findings
            (run_id, fingerprint, family, rule_id, tool, severity, message, path, start_line, end_line, snippet, cwe_ids, status, waiver_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			run.ID, f.Fingerprint, f.Family, f.RuleID, f.Tool, int(f.Severity),
			f.Message, f.Path, f.StartLine, f.EndLine, f.Snippet, strings.Join(f.CWEIDs, ","), f.Status, f.WaiverID)
		if err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}
	for _, m := range run.Metrics {
		if _, err = tx.Exec(`INSERT INTO metrics (run_id, key, value) VALUES (?,?,?)`,
			run.ID, m.Key, m.Value); err != nil {
			return err
		}
	}
	for _, t := range run.Tests {
		if _, err = tx.Exec(`INSERT INTO test_results
            (run_id, suite, name, status, duration_ms, retries, flaky, quarantined)
            VALUES (?,?,?,?,?,?,?,?)`,
			run.ID, t.Suite, t.Name, t.Status, t.Duration.Milliseconds(),
			t.Retries, boolToInt(t.Flaky), boolToInt(t.Quarantined)); err != nil {
			return err
		}
	}
	for _, c := range run.SBOM {
		if _, err = tx.Exec(`INSERT INTO components (run_id, purl, name, version, license, direct)
            VALUES (?,?,?,?,?,?)`,
			run.ID, c.PURL, c.Name, c.Version, c.License, boolToInt(c.Direct)); err != nil {
			return err
		}
	}
	for _, s := range run.Steps {
		if _, err = tx.Exec(`INSERT INTO steps (run_id, plugin_id, image_digest, exit_code, duration_ms, errored, error)
            VALUES (?,?,?,?,?,?,?)`,
			run.ID, s.PluginID, s.ImageDigest, s.ExitCode, s.Duration.Milliseconds(),
			boolToInt(s.Errored), s.Error); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SaveDecision persists the policy decision for a run.
func (s *Store) SaveDecision(runID string, verdict model.Verdict, deny, warn []string) error {
	dj, _ := json.Marshal(deny)
	wj, _ := json.Marshal(warn)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO decisions (run_id, verdict, deny_json, warn_json)
        VALUES (?,?,?,?)`, runID, verdict, string(dj), string(wj))
	return err
}

// LastFindings returns the findings of the most recent completed run for the
// given repo on the given ref, used as the diff base for the current run.
// Returns nil (not an error) when there is no prior run.
func (s *Store) LastFindings(repoPath, ref string) ([]model.Finding, error) {
	var runID string
	err := s.db.QueryRow(`SELECT id FROM runs
        WHERE repo_path = ? AND ref = ? AND status = 'done'
        ORDER BY started_at DESC LIMIT 1`, repoPath, ref).Scan(&runID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.findingsForRun(runID)
}

func (s *Store) findingsForRun(runID string) ([]model.Finding, error) {
	rows, err := s.db.Query(`SELECT fingerprint, family, rule_id, tool, severity, message, path, start_line, end_line, snippet, cwe_ids, status, waiver_id
        FROM findings WHERE run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		var f model.Finding
		var sev int
		var cwes string
		if err := rows.Scan(&f.Fingerprint, &f.Family, &f.RuleID, &f.Tool, &sev,
			&f.Message, &f.Path, &f.StartLine, &f.EndLine, &f.Snippet, &cwes, &f.Status, &f.WaiverID); err != nil {
			return nil, err
		}
		f.Severity = model.Severity(sev)
		if cwes != "" {
			f.CWEIDs = strings.Split(cwes, ",")
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// GetRun loads a full run (findings, metrics, tests, decision) by id for
// reporting and evidence export. Returns (nil, nil) if no such run exists.
func (s *Store) GetRun(id string) (*model.Run, []string, []string, error) {
	var r model.Run
	var profileJSON, started, finished string
	err := s.db.QueryRow(`SELECT id, repo_path, COALESCE(ref,''), COALESCE(tree_hash,''), COALESCE(base_ref,''),
        COALESCE(context,''), COALESCE(verdict,''), COALESCE(status,''), COALESCE(profile_json,'{}'),
        COALESCE(started_at,''), COALESCE(finished_at,'')
        FROM runs WHERE id = ?`, id).Scan(&r.ID, &r.RepoPath, &r.Ref, &r.TreeHash, &r.BaseRef,
		&r.Context, &r.Verdict, &r.Status, &profileJSON, &started, &finished)
	if err == sql.ErrNoRows {
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, err
	}
	_ = json.Unmarshal([]byte(profileJSON), &r.Profile)
	r.StartedAt, _ = time.Parse(time.RFC3339, started)
	r.FinishedAt, _ = time.Parse(time.RFC3339, finished)

	if r.Findings, err = s.findingsForRun(id); err != nil {
		return nil, nil, nil, err
	}

	mrows, err := s.db.Query(`SELECT key, value FROM metrics WHERE run_id = ?`, id)
	if err != nil {
		return nil, nil, nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var m model.Metric
		if err := mrows.Scan(&m.Key, &m.Value); err != nil {
			return nil, nil, nil, err
		}
		r.Metrics = append(r.Metrics, m)
	}

	trows, err := s.db.Query(`SELECT suite, name, status, duration_ms, retries, flaky, quarantined FROM test_results WHERE run_id = ?`, id)
	if err != nil {
		return nil, nil, nil, err
	}
	defer trows.Close()
	for trows.Next() {
		var t model.TestResult
		var ms int64
		var flaky, quar int
		if err := trows.Scan(&t.Suite, &t.Name, &t.Status, &ms, &t.Retries, &flaky, &quar); err != nil {
			return nil, nil, nil, err
		}
		t.Duration = time.Duration(ms) * time.Millisecond
		t.Flaky, t.Quarantined = flaky == 1, quar == 1
		r.Tests = append(r.Tests, t)
	}

	crows, err := s.db.Query(`SELECT purl, name, version, license, direct FROM components WHERE run_id = ?`, id)
	if err != nil {
		return nil, nil, nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var c model.Component
		var direct int
		if err := crows.Scan(&c.PURL, &c.Name, &c.Version, &c.License, &direct); err != nil {
			return nil, nil, nil, err
		}
		c.Direct = direct == 1
		r.SBOM = append(r.SBOM, c)
	}

	srows, err := s.db.Query(`SELECT plugin_id, image_digest, exit_code, duration_ms, errored, error FROM steps WHERE run_id = ?`, id)
	if err != nil {
		return nil, nil, nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var st model.Step
		var ms int64
		var errored int
		if err := srows.Scan(&st.PluginID, &st.ImageDigest, &st.ExitCode, &ms, &errored, &st.Error); err != nil {
			return nil, nil, nil, err
		}
		st.Duration = time.Duration(ms) * time.Millisecond
		st.Errored = errored == 1
		r.Steps = append(r.Steps, st)
	}

	deny, warn := s.decisionMessages(id)
	return &r, deny, warn, nil
}

func (s *Store) decisionMessages(id string) (deny, warn []string) {
	var dj, wj string
	if err := s.db.QueryRow(`SELECT deny_json, warn_json FROM decisions WHERE run_id = ?`, id).Scan(&dj, &wj); err != nil {
		return nil, nil
	}
	_ = json.Unmarshal([]byte(dj), &deny)
	_ = json.Unmarshal([]byte(wj), &warn)
	return deny, warn
}

// TestOutcome tallies how often a test passed vs failed across prior runs.
type TestOutcome struct {
	Pass int
	Fail int
}

// TestHistory aggregates per-test pass/fail counts over the most recent `limit`
// completed runs for a repo+ref, used for flaky-test detection (plan §8). The
// map key is "<suite>\x00<name>".
func (s *Store) TestHistory(repoPath, ref string, limit int) (map[string]TestOutcome, error) {
	rows, err := s.db.Query(`
        SELECT tr.suite, tr.name, tr.status, COUNT(*)
        FROM test_results tr
        WHERE tr.run_id IN (
            SELECT id FROM runs WHERE repo_path = ? AND ref = ? AND status = 'done'
            ORDER BY started_at DESC LIMIT ?)
        GROUP BY tr.suite, tr.name, tr.status`, repoPath, ref, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]TestOutcome{}
	for rows.Next() {
		var suite, name, status string
		var n int
		if err := rows.Scan(&suite, &name, &status, &n); err != nil {
			return nil, err
		}
		key := suite + "\x00" + name
		o := out[key]
		switch status {
		case "passed":
			o.Pass += n
		case "failed":
			o.Fail += n
		}
		out[key] = o
	}
	return out, rows.Err()
}

// Repo is a registered project the UI can scan.
type Repo struct {
	ID        int64
	Path      string
	Name      string
	CreatedAt time.Time
}

// AddRepo registers a repo path (idempotent on path) and returns it.
func (s *Store) AddRepo(path, name string) (Repo, error) {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO repos (path, name, created_at) VALUES (?,?,?)`,
		path, name, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return Repo{}, err
	}
	var r Repo
	var created string
	err = s.db.QueryRow(`SELECT id, path, name, created_at FROM repos WHERE path = ?`, path).
		Scan(&r.ID, &r.Path, &r.Name, &created)
	r.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return r, err
}

// ListRepos returns all registered repos, newest first.
func (s *Store) ListRepos() ([]Repo, error) {
	rows, err := s.db.Query(`SELECT id, path, name, created_at FROM repos ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Repo
	for rows.Next() {
		var r Repo
		var created string
		if err := rows.Scan(&r.ID, &r.Path, &r.Name, &created); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRepo returns a repo by id.
func (s *Store) GetRepo(id int64) (Repo, error) {
	var r Repo
	var created string
	err := s.db.QueryRow(`SELECT id, path, name, created_at FROM repos WHERE id = ?`, id).
		Scan(&r.ID, &r.Path, &r.Name, &created)
	r.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return r, err
}

// InsertRunningRun records a placeholder row so the UI can show a scan in
// progress before the orchestrator finishes and saves the full run.
func (s *Store) InsertRunningRun(id, repoPath, ref string, ctx model.Context) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO runs
        (id, repo_path, ref, context, verdict, status, started_at)
        VALUES (?,?,?,?,?,?,?)`,
		id, repoPath, ref, ctx, "", "running", time.Now().UTC().Format(time.RFC3339))
	return err
}

// RunStatus returns a run's status (running|done|error) and verdict.
func (s *Store) RunStatus(id string) (status string, verdict model.Verdict, err error) {
	err = s.db.QueryRow(`SELECT status, verdict FROM runs WHERE id = ?`, id).Scan(&status, &verdict)
	return status, verdict, err
}

// LatestRunForRepo returns the id of the most recent run for a repo path, or "".
func (s *Store) LatestRunForRepo(repoPath string) string {
	var id string
	_ = s.db.QueryRow(`SELECT id FROM runs WHERE repo_path = ? ORDER BY started_at DESC LIMIT 1`, repoPath).Scan(&id)
	return id
}

// RunSummary is a run plus the aggregate counts the history/trends view needs.
type RunSummary struct {
	Run             model.Run
	NewFindings     int
	TotalFindings   int
	CoverageChanged float64 // -1 when not measured
}

// RunSummaries returns the most recent runs with finding counts and changed-
// lines coverage, newest first, for the history/trends view.
func (s *Store) RunSummaries(limit int) ([]RunSummary, error) {
	runs, err := s.RecentRuns(limit)
	if err != nil {
		return nil, err
	}
	out := make([]RunSummary, 0, len(runs))
	for _, r := range runs {
		sum := RunSummary{Run: r, CoverageChanged: -1}
		_ = s.db.QueryRow(`SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN status='new' THEN 1 ELSE 0 END), 0)
			FROM findings WHERE run_id = ?`, r.ID).Scan(&sum.TotalFindings, &sum.NewFindings)
		var cov float64
		if err := s.db.QueryRow(`SELECT value FROM metrics WHERE run_id = ? AND key = 'coverage.changed_lines'`, r.ID).Scan(&cov); err == nil {
			sum.CoverageChanged = cov
		}
		out = append(out, sum)
	}
	return out, nil
}

// WaivedFindings returns findings across recent runs that had a waiver applied,
// for the waivers view. Each is the most recent occurrence per fingerprint.
func (s *Store) WaivedFindings(limit int) ([]model.Finding, error) {
	rows, err := s.db.Query(`
		SELECT f.fingerprint, f.family, f.rule_id, f.tool, f.severity, f.message, f.path, f.start_line, f.waiver_id
		FROM findings f
		JOIN runs r ON f.run_id = r.id
		WHERE f.waiver_id != ''
		GROUP BY f.fingerprint
		ORDER BY r.started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		var f model.Finding
		var sev int
		if err := rows.Scan(&f.Fingerprint, &f.Family, &f.RuleID, &f.Tool, &sev, &f.Message, &f.Path, &f.StartLine, &f.WaiverID); err != nil {
			return nil, err
		}
		f.Severity = model.Severity(sev)
		out = append(out, f)
	}
	return out, rows.Err()
}

// RecentRuns returns the most recent runs across all repos, newest first.
func (s *Store) RecentRuns(limit int) ([]model.Run, error) {
	rows, err := s.db.Query(`SELECT id, repo_path, COALESCE(ref,''), COALESCE(base_ref,''), COALESCE(context,''),
        COALESCE(verdict,''), COALESCE(status,''), COALESCE(started_at,''), COALESCE(finished_at,'')
        FROM runs ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Run
	for rows.Next() {
		var r model.Run
		var started, finished string
		if err := rows.Scan(&r.ID, &r.RepoPath, &r.Ref, &r.BaseRef, &r.Context,
			&r.Verdict, &r.Status, &started, &finished); err != nil {
			return nil, err
		}
		r.StartedAt, _ = time.Parse(time.RFC3339, started)
		r.FinishedAt, _ = time.Parse(time.RFC3339, finished)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GC applies retention (plan §10): for each repo+branch it keeps the most
// recent keepPerBranch completed runs, but never prunes runs tagged with the
// release context. Returns the number of runs deleted. Cascading foreign keys
// remove the pruned runs' findings/metrics/tests/components/steps/decisions.
func (s *Store) GC(keepPerBranch int) (int, error) {
	if keepPerBranch < 1 {
		keepPerBranch = 1
	}
	// Candidate runs to delete: those that are NOT release and NOT within the
	// newest keepPerBranch for their (repo_path, ref) group.
	res, err := s.db.Exec(`
        DELETE FROM runs WHERE context != 'release' AND id IN (
            SELECT id FROM (
                SELECT id,
                    ROW_NUMBER() OVER (PARTITION BY repo_path, ref ORDER BY started_at DESC) AS rn
                FROM runs
            ) WHERE rn > ?)`, keepPerBranch)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

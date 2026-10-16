package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/store"
)

func seed(t *testing.T) (*Server, string) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	run := model.Run{
		ID: "RUN-1", RepoPath: "/home/me/payments", Ref: "working-tree",
		Context: model.ContextPrePush, Verdict: model.VerdictFail, Status: "done",
		Profile: model.RepoProfile{Languages: []string{"Go"}},
		Findings: []model.Finding{
			{Fingerprint: "f1", Family: model.FamilySecret, RuleID: "aws-key", Tool: "gitleaks",
				Severity: model.SevHigh, Path: "cfg.env", StartLine: 3, Status: model.StatusNew,
				Message: "secret", CWEIDs: []string{"CWE-798"}},
			{Fingerprint: "f2", Family: model.FamilySAST, RuleID: "sqli", Tool: "opengrep",
				Severity: model.SevMedium, Path: "db.go", StartLine: 9, Status: model.StatusExisting,
				Message: "sql", CWEIDs: []string{"CWE-89"}},
		},
		SBOM: []model.Component{{Name: "left-pad", Version: "1.3.0", License: "WTFPL"}},
	}
	if err := st.SaveRun(run); err != nil {
		t.Fatal(err)
	}
	_ = st.SaveDecision(run.ID, run.Verdict, []string{"New secret detected"}, nil)

	srv, err := New(st)
	if err != nil {
		t.Fatal(err)
	}
	return srv, run.ID
}

func do(t *testing.T, srv *Server, path string) (int, string) {
	t.Helper()
	mux := http.NewServeMux()
	srv.Routes(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec.Code, rec.Body.String()
}

func TestDashboardRendersRuns(t *testing.T) {
	srv, id := seed(t)
	code, body := do(t, srv, "/")
	if code != 200 {
		t.Fatalf("dashboard status %d", code)
	}
	if !strings.Contains(body, id) || !strings.Contains(body, "payments") {
		t.Error("dashboard should list the run and repo")
	}
}

func TestRunDetailRendersSections(t *testing.T) {
	srv, id := seed(t)
	code, body := do(t, srv, "/runs/"+id)
	if code != 200 {
		t.Fatalf("run detail status %d", code)
	}
	for _, want := range []string{"aws-key", "left-pad", "Cryptographic Failures", `class="verdict fail"`, "New secret detected"} {
		if !strings.Contains(body, want) {
			t.Errorf("run detail missing %q", want)
		}
	}
}

func TestFindingsFilterBySeverity(t *testing.T) {
	srv, id := seed(t)
	_, body := do(t, srv, "/runs/"+id+"/findings?severity=high")
	if !strings.Contains(body, "aws-key") {
		t.Error("high filter should include the secret")
	}
	if strings.Contains(body, "sqli") {
		t.Error("high filter should exclude the medium SAST finding")
	}
}

func TestFindingsFilterByStatus(t *testing.T) {
	srv, id := seed(t)
	_, body := do(t, srv, "/runs/"+id+"/findings?status=existing")
	if !strings.Contains(body, "sqli") || strings.Contains(body, "aws-key") {
		t.Error("status=existing should show only the existing finding")
	}
}

func TestCompliancePartialSwitchesStandard(t *testing.T) {
	srv, id := seed(t)
	code, body := do(t, srv, "/runs/"+id+"/compliance?standard=cwe-top25")
	if code != 200 {
		t.Fatalf("compliance status %d", code)
	}
	if !strings.Contains(body, "CWE Top 25") {
		t.Error("should render the cwe-top25 report")
	}
}

func TestUnknownRun404(t *testing.T) {
	srv, _ := seed(t)
	if code, _ := do(t, srv, "/runs/nope"); code != 404 {
		t.Fatalf("unknown run should 404, got %d", code)
	}
}

func TestHistoryPage(t *testing.T) {
	srv, id := seed(t)
	code, body := do(t, srv, "/history")
	if code != 200 {
		t.Fatalf("history status %d", code)
	}
	if !strings.Contains(body, id) {
		t.Error("history should list the run")
	}
}

func TestWaiversPage(t *testing.T) {
	srv, _ := seed(t)
	if code, _ := do(t, srv, "/waivers"); code != 200 {
		t.Fatalf("waivers status %d", code)
	}
}

func TestPoliciesPageListsPacks(t *testing.T) {
	srv, _ := seed(t)
	code, body := do(t, srv, "/policies")
	if code != 200 {
		t.Fatalf("policies status %d", code)
	}
	for _, want := range []string{"baseline", "strict-release", "iac-hardening"} {
		if !strings.Contains(body, want) {
			t.Errorf("policies page missing pack %q", want)
		}
	}
}

func TestSettingsPage(t *testing.T) {
	srv, _ := seed(t)
	srv.SetMeta(Settings{BindAddr: "127.0.0.1:7420", DBPath: "/tmp/x.db", KeyID: "KEY123"})
	code, body := do(t, srv, "/settings")
	if code != 200 {
		t.Fatalf("settings status %d", code)
	}
	if !strings.Contains(body, "KEY123") || !strings.Contains(body, "127.0.0.1:7420") {
		t.Error("settings page should show injected metadata")
	}
}

func TestStaticHtmxServed(t *testing.T) {
	srv, _ := seed(t)
	code, body := do(t, srv, "/static/htmx.min.js")
	if code != 200 || len(body) < 1000 {
		t.Fatalf("htmx asset not served: code=%d len=%d", code, len(body))
	}
}

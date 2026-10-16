package enrich

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gatehouse/gatehouse/internal/model"
)

func writeMirror(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "cvss.json"), []byte(`{"CVE-2024-1":9.8,"CVE-2024-2":4.1}`), 0o644)
	os.WriteFile(filepath.Join(dir, "epss.csv"), []byte("CVE-2024-1,0.97\nCVE-2024-2,0.02\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "kev.json"), []byte(`["CVE-2024-1"]`), 0o644)
	return dir
}

func TestEnrichAppliesFeeds(t *testing.T) {
	m, err := Load(writeMirror(t))
	if err != nil {
		t.Fatal(err)
	}
	fs := []model.Finding{
		{Family: model.FamilyVuln, RuleID: "CVE-2024-1", Message: "vuln"},
		{Family: model.FamilyVuln, RuleID: "CVE-2024-2", Message: "vuln"},
		{Family: model.FamilySecret, RuleID: "x"}, // not a vuln → untouched
	}
	out := m.Apply(fs)
	// Sorted by risk: CVE-2024-1 (critical + KEV + high EPSS) first.
	if out[0].RuleID != "CVE-2024-1" {
		t.Fatalf("expected highest-risk finding first, got %s", out[0].RuleID)
	}
	if out[0].CVSS != 9.8 || !out[0].KEV || out[0].EPSS < 0.9 {
		t.Errorf("CVE-2024-1 not enriched: %+v", out[0])
	}
	if out[0].Severity != model.SevCritical {
		t.Errorf("severity should be promoted to critical from CVSS, got %s", out[0].Severity)
	}
}

func TestEnrichMissingMirrorIsNoOp(t *testing.T) {
	m, err := Load(t.TempDir()) // empty dir, no feeds
	if err != nil {
		t.Fatal(err)
	}
	fs := []model.Finding{{Family: model.FamilyVuln, RuleID: "CVE-2024-1", Severity: model.SevMedium}}
	out := m.Apply(fs)
	if out[0].CVSS != 0 || out[0].Severity != model.SevMedium {
		t.Error("absent mirror must not change findings")
	}
}

func TestRiskOrdering(t *testing.T) {
	kev := model.Finding{Severity: model.SevHigh, KEV: true}
	plain := model.Finding{Severity: model.SevCritical}
	if Risk(kev) <= Risk(plain) {
		t.Error("a known-exploited high should outrank a plain critical")
	}
}

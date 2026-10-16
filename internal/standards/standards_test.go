package standards_test

import (
	"testing"

	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/standards"
	standardsdata "github.com/gatehouse/gatehouse/standards"
)

func load(t *testing.T, name string) *standards.Standard {
	t.Helper()
	s, err := standardsdata.Load(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func resultByID(rep standards.Report, id string) standards.ControlResult {
	for _, cr := range rep.Results {
		if cr.Control.ID == id {
			return cr
		}
	}
	return standards.ControlResult{}
}

func TestOWASPCleanRunMetAndManual(t *testing.T) {
	std := load(t, "owasp-top10")
	rep := standards.Evaluate(std, model.Run{}) // no findings
	// A04 Insecure Design is automatable: no → manual even on a clean run.
	if got := resultByID(rep, "A04").Status; got != standards.StatusManual {
		t.Errorf("A04 should be manual, got %s", got)
	}
	// A03 Injection is partial and has no findings → met.
	if got := resultByID(rep, "A03").Status; got != standards.StatusMet {
		t.Errorf("A03 should be met on a clean run, got %s", got)
	}
}

func TestInjectionFindingMarksA03NotMet(t *testing.T) {
	std := load(t, "owasp-top10")
	run := model.Run{Findings: []model.Finding{
		{RuleID: "sql-injection", Family: model.FamilySAST, CWEIDs: []string{"CWE-89"}, Status: model.StatusNew},
	}}
	rep := standards.Evaluate(std, run)
	cr := resultByID(rep, "A03")
	if cr.Status != standards.StatusNotMet {
		t.Fatalf("A03 should be not_met with a CWE-89 finding, got %s", cr.Status)
	}
	if len(cr.Findings) != 1 {
		t.Errorf("expected the mapped finding attached, got %d", len(cr.Findings))
	}
}

func TestSecretFamilyMarksA02NotMet(t *testing.T) {
	std := load(t, "owasp-top10")
	run := model.Run{Findings: []model.Finding{
		{RuleID: "generic-api-key", Family: model.FamilySecret, Status: model.StatusNew},
	}}
	if got := resultByID(standards.Evaluate(std, run), "A02").Status; got != standards.StatusNotMet {
		t.Errorf("A02 should be not_met via secret family, got %s", got)
	}
}

func TestWaivedFindingDoesNotFailControl(t *testing.T) {
	std := load(t, "owasp-top10")
	run := model.Run{Findings: []model.Finding{
		{RuleID: "sql-injection", CWEIDs: []string{"CWE-89"}, Status: model.StatusNew, WaiverID: "W-1"},
	}}
	if got := resultByID(standards.Evaluate(std, run), "A03").Status; got != standards.StatusMet {
		t.Errorf("A03 should be met when the only mapped finding is waived, got %s", got)
	}
}

func TestSSDFActivityEvidence(t *testing.T) {
	std := load(t, "nist-ssdf")
	run := model.Run{
		Steps: []model.Step{
			{PluginID: "opengrep"},                   // ran OK → PW.7 met
			{PluginID: "osv-scanner", Errored: true}, // attempted but failed → RV.1 not_met
		},
		Tests: []model.TestResult{{Name: "t", Status: "passed"}}, // PW.8 met
		// no SBOM → PS.3 manual (no evidence)
	}
	rep := standards.Evaluate(std, run)
	if got := resultByID(rep, "PW.7").Status; got != standards.StatusMet {
		t.Errorf("PW.7 should be met (opengrep ran), got %s", got)
	}
	if got := resultByID(rep, "PW.8").Status; got != standards.StatusMet {
		t.Errorf("PW.8 should be met (tests ran), got %s", got)
	}
	if got := resultByID(rep, "RV.1").Status; got != standards.StatusNotMet {
		t.Errorf("RV.1 should be not_met (osv-scanner errored), got %s", got)
	}
	if got := resultByID(rep, "PS.3").Status; got != standards.StatusManual {
		t.Errorf("PS.3 should be manual (no SBOM produced), got %s", got)
	}
}

func TestSLSAManualForBuildPlatform(t *testing.T) {
	std := load(t, "slsa")
	rep := standards.Evaluate(std, model.Run{SBOM: []model.Component{{Name: "x"}}})
	if got := resultByID(rep, "L1-PROVENANCE").Status; got != standards.StatusMet {
		t.Errorf("L1 should be met (SBOM present), got %s", got)
	}
	if got := resultByID(rep, "L3-HARDENED-BUILD").Status; got != standards.StatusManual {
		t.Errorf("L3 hardened-build is not locally attestable → manual, got %s", got)
	}
}

func TestAllShippedStandardsLoad(t *testing.T) {
	for _, name := range []string{"owasp-top10", "cwe-top25", "nist-ssdf", "slsa", "iso-27001", "soc2", "pci-dss"} {
		std, err := standardsdata.Load(name)
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		if len(std.Controls) == 0 {
			t.Errorf("%s has no controls", name)
		}
		// Every control must evaluate without panicking.
		standards.Evaluate(std, model.Run{})
	}
}

func TestPCIDependencyVulnMarksNotMet(t *testing.T) {
	std := load(t, "pci-dss")
	run := model.Run{Findings: []model.Finding{
		{RuleID: "CVE-2024-1", Family: model.FamilyVuln, Status: model.StatusNew, Severity: model.SevHigh},
	}}
	if got := resultByID(standards.Evaluate(std, run), "6.3.3-NOVULN").Status; got != standards.StatusNotMet {
		t.Errorf("PCI 6.3.3 should be not_met with a vulnerable dep, got %s", got)
	}
}

func TestCWETop25LoadsAndEvaluates(t *testing.T) {
	std := load(t, "cwe-top25")
	if len(std.Controls) != 25 {
		t.Fatalf("expected 25 controls, got %d", len(std.Controls))
	}
	run := model.Run{Findings: []model.Finding{
		{RuleID: "hardcoded", Family: model.FamilySecret, CWEIDs: []string{"CWE-798"}, Status: model.StatusNew},
	}}
	rep := standards.Evaluate(std, run)
	if resultByID(rep, "18").Status != standards.StatusNotMet {
		t.Error("CWE-798 control (#18) should be not_met")
	}
}

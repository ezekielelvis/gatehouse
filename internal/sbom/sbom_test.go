package sbom_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/gatehouse/gatehouse/internal/adapters"
	"github.com/gatehouse/gatehouse/internal/model"
	"github.com/gatehouse/gatehouse/internal/sbom"
)

func sampleRun() model.Run {
	return model.Run{
		ID: "R1", RepoPath: "/repo", StartedAt: time.Now(),
		SBOM: []model.Component{
			{Name: "left-pad", Version: "1.3.0", PURL: "pkg:npm/left-pad@1.3.0", License: "WTFPL", Direct: true},
			{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", License: "MIT"},
		},
	}
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCycloneDXRoundTripsThroughParser(t *testing.T) {
	data := marshal(t, sbom.CycloneDX(sampleRun()))
	comps, err := adapters.ParseCycloneDX(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("our CycloneDX output must parse back: %v", err)
	}
	if len(comps) != 2 {
		t.Fatalf("want 2 components round-tripped, got %d", len(comps))
	}
	if comps[0].Name != "left-pad" || comps[0].License != "WTFPL" {
		t.Errorf("component not preserved: %+v", comps[0])
	}
}

func TestSPDXShape(t *testing.T) {
	data := marshal(t, sbom.SPDX(sampleRun()))
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion wrong: %v", doc["spdxVersion"])
	}
	pkgs, ok := doc["packages"].([]any)
	if !ok || len(pkgs) != 2 {
		t.Fatalf("want 2 packages, got %v", doc["packages"])
	}
	p0 := pkgs[0].(map[string]any)
	if p0["licenseConcluded"] != "WTFPL" {
		t.Errorf("license not emitted: %v", p0["licenseConcluded"])
	}
}

func TestSPDXNoAssertionForMissingLicense(t *testing.T) {
	run := model.Run{ID: "R2", SBOM: []model.Component{{Name: "x", Version: "1"}}}
	data := marshal(t, sbom.SPDX(run))
	var doc map[string]any
	_ = json.Unmarshal(data, &doc)
	p := doc["packages"].([]any)[0].(map[string]any)
	if p["licenseConcluded"] != "NOASSERTION" {
		t.Errorf("missing license should be NOASSERTION, got %v", p["licenseConcluded"])
	}
}

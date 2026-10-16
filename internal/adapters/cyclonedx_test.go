package adapters

import (
	"strings"
	"testing"
)

const cdxJSON = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "library",
      "name": "left-pad",
      "version": "1.3.0",
      "purl": "pkg:npm/left-pad@1.3.0",
      "licenses": [{"license": {"id": "WTFPL"}}],
      "hashes": [{"alg": "SHA-256", "content": "abc123"}],
      "properties": [{"name": "syft:package:foundBy", "value": "x"}, {"name": "gatehouse:direct", "value": "true"}]
    },
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [{"expression": "MIT"}]
    }
  ]
}`

func TestParseCycloneDX(t *testing.T) {
	comps, err := ParseCycloneDX(strings.NewReader(cdxJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 2 {
		t.Fatalf("want 2 components, got %d", len(comps))
	}
	lp := comps[0]
	if lp.Name != "left-pad" || lp.Version != "1.3.0" {
		t.Errorf("component fields wrong: %+v", lp)
	}
	if lp.License != "WTFPL" {
		t.Errorf("license id not parsed: %q", lp.License)
	}
	if !lp.Direct {
		t.Error("left-pad should be marked direct from its property")
	}
	if len(lp.Hashes) != 1 || lp.Hashes[0] != "SHA-256:abc123" {
		t.Errorf("hashes wrong: %v", lp.Hashes)
	}
	if comps[1].License != "MIT" {
		t.Errorf("expression license not parsed: %q", comps[1].License)
	}
	if comps[1].Direct {
		t.Error("lodash should default to transitive (no direct property)")
	}
}

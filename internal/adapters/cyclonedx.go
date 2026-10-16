package adapters

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gatehouse/gatehouse/internal/model"
)

// Minimal CycloneDX 1.x structures — the subset Gatehouse ingests from a Syft
// SBOM (plan §6/§7). CycloneDX is the primary SBOM format; SPDX export is a
// later concern.
type cdxDocument struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type       string       `json:"type"`
	Name       string       `json:"name"`
	Version    string       `json:"version"`
	PURL       string       `json:"purl"`
	Scope      string       `json:"scope"`
	Hashes     []cdxHash    `json:"hashes"`
	Licenses   []cdxLicense `json:"licenses"`
	Properties []cdxProp    `json:"properties"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// A CycloneDX license entry is either {license:{id|name}} or {expression:"..."}.
type cdxLicense struct {
	License struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}

type cdxProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ParseCycloneDX reads a CycloneDX JSON SBOM and returns normalised components.
func ParseCycloneDX(r io.Reader) ([]model.Component, error) {
	var doc cdxDocument
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode cyclonedx: %w", err)
	}
	out := make([]model.Component, 0, len(doc.Components))
	for _, c := range doc.Components {
		comp := model.Component{
			PURL:    c.PURL,
			Name:    c.Name,
			Version: c.Version,
			License: licenseOf(c.Licenses),
			Hashes:  hashesOf(c.Hashes),
			Direct:  isDirect(c),
		}
		out = append(out, comp)
	}
	return out, nil
}

// licenseOf picks the best license string available: an SPDX id, else a name,
// else an expression. Multiple licenses are joined so policy can match any.
func licenseOf(ls []cdxLicense) string {
	var parts []string
	for _, l := range ls {
		switch {
		case l.License.ID != "":
			parts = append(parts, l.License.ID)
		case l.License.Name != "":
			parts = append(parts, l.License.Name)
		case l.Expression != "":
			parts = append(parts, l.Expression)
		}
	}
	return strings.Join(parts, " OR ")
}

func hashesOf(hs []cdxHash) []string {
	var out []string
	for _, h := range hs {
		out = append(out, h.Alg+":"+h.Content)
	}
	return out
}

// isDirect reports whether a component is a direct dependency. Syft records this
// in a property; absent that, we conservatively treat components as transitive.
func isDirect(c cdxComponent) bool {
	for _, p := range c.Properties {
		if strings.Contains(strings.ToLower(p.Name), "direct") {
			return strings.EqualFold(p.Value, "true")
		}
	}
	return false
}

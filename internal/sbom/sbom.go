// Package sbom emits a run's component inventory as the two recognised SBOM
// standards: CycloneDX 1.6 (primary) and SPDX 2.3 (export), per plan §6/§10.
// The orchestrator ingests CycloneDX from Syft; these writers re-emit the
// normalised, stored inventory so an evidence export is self-contained and
// consumers can pick their preferred format.
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gatehouse/gatehouse/internal/model"
)

// Format names a supported SBOM output.
type Format string

const (
	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
)

// --- CycloneDX 1.6 ----------------------------------------------------------

type cdxDoc struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMeta        `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMeta struct {
	Timestamp string    `json:"timestamp"`
	Tools     []cdxTool `json:"tools"`
	Component cdxComp   `json:"component"`
}

type cdxTool struct {
	Vendor string `json:"vendor"`
	Name   string `json:"name"`
}

type cdxComp struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type cdxComponent struct {
	Type     string       `json:"type"`
	Name     string       `json:"name"`
	Version  string       `json:"version"`
	PURL     string       `json:"purl,omitempty"`
	Scope    string       `json:"scope,omitempty"`
	Licenses []cdxLicense `json:"licenses,omitempty"`
}

type cdxLicense struct {
	License cdxLicenseID `json:"license"`
}

type cdxLicenseID struct {
	Name string `json:"name"`
}

// CycloneDX builds a CycloneDX 1.6 document for a run.
func CycloneDX(run model.Run) any {
	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + deterministicUUID(run.ID),
		Version:      1,
		Metadata: cdxMeta{
			Timestamp: run.StartedAt.UTC().Format(time.RFC3339),
			Tools:     []cdxTool{{Vendor: "Gatehouse", Name: "gatehouse"}},
			Component: cdxComp{Type: "application", Name: run.RepoPath},
		},
		Components: []cdxComponent{}, // emit [] not null for an empty inventory
	}
	for _, c := range run.SBOM {
		cc := cdxComponent{Type: "library", Name: c.Name, Version: c.Version, PURL: c.PURL}
		if c.Direct {
			cc.Scope = "required"
		}
		if c.License != "" {
			cc.Licenses = []cdxLicense{{License: cdxLicenseID{Name: c.License}}}
		}
		doc.Components = append(doc.Components, cc)
	}
	return doc
}

// --- SPDX 2.3 (JSON) --------------------------------------------------------

type spdxDoc struct {
	SPDXVersion       string        `json:"spdxVersion"`
	DataLicense       string        `json:"dataLicense"`
	SPDXID            string        `json:"SPDXID"`
	Name              string        `json:"name"`
	DocumentNamespace string        `json:"documentNamespace"`
	CreationInfo      spdxCreation  `json:"creationInfo"`
	Packages          []spdxPackage `json:"packages"`
}

type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDX builds an SPDX 2.3 JSON document for a run.
func SPDX(run model.Run) any {
	doc := spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "gatehouse-" + run.ID,
		DocumentNamespace: "https://gatehouse.dev/spdx/" + run.ID,
		CreationInfo: spdxCreation{
			Created:  run.StartedAt.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: gatehouse"},
		},
		Packages: []spdxPackage{}, // emit [] not null for an empty inventory
	}
	for i, c := range run.SBOM {
		pkg := spdxPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			Name:             c.Name,
			VersionInfo:      c.Version,
			DownloadLocation: "NOASSERTION",
			LicenseConcluded: licenseOrNoAssertion(c.License),
			LicenseDeclared:  licenseOrNoAssertion(c.License),
		}
		if c.PURL != "" {
			pkg.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  c.PURL,
			}}
		}
		doc.Packages = append(doc.Packages, pkg)
	}
	return doc
}

func licenseOrNoAssertion(l string) string {
	if l == "" {
		return "NOASSERTION"
	}
	return l
}

// deterministicUUID derives a stable UUID-shaped string from the run id so the
// same run always serialises to the same CycloneDX serial number.
func deterministicUUID(seed string) string {
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	s := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}

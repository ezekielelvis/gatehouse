// Package findings handles normalisation of tool output into model.Finding,
// stable fingerprinting, and diffing a run against a base run to classify each
// finding as new, existing or fixed.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"

	"github.com/gatehouse/gatehouse/internal/model"
)

// Fingerprint computes a stable identity for a finding:
//
//	sha256(rule_id + "\n" + normalised_path + "\n" + normalised_snippet)
//
// The path is cleaned and slashed so OS differences don't change identity, and
// the snippet is whitespace-normalised so a finding keeps its identity when
// unrelated lines above it move or indentation changes. Line numbers are
// deliberately excluded for the same reason.
func Fingerprint(f model.Finding) string {
	h := sha256.New()
	h.Write([]byte(f.RuleID))
	h.Write([]byte{'\n'})
	h.Write([]byte(normalisePath(f.Path)))
	h.Write([]byte{'\n'})
	h.Write([]byte(normaliseSnippet(f.Snippet)))
	// For findings with no snippet (e.g. dependency CVEs) the rule+path alone is
	// too coarse when several CVEs hit one manifest; fold in the message.
	if f.Snippet == "" {
		h.Write([]byte{'\n'})
		h.Write([]byte(normaliseSnippet(f.Message)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Assign fills in the Fingerprint field of every finding in place.
func Assign(fs []model.Finding) {
	for i := range fs {
		fs[i].Fingerprint = Fingerprint(fs[i])
	}
}

func normalisePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	// Strip a leading sandbox mount prefix so host and container paths agree.
	p = strings.TrimPrefix(p, "/src/")
	return path.Clean(p)
}

func normaliseSnippet(s string) string {
	// Collapse all runs of whitespace to single spaces and trim, so reflowing
	// or reindenting code doesn't change the fingerprint.
	return strings.Join(strings.Fields(s), " ")
}

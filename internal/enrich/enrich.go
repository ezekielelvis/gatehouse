// Package enrich adds prioritisation data to vulnerability findings from
// locally mirrored feeds (plan §6): CVSS base score, EPSS exploit probability,
// and the CISA KEV "known exploited" flag. The UI and policies can then sort by
// *risk* rather than raw count. Everything is offline: the feeds are plain
// files under the mirror directory, refreshed by `gatehouse db update`.
package enrich

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/gatehouse/gatehouse/internal/model"
)

// Mirror holds the locally mirrored prioritisation feeds, keyed by CVE/advisory
// id. It is safe to use with empty maps (enrichment simply adds nothing).
type Mirror struct {
	cvss map[string]float64
	epss map[string]float64
	kev  map[string]bool
}

// Empty returns a Mirror that enriches nothing — the zero-value fallback when
// no mirror has been downloaded yet.
func Empty() *Mirror {
	return &Mirror{cvss: map[string]float64{}, epss: map[string]float64{}, kev: map[string]bool{}}
}

// Load reads the mirror files from dir. Missing files are tolerated (that feed
// is simply unavailable). Expected files:
//
//	cvss.json  {"CVE-2024-1": 9.8, ...}
//	epss.csv   CVE-2024-1,0.97           (cve,probability per line)
//	kev.json   ["CVE-2024-1", ...]       (known-exploited CVE ids)
func Load(dir string) (*Mirror, error) {
	m := Empty()
	if dir == "" {
		return m, nil
	}
	if err := loadJSONMap(filepath.Join(dir, "cvss.json"), m.cvss); err != nil {
		return nil, err
	}
	if err := loadEPSS(filepath.Join(dir, "epss.csv"), m.epss); err != nil {
		return nil, err
	}
	if err := loadKEV(filepath.Join(dir, "kev.json"), m.kev); err != nil {
		return nil, err
	}
	return m, nil
}

// Apply enriches vulnerability findings in place and returns them sorted by
// descending risk so the most urgent appear first.
func (m *Mirror) Apply(findings []model.Finding) []model.Finding {
	for i := range findings {
		f := &findings[i]
		if f.Family != model.FamilyVuln {
			continue
		}
		for _, id := range candidateIDs(*f) {
			if v, ok := m.cvss[id]; ok && f.CVSS == 0 {
				f.CVSS = v
			}
			if v, ok := m.epss[id]; ok && f.EPSS == 0 {
				f.EPSS = v
			}
			if m.kev[id] {
				f.KEV = true
			}
		}
		// Promote severity from CVSS when the tool gave none.
		if f.Severity == model.SevUnknown && f.CVSS > 0 {
			f.Severity = cvssToSeverity(f.CVSS)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool { return Risk(findings[i]) > Risk(findings[j]) })
	return findings
}

// Risk is a single prioritisation score combining severity, exploit
// probability and known-exploited status. Higher is more urgent. Exposed so the
// UI and reports can sort consistently.
func Risk(f model.Finding) float64 {
	score := float64(f.Severity) * 10 // 0..50 baseline from the severity band
	if f.CVSS > 0 {
		score += f.CVSS // 0..10
	}
	score += f.EPSS * 20 // exploit probability weighs heavily (0..20)
	if f.KEV {
		score += 50 // known-exploited dominates
	}
	return score
}

// candidateIDs returns the identifiers a finding might be keyed under in the
// feeds: its rule id (often the CVE) and any CVE-shaped tokens in its message.
func candidateIDs(f model.Finding) []string {
	ids := []string{}
	if strings.HasPrefix(f.RuleID, "CVE-") || strings.HasPrefix(f.RuleID, "GHSA-") {
		ids = append(ids, f.RuleID)
	}
	for _, tok := range strings.FieldsFunc(f.Message, func(r rune) bool {
		return r == ' ' || r == ',' || r == '(' || r == ')' || r == ':'
	}) {
		if strings.HasPrefix(tok, "CVE-") {
			ids = append(ids, tok)
		}
	}
	return ids
}

func cvssToSeverity(v float64) model.Severity {
	switch {
	case v >= 9.0:
		return model.SevCritical
	case v >= 7.0:
		return model.SevHigh
	case v >= 4.0:
		return model.SevMedium
	case v > 0:
		return model.SevLow
	default:
		return model.SevUnknown
	}
}

func loadJSONMap(path string, dst map[string]float64) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &dst)
}

func loadEPSS(path string, dst map[string]float64) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
			dst[strings.TrimSpace(parts[0])] = v
		}
	}
	return sc.Err()
}

func loadKEV(path string, dst map[string]bool) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var ids []string
	if err := json.Unmarshal(data, &ids); err != nil {
		return fmt.Errorf("parse kev: %w", err)
	}
	for _, id := range ids {
		dst[id] = true
	}
	return nil
}

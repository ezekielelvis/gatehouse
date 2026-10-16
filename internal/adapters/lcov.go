package adapters

import (
	"bufio"
	"io"
	"path"
	"strconv"
	"strings"

	"github.com/gatehouse/gatehouse/internal/model"
)

// Coverage holds per-file line-hit data parsed from an lcov report, enough to
// compute both overall and changed-lines coverage.
type Coverage struct {
	// Files maps a normalised file path to its line-number → hit-count map.
	Files map[string]map[int]int
}

// ParseLCOV reads an lcov tracefile. The relevant records are:
//
//	SF:<path>      start of a file section
//	DA:<line>,<hits>  a line's execution count
//	end_of_record
//
// Other records (functions, branches) are ignored for v1.
func ParseLCOV(r io.Reader) (*Coverage, error) {
	cov := &Coverage{Files: map[string]map[int]int{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var cur string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "SF:"):
			cur = normalisePath(line[3:])
			if cov.Files[cur] == nil {
				cov.Files[cur] = map[int]int{}
			}
		case strings.HasPrefix(line, "DA:") && cur != "":
			rest := line[3:]
			comma := strings.IndexByte(rest, ',')
			if comma < 0 {
				continue
			}
			lineNo, err1 := strconv.Atoi(rest[:comma])
			hits, err2 := strconv.Atoi(strings.SplitN(rest[comma+1:], ",", 2)[0])
			if err1 != nil || err2 != nil {
				continue
			}
			cov.Files[cur][lineNo] = hits
		case line == "end_of_record":
			cur = ""
		}
	}
	return cov, sc.Err()
}

// Overall returns the fraction (0-100) of instrumented lines that were hit at
// least once across all files.
func (c *Coverage) Overall() float64 {
	var total, hit int
	for _, lines := range c.Files {
		for _, h := range lines {
			total++
			if h > 0 {
				hit++
			}
		}
	}
	return pct(hit, total)
}

// ChangedLines returns coverage restricted to the given changed files (matched
// by normalised path suffix). This is the gate that matters: "new code is
// tested". Returns (value, true) only when at least one changed file had
// instrumented lines; otherwise (0, false) so the caller can omit the metric.
func (c *Coverage) ChangedLines(changed []string) (float64, bool) {
	changedSet := make(map[string]bool, len(changed))
	for _, p := range changed {
		changedSet[normalisePath(p)] = true
	}
	var total, hit int
	for file, lines := range c.Files {
		if !matchesChanged(file, changedSet) {
			continue
		}
		for _, h := range lines {
			total++
			if h > 0 {
				hit++
			}
		}
	}
	if total == 0 {
		return 0, false
	}
	return pct(hit, total), true
}

// Metrics renders coverage into the model's metric set. changed may be nil.
func (c *Coverage) Metrics(changed []string) []model.Metric {
	ms := []model.Metric{{Key: "coverage.line", Value: c.Overall()}}
	if v, ok := c.ChangedLines(changed); ok {
		ms = append(ms, model.Metric{Key: "coverage.changed_lines", Value: v})
	}
	return ms
}

// matchesChanged reports whether a coverage file path corresponds to one of the
// changed files. lcov and git may spell paths differently (absolute vs
// repo-relative), so we match on a path-suffix basis.
func matchesChanged(file string, changed map[string]bool) bool {
	if changed[file] {
		return true
	}
	for c := range changed {
		if strings.HasSuffix(file, "/"+c) || strings.HasSuffix(c, "/"+file) {
			return true
		}
	}
	return false
}

func normalisePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/src/")
	return path.Clean(p)
}

func pct(hit, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(hit) / float64(total) * 100
}

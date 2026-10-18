package ui

import (
	"fmt"
	"html/template"
	"strings"
)

// Server-rendered SVG charts — no JS charting library, so the UI stays offline
// and CSP-clean. Each returns template.HTML ready to drop into a page.

// sparkline draws a small line chart of values (oldest→newest) with the given
// stroke colour token. Returns an empty string for <2 points.
func sparkline(values []float64, stroke string) template.HTML {
	if len(values) < 2 {
		return ""
	}
	const w, h, pad = 460, 90, 6
	min, max := values[0], values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	span := max - min
	if span == 0 {
		span = 1
	}
	n := len(values)
	var pts strings.Builder
	for i, v := range values {
		x := pad + float64(i)*(float64(w-2*pad)/float64(n-1))
		y := float64(h-pad) - (v-min)/span*float64(h-2*pad)
		if i > 0 {
			pts.WriteByte(' ')
		}
		fmt.Fprintf(&pts, "%.1f,%.1f", x, y)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" width="100%%" height="%d" preserveAspectRatio="none" role="img">`, w, h, h)
	fmt.Fprintf(&b, `<polyline fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" points="%s"/>`, stroke, pts.String())
	// end dot
	last := strings.Fields(pts.String())
	if len(last) > 0 {
		xy := strings.Split(last[len(last)-1], ",")
		fmt.Fprintf(&b, `<circle cx="%s" cy="%s" r="3" fill="%s"/>`, xy[0], xy[1], stroke)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // values are numeric, stroke is a fixed token
}

// Bar is one labelled bar for barChart.
type Bar struct {
	Label string
	Count int
	Color string // CSS colour/token
}

// barChart draws a horizontal bar chart (e.g. findings by severity).
func barChart(bars []Bar) template.HTML {
	max := 1
	for _, b := range bars {
		if b.Count > max {
			max = b.Count
		}
	}
	var b strings.Builder
	b.WriteString(`<div class="hbars">`)
	for _, bar := range bars {
		pct := float64(bar.Count) / float64(max) * 100
		fmt.Fprintf(&b, `<div class="hbar"><div class="hbar-head"><span>%s</span><b class="nums">%d</b></div>`,
			template.HTMLEscapeString(bar.Label), bar.Count)
		fmt.Fprintf(&b, `<div class="hbar-track"><span style="width:%.1f%%;background:%s"></span></div></div>`, pct, bar.Color)
	}
	b.WriteString(`</div>`)
	return template.HTML(b.String()) //nolint:gosec // labels escaped, widths numeric
}

package main

import (
	"fmt"
	"html/template"
	"strings"
)

// renderHitChart builds a simple SVG bar chart for the stats page. No
// external chart library — the plugin UI runs in a sandboxed iframe.
func renderHitChart(buckets []HitBucket) template.HTML {
	const (
		width   = 920
		height  = 280
		padL    = 44
		padR    = 16
		padT    = 20
		padB    = 48
	)
	plotW := width - padL - padR
	plotH := height - padT - padB

	var max int64
	for _, b := range buckets {
		if b.Count > max {
			max = b.Count
		}
	}
	if max < 1 {
		max = 1
	}

	n := len(buckets)
	if n == 0 {
		return template.HTML(`<p class="muted">Keine Daten für den gewählten Zeitraum.</p>`)
	}

	gap := 4.0
	barW := float64(plotW)/float64(n) - gap
	if barW < 2 {
		barW = 2
		gap = 1
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="hit-chart" viewBox="0 0 %d %d" role="img" aria-label="Blockierte Anfragen">`, width, height)
	// Grid lines
	for i := 0; i <= 4; i++ {
		y := float64(padT) + float64(plotH)*float64(i)/4
		val := max - (max * int64(i) / 4)
		fmt.Fprintf(&b, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" class="chart-grid"/>`, padL, y, width-padR, y)
		fmt.Fprintf(&b, `<text x="%d" y="%.1f" class="chart-axis" text-anchor="end" dy="0.35em">%d</text>`, padL-8, y, val)
	}

	labelEvery := 1
	if n > 14 {
		labelEvery = 2
	}
	if n > 24 {
		labelEvery = 3
	}

	for i, bucket := range buckets {
		x := float64(padL) + float64(i)*(barW+gap)
		h := float64(bucket.Count) / float64(max) * float64(plotH)
		y := float64(padT+plotH) - h
		if h < 1 && bucket.Count > 0 {
			h = 1
			y = float64(padT+plotH) - h
		}
		fmt.Fprintf(&b,
			`<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" class="chart-bar" rx="3"><title>%s: %d</title></rect>`,
			x, y, barW, h, template.HTMLEscapeString(bucket.Label), bucket.Count)
		if i%labelEvery == 0 || i == n-1 {
			fmt.Fprintf(&b,
				`<text x="%.1f" y="%d" class="chart-axis" text-anchor="middle">%s</text>`,
				x+barW/2, height-14, template.HTMLEscapeString(bucket.Label))
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

package web

import (
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"math"
	"strings"
)

// Charts are rendered on the server as inline SVG: no chart library, no
// external script, and they work with the strict CSP. charts.js adds the
// hover layer on top of the data-* attributes written here.

type series struct {
	Name   string
	Slot   int // categorical slot 1..8, see --series-N in style.css
	Values []float64
}

const (
	chartW, chartH = 640.0, 220.0
	padL, padR     = 44.0, 12.0
	padT, padB     = 14.0, 26.0
)

// areaChart draws one or more smooth lines with a soft fill on one y-axis.
func areaChart(id string, labels []string, ss []series) template.HTML {
	n := len(labels)
	if n == 0 {
		return `<p class="muted small">—</p>`
	}
	peak := 0.0
	for _, s := range ss {
		for _, v := range s.Values {
			peak = math.Max(peak, v)
		}
	}
	// Four gridlines on a 1/2/5×10ⁿ step, integers only.
	step := niceStep(peak / 4)
	top := step * 4
	x := func(i int) float64 {
		if n == 1 {
			return padL + (chartW-padL-padR)/2
		}
		return padL + float64(i)*(chartW-padL-padR)/float64(n-1)
	}
	y := func(v float64) float64 { return chartH - padB - v/top*(chartH-padT-padB) }

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart area" viewBox="0 0 %g %g" role="img" aria-label="%s"`, chartW, chartH, html.EscapeString(seriesNames(ss)))
	// Hover data: labels and every series' values, read by charts.js.
	pts := map[string]any{"labels": labels, "x0": padL, "x1": chartW - padR}
	var js []map[string]any
	for _, s := range ss {
		js = append(js, map[string]any{"name": s.Name, "slot": s.Slot, "values": s.Values})
	}
	pts["series"] = js
	raw, _ := json.Marshal(pts)
	fmt.Fprintf(&b, ` data-chart="%s">`, html.EscapeString(string(raw)))

	b.WriteString(`<defs>`)
	for _, s := range ss {
		fmt.Fprintf(&b, `<linearGradient id="%s-g%d" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="stop s%d" stop-opacity=".28"/><stop offset="1" class="stop s%d" stop-opacity="0"/></linearGradient>`, id, s.Slot, s.Slot, s.Slot)
	}
	b.WriteString(`</defs>`)

	// Recessive grid with three value labels.
	for i := 0; i <= 4; i++ {
		v := step * float64(i)
		gy := y(v)
		fmt.Fprintf(&b, `<line class="grid" x1="%g" x2="%g" y1="%.1f" y2="%.1f"/>`, padL, chartW-padR, gy, gy)
		fmt.Fprintf(&b, `<text class="axis" x="%g" y="%.1f" text-anchor="end">%s</text>`, padL-6, gy+4, compact(int64(v)))
	}
	every := max(1, n/6)
	for i := 0; i < n; i += every {
		fmt.Fprintf(&b, `<text class="axis" x="%.1f" y="%g" text-anchor="middle">%s</text>`, x(i), chartH-8, html.EscapeString(labels[i]))
	}
	for _, s := range ss {
		xs := make([]float64, len(s.Values))
		ys := make([]float64, len(s.Values))
		for i, v := range s.Values {
			xs[i], ys[i] = x(i), y(v)
		}
		line := smoothPath(xs, ys)
		if line == "" {
			continue
		}
		fmt.Fprintf(&b, `<path class="fill" fill="url(#%s-g%d)" d="%s L%.1f,%.1f L%.1f,%.1f Z"/>`, id, s.Slot, line, xs[len(xs)-1], y(0), xs[0], y(0))
		fmt.Fprintf(&b, `<path class="line s%d" d="%s"/>`, s.Slot, line)
	}
	b.WriteString(`<line class="cross" y1="` + fmt.Sprint(padT) + `" y2="` + fmt.Sprint(chartH-padB) + `" x1="0" x2="0" visibility="hidden"/>`)
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func seriesNames(ss []series) string {
	var n []string
	for _, s := range ss {
		n = append(n, s.Name)
	}
	return strings.Join(n, ", ")
}

// smoothPath is a monotone cubic through the points (Fritsch–Carlson), so
// the curve never dips below zero or overshoots a peak like a plain spline.
func smoothPath(xs, ys []float64) string {
	n := len(xs)
	if n == 0 {
		return ""
	}
	if n == 1 {
		return fmt.Sprintf("M%.1f,%.1f", xs[0], ys[0])
	}
	d := make([]float64, n-1)
	for i := 0; i < n-1; i++ {
		d[i] = (ys[i+1] - ys[i]) / (xs[i+1] - xs[i])
	}
	m := make([]float64, n)
	m[0], m[n-1] = d[0], d[n-2]
	for i := 1; i < n-1; i++ {
		if d[i-1]*d[i] <= 0 {
			m[i] = 0
		} else {
			m[i] = (d[i-1] + d[i]) / 2
		}
	}
	for i := 0; i < n-1; i++ {
		if d[i] == 0 {
			m[i], m[i+1] = 0, 0
			continue
		}
		a, bb := m[i]/d[i], m[i+1]/d[i]
		if s := a*a + bb*bb; s > 9 {
			t := 3 / math.Sqrt(s)
			m[i], m[i+1] = t*a*d[i], t*bb*d[i]
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "M%.1f,%.1f", xs[0], ys[0])
	for i := 0; i < n-1; i++ {
		h := (xs[i+1] - xs[i]) / 3
		fmt.Fprintf(&b, " C%.1f,%.1f %.1f,%.1f %.1f,%.1f", xs[i]+h, ys[i]+m[i]*h, xs[i+1]-h, ys[i+1]-m[i+1]*h, xs[i+1], ys[i+1])
	}
	return b.String()
}

// niceStep rounds a grid step up to 1, 2 or 5 times a power of ten, at
// least 1 so a chart of counts never shows fractional ticks.
func niceStep(v float64) float64 {
	if v <= 1 {
		return 1
	}
	p := math.Pow(10, math.Floor(math.Log10(v)))
	for _, f := range []float64{1, 2, 5, 10} {
		if f*p >= v {
			return f * p
		}
	}
	return 10 * p
}

type slice struct {
	Label string
	Value int64
	Slot  int
	Pct   int
}

// donut draws a ring of up to six slices; the rest folds into "Other".
func donut(items []slice, centerLabel string) template.HTML {
	var total int64
	for _, s := range items {
		total += s.Value
	}
	const r, sw = 52.0, 16.0
	circ := 2 * math.Pi * r
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart donut" viewBox="0 0 140 140" role="img" aria-label="%s">`, html.EscapeString(centerLabel))
	fmt.Fprintf(&b, `<circle class="track" cx="70" cy="70" r="%g" stroke-width="%g"/>`, r, sw)
	if total > 0 {
		off := 0.0
		gap := 2.0 // surface gap between slices
		for _, s := range items {
			if s.Value == 0 {
				continue
			}
			l := circ * float64(s.Value) / float64(total)
			seg := math.Max(l-gap, 0.5)
			if len(items) == 1 || l >= circ-0.01 {
				seg = circ
			}
			fmt.Fprintf(&b, `<circle class="seg s%d" cx="70" cy="70" r="%g" stroke-width="%g" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 70 70)" data-tip="%s"><title>%s</title></circle>`,
				s.Slot, r, sw, seg, circ-seg, -off, html.EscapeString(fmt.Sprintf("%s: %d (%d%%)", s.Label, s.Value, s.Pct)), html.EscapeString(fmt.Sprintf("%s: %d", s.Label, s.Value)))
			off += l
		}
	}
	fmt.Fprintf(&b, `<text class="dv" x="70" y="72" text-anchor="middle">%s</text><text class="dl" x="70" y="90" text-anchor="middle">%s</text></svg>`, compact(total), html.EscapeString(centerLabel))
	return template.HTML(b.String())
}

// slices turns counts into donut slices, folding the tail into "Other".
func slices6(keys []string, vals []int64) []slice {
	var total int64
	for _, v := range vals {
		total += v
	}
	var out []slice
	var other int64
	for i := range keys {
		if vals[i] == 0 {
			continue
		}
		if len(out) == 5 && len(keys) > 6 {
			other += vals[i]
			continue
		}
		out = append(out, slice{Label: keys[i], Value: vals[i], Slot: len(out) + 1})
	}
	if other > 0 {
		out = append(out, slice{Label: "Other", Value: other, Slot: 0})
	}
	for i := range out {
		if total > 0 {
			out[i].Pct = int(out[i].Value * 100 / total)
		}
	}
	return out
}

// sparkline is a tiny trend line for stat tiles.
func sparkline(vals []float64, slot int) template.HTML {
	if len(vals) < 2 {
		return ""
	}
	const w, h = 120.0, 32.0
	peak := 0.0
	for _, v := range vals {
		peak = math.Max(peak, v)
	}
	if peak == 0 {
		peak = 1
	}
	xs := make([]float64, len(vals))
	ys := make([]float64, len(vals))
	for i, v := range vals {
		xs[i] = float64(i) * w / float64(len(vals)-1)
		ys[i] = h - 2 - v/peak*(h-4)
	}
	p := smoothPath(xs, ys)
	return template.HTML(fmt.Sprintf(`<svg class="spark" viewBox="0 0 %g %g" preserveAspectRatio="none" aria-hidden="true"><path class="sfill s%d" d="%s L%g,%g L0,%g Z"/><path class="line s%d" d="%s"/></svg>`, w, h, slot, p, w, h, h, slot, p))
}

// compact writes 23491 as "23.5k".
func compact(n int64) string {
	f := float64(n)
	switch {
	case n >= 1_000_000:
		return trimZero(fmt.Sprintf("%.1f", f/1e6)) + "M"
	case n >= 10_000:
		return trimZero(fmt.Sprintf("%.1f", f/1e3)) + "k"
	default:
		return fmt.Sprint(n)
	}
}

func trimZero(s string) string { return strings.TrimSuffix(s, ".0") }

// httpHighlight colours a raw HTTP message: method and path on the first
// line, header names, and every occurrence of the attack payload.
func httpHighlight(raw, payload string) template.HTML {
	if raw == "" {
		return template.HTML(html.EscapeString("—"))
	}
	mark := func(s string) string {
		e := html.EscapeString(s)
		if p := html.EscapeString(payload); len(payload) >= 3 {
			e = strings.ReplaceAll(e, p, "<mark>"+p+"</mark>")
		}
		return e
	}
	head, body, _ := strings.Cut(strings.ReplaceAll(raw, "\r\n", "\n"), "\n\n")
	lines := strings.Split(head, "\n")
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		if i == 0 {
			parts := strings.SplitN(l, " ", 3)
			if len(parts) == 3 && !strings.HasPrefix(parts[0], "HTTP/") {
				fmt.Fprintf(&b, `<span class="m">%s</span> <span class="p">%s</span> %s`, html.EscapeString(parts[0]), mark(parts[1]), html.EscapeString(parts[2]))
			} else {
				fmt.Fprintf(&b, `<span class="m">%s</span>`, html.EscapeString(l))
			}
			continue
		}
		if k, v, ok := strings.Cut(l, ":"); ok {
			fmt.Fprintf(&b, `<span class="k">%s</span>:%s`, html.EscapeString(k), mark(v))
		} else {
			b.WriteString(mark(l))
		}
	}
	if body != "" {
		b.WriteString("\n\n" + mark(body))
	}
	return template.HTML(b.String())
}

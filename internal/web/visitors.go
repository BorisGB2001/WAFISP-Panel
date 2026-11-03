package web

import (
	"html/template"
	"net/http"
	"slices"
	"time"

	"wafisp/internal/visitors"
)

// donutCard is one ring with its legend.
type donutCard struct {
	Title  string
	Donut  template.HTML
	Slices []slice
}

// visitorLabels name the fixed keys of the access log counters.
var visitorLabels = map[string]string{
	"desktop": "Desktop", "mobile": "Phone", "tablet": "Tablet",
	"browser": "Browsers", "bot": "Bots", "script": "Scripts and scanners", "empty": "No User-Agent",
	"direct": "Direct", "internal": "Within the site", "search": "Search engines", "social": "Social networks", "other": "Other sites",
	visitors.OtherKey: "Other",
}

func (s *Server) visitorsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	f := viewFilter(w, r, "24h")
	data := map[string]any{"F": f, "Periods": periods, "Sites": s.siteNames(), "Off": s.Visitors == nil}
	if s.Visitors == nil {
		s.render(w, r, rc, "visitors.html", page{Title: "Visitors", Active: "visitors", Data: data})
		return
	}
	now := time.Now()
	rep := s.Visitors.Report(f.since(), now, f.Site)
	a := rep.Total
	ring := func(title string, c visitors.Counts, center string) donutCard {
		top := counter(c).top(50)
		keys, vals := make([]string, len(top)), make([]int64, len(top))
		for i, x := range top {
			keys[i], vals[i] = x.Key, int64(x.Count)
			if l, ok := visitorLabels[x.Key]; ok {
				keys[i] = tr(r, l)
			}
		}
		sl := slices6(keys, vals)
		return donutCard{Title: tr(r, title), Donut: donut(sl, center), Slices: sl}
	}
	errors5 := 0
	for k, v := range a.Status {
		if len(k) == 3 && k[0] == '5' {
			errors5 += v
		}
	}
	data["Rep"] = rep
	data["Bots"] = a.Kind["bot"]
	data["Scripts"] = a.Kind["script"] + a.Kind["empty"]
	data["NotFound"] = a.Status["404"]
	data["Errors5"] = errors5
	data["Chart"] = areaChart("vis", rep.Labels, []series{{Name: tr(r, "requests"), Slot: 1, Values: rep.Series}, {Name: tr(r, "page views"), Slot: 3, Values: rep.Views}})
	data["Rings"] = []donutCard{
		ring("Devices", a.Device, tr(r, "page views")),
		ring("Clients", a.Kind, tr(r, "requests")),
		ring("Response codes", a.Status, tr(r, "requests")),
		ring("Where visitors come from", a.Source, tr(r, "page views")),
	}
	top := func(c visitors.Counts, n int) []kv {
		l := counter(c).top(n)
		for i := range l {
			if t, ok := visitorLabels[l[i].Key]; ok && l[i].Key == visitors.OtherKey {
				l[i].Key = tr(r, t)
			}
		}
		return l
	}
	data["Search"], data["Social"], data["Referrers"] = top(a.Search, 10), top(a.Social, 10), top(a.Referrer, 15)
	data["OS"], data["Browsers"] = top(a.OS, 10), top(a.Browser, 10)
	data["Pages"], data["Missing"] = top(a.Page, 15), top(a.NotFound, 15)
	data["BotList"], data["ScriptList"] = top(a.Bot, 15), top(a.Script, 15)
	data["SiteList"] = counter(rep.Sites).top(15)
	files := s.VisitorLogs.Files()
	slices.SortFunc(files, func(x, y visitors.FileStat) int { return int(y.Lines - x.Lines) })
	data["Files"], data["Glob"] = files, s.Cfg.AccessLogs.Glob
	s.render(w, r, rc, "visitors.html", page{Title: "Visitors", Active: "visitors", Data: data})
}

package web

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"wafisp/internal/event"
	"wafisp/internal/policy"
	"wafisp/internal/store"
)

type catOption struct{ Code, Name string }

func categoryOptions() []catOption {
	var out []catOption
	for _, c := range event.Categories {
		out = append(out, catOption{c.Code, c.Name})
	}
	return out
}

func (s *Server) siteNames() []string {
	var out []string
	for _, x := range s.Sites.Sites() {
		out = append(out, x.Name)
	}
	return out
}

// ---------- overview ----------

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	f := parseFilter(r, "24h")
	now := time.Now()
	a := aggregate(s.Store, f, now)
	cats := a.Cats.top(20)
	keys := make([]string, len(cats))
	vals := make([]int64, len(cats))
	for i, c := range cats {
		keys[i], vals[i] = event.CategoryName(c.Key), int64(c.Count)
	}
	slices := slices6(keys, vals)
	rules := a.Rules.top(10)
	for i := range rules {
		rules[i].Extra = a.RuleMsg[rules[i].Key]
	}
	pending, lastErr, _ := s.Policy.Status()
	data := map[string]any{
		"F": f, "Periods": periods, "A": a, "UniqueIPs": len(a.IPs), "SitesHit": len(a.Sites),
		"Chart":       areaChart("ov", a.Labels, []series{{Name: tr(r, "blocked"), Slot: 1, Values: a.BucketDenied}, {Name: tr(r, "passed"), Slot: 3, Values: a.BucketPassed}}),
		"CatsDonut":   donut(slices, tr(r, "events")),
		"CatSlices":   slices,
		"IPs":         s.topIPs(a.IPs, 10, pref(r, "hide_blocked")),
		"Sites":       a.Sites.top(10),
		"Rules":       rules,
		"Paths":       s.topPaths(a.Paths, 10, pref(r, "hide_trapped")),
		"HideBlocked": pref(r, "hide_blocked"), "HideTrapped": pref(r, "hide_trapped"), "Self": r.URL.RequestURI(),
		"Countries":  a.Countries.top(10),
		"Files":      s.Collector.Files(),
		"Stored":     s.Store.Len(),
		"Oldest":     s.Store.Oldest(),
		"Blocks":     len(s.Blocks.Entries()),
		"BlockErrs":  s.Blocks.Errors(),
		"Pending":    pending,
		"PolicyErr":  lastErr,
		"Exclusions": len(s.Policy.State().Exclusions),
	}
	s.render(w, r, rc, "dashboard.html", page{Title: "Overview", Active: "dash", Data: data})
}

// ---------- attack log ----------

const pageSize = 50

func (s *Server) attacks(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	f := parseFilter(r, "24h")
	var rows []store.Summary
	total := 0
	from := (f.Page - 1) * pageSize
	s.Store.Scan(f.since(), func(e *store.Summary) bool {
		if !f.match(e) {
			return true
		}
		if total >= from && total < from+pageSize {
			rows = append(rows, *e)
		}
		total++
		return true
	})
	pages := max(1, (total+pageSize-1)/pageSize)
	var ips []string
	allowed := map[string]bool{}
	for _, x := range rows {
		ips = append(ips, x.SrcIP)
		if _, seen := allowed[x.SrcIP]; !seen {
			allowed[x.SrcIP] = s.allowed(x.SrcIP)
		}
	}
	s.render(w, r, rc, "attacks.html", page{Title: "Attack log", Active: "attacks", Data: map[string]any{
		"F": f, "Rows": rows, "Total": total, "Pages": pages, "Periods": periods, "Cats": categoryOptions(),
		"Sites": s.siteNames(), "Prev": f.Query(f.Page - 1), "Next": f.Query(f.Page + 1), "CSV": f.Query(0),
		"DefaultBackends": s.Cfg.Block.Default, "Blocked": s.Blocks.Blocked(ips), "Allowed": allowed,
	}})
}

const csvMax = 50000

func (s *Server) attacksCSV(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	f := parseFilter(r, "24h")
	var buf bytes.Buffer
	buf.WriteString("\uFEFF") // Excel opens UTF-8 CSV correctly with a BOM
	cw := csv.NewWriter(&buf)
	cw.Comma = ';'
	cw.Write([]string{"time", "site", "event_id", "src_ip", "country", "method", "path", "status", "action", "score", "category", "rules", "variables", "message"})
	n := 0
	s.Store.Scan(f.since(), func(e *store.Summary) bool {
		if !f.match(e) {
			return true
		}
		cw.Write([]string{e.Time.Local().Format(time.DateTime), e.Site, e.ID, e.SrcIP, e.Country, e.Method, e.Path,
			strconv.Itoa(e.Status), map[bool]string{true: "deny", false: "pass"}[e.Denied], strconv.Itoa(e.Score),
			e.Category, strings.Join(e.Rules, " "), strings.Join(e.Vars, " "), e.Reason})
		n++
		return n < csvMax
	})
	cw.Flush()
	s.audit.Log(rc.User.Name, clientIP(r), "attacks.export", fmt.Sprintf("%d rows, %s", n, f.Query(0)))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="waf-events-%s.csv"`, time.Now().Format("20060102-1504")))
	w.Write(buf.Bytes())
}

func (s *Server) attackDetail(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ev, err := s.Store.Get(r.PathValue("id"))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		s.render(w, r, rc, "attack.html", page{Title: "Event", Active: "attacks", Error: err.Error(), Data: map[string]any{}})
		return
	}
	var req strings.Builder
	fmt.Fprintf(&req, "%s %s %s\n", ev.Method, ev.URI, ev.Proto)
	for _, h := range ev.Headers {
		fmt.Fprintf(&req, "%s: %s\n", h.Name, h.Value)
	}
	if ev.Body != "" {
		req.WriteString("\n" + ev.Body)
	}
	payload := ""
	if m := ev.Top(); m != nil {
		payload = matchedValue(m.Data)
	}
	scheme := "https"
	if ev.DstPort == 80 {
		scheme = "http"
	}
	blocked, isBlocked := s.Blocks.Lookup(ev.SrcIP)
	site, _ := s.Sites.Get(ev.Site)
	s.render(w, r, rc, "attack.html", page{Title: "Event", Active: "attacks", Data: map[string]any{
		"E": ev, "ReqHTML": httpHighlight(req.String(), payload), "ReqRaw": req.String(), "Scheme": scheme,
		"Blocked": blocked, "IsBlocked": isBlocked, "Allowed": s.allowed(ev.SrcIP), "Allow": allowOf(s, ev.SrcIP), "Backends": s.Blocks.Names(),
		"DefaultBackends": s.Cfg.Block.Default, "TTLs": blockTTLs, "SiteMode": s.Policy.State().ModeOf(ev.Site),
		"SiteWAF": site.WAF,
	}})
}

// matchedValue pulls the matched value out of CRS's data field, e.g.
// "Matched Data: union select found within ARGS:q: ..." gives "union select".
func matchedValue(data string) string {
	v, ok := strings.CutPrefix(data, "Matched Data: ")
	if !ok {
		return ""
	}
	if i := strings.Index(v, " found within "); i > 0 {
		return v[:i]
	}
	return ""
}

func (s *Server) allowed(ip string) bool {
	_, ok := s.allowEntry(ip)
	return ok
}

// allowEntry is the allow-list entry that covers ip, if any.
func (s *Server) allowEntry(ip string) (policy.Addr, bool) {
	st := s.Policy.State()
	return st.AllowedFor(ip)
}

// markBlocked sets Extra of every top-list address that is blocked.
func (s *Server) markBlocked(list []kv) []kv {
	for i := range list {
		if _, ok := s.Blocks.Lookup(list[i].Key); ok {
			list[i].Extra = "blocked"
		} else if s.allowed(list[i].Key) {
			list[i].Extra = "allowed"
		}
	}
	return list
}

// topIPs is the top n addresses, marked; with hide the blocked ones are
// left out and the list is filled from further down.
func (s *Server) topIPs(c counter, n int, hide bool) []kv {
	list := s.markBlocked(c.top(n + 500))
	if hide {
		list = slices.DeleteFunc(list, func(x kv) bool { return x.Extra == "blocked" })
	}
	return list[:min(n, len(list))]
}

// topPaths is the top n paths, marked; with hide the trapped ones are left
// out.
func (s *Server) topPaths(c counter, n int, hide bool) []kv {
	list := s.markTraps(c.top(n + 500))
	if hide {
		list = slices.DeleteFunc(list, func(x kv) bool { return x.Extra != "" })
	}
	return list[:min(n, len(list))]
}

// trapOf is the id of the enabled trap that site+path falls into, or "".
func trapOf(traps []policy.Trap, site, path string) string {
	for _, t := range traps {
		if t.Matches(site, path) {
			return strconv.Itoa(t.ID)
		}
	}
	return ""
}

// markTraps sets Extra of every top-list path (site+path) a trap covers.
func (s *Server) markTraps(list []kv) []kv {
	traps := s.Policy.State().Traps
	for i := range list {
		if j := strings.Index(list[i].Key, "/"); j >= 0 {
			list[i].Extra = trapOf(traps, list[i].Key[:j], list[i].Key[j:])
		}
	}
	return list
}

// ---------- analysis ----------

func (s *Server) analysis(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	f := parseFilter(r, "7d")
	minIPs, _ := strconv.Atoi(r.URL.Query().Get("min_ips"))
	if minIPs <= 0 {
		minIPs = 3
	}
	a := aggregate(s.Store, f, time.Now())
	attackers := s.topIPs(a.IPs, 30, pref(r, "hide_blocked"))
	rules := a.Rules.top(30)
	for i := range rules {
		rules[i].Extra = a.RuleMsg[rules[i].Key]
	}
	s.render(w, r, rc, "analysis.html", page{Title: "Analysis", Active: "analysis", Data: map[string]any{
		"F": f, "Periods": periods, "Sites": s.siteNames(), "MinIPs": minIPs,
		"Candidates": candidates(s.Store, f, minIPs), "Attackers": attackers, "Rules": rules,
		"Paths": s.topPaths(a.Paths, 30, pref(r, "hide_trapped")), "Countries": a.Countries.top(30), "Total": a.Total,
		"HideBlocked": pref(r, "hide_blocked"), "HideTrapped": pref(r, "hide_trapped"), "Self": r.URL.RequestURI(),
	}})
}

// ---------- one address ----------

func (s *Server) ipPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ip := r.PathValue("ip")
	if _, err := netip.ParseAddr(ip); err != nil {
		http.NotFound(w, r)
		return
	}
	f := parseFilter(r, "30d")
	f.IP = ip
	a := aggregate(s.Store, f, time.Now())
	var recent []store.Summary
	var first, last time.Time
	s.Store.Scan(f.since(), func(e *store.Summary) bool {
		if !f.match(e) {
			return true
		}
		if len(recent) < 30 {
			recent = append(recent, *e)
		}
		if last.IsZero() {
			last = e.Time
		}
		first = e.Time
		return true
	})
	blocked, isBlocked := s.Blocks.Lookup(ip)
	traps := s.Policy.State().Traps
	trapped := map[string]string{}
	for _, e := range recent {
		trapped[e.Site+e.Path] = trapOf(traps, e.Site, e.Path)
	}
	country := ""
	if len(recent) > 0 {
		country = recent[0].Country
	}
	s.render(w, r, rc, "ip.html", page{Title: "Address", Active: "attacks", Data: map[string]any{
		"IP": ip, "F": f, "A": a, "Recent": recent, "First": first, "Last": last, "Country": country,
		"Sites": a.Sites.top(20), "Rules": a.Rules.top(20), "Paths": s.markTraps(a.Paths.top(20)), "RuleMsg": a.RuleMsg,
		"Blocked": blocked, "IsBlocked": isBlocked, "Allowed": s.allowed(ip), "Allow": allowOf(s, ip), "Trapped": trapped, "Backends": s.Blocks.Names(),
		"DefaultBackends": s.Cfg.Block.Default, "TTLs": blockTTLs, "Periods": periods,
	}})
}

func allowOf(s *Server, ip string) policy.Addr {
	a, _ := s.allowEntry(ip)
	return a
}

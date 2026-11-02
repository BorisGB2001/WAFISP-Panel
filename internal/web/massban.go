package web

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"wafisp/internal/block"
	"wafisp/internal/event"
	"wafisp/internal/store"
)

// maxMassBan bounds one mass ban.
const maxMassBan = 1000

// massRow is one address a mass ban would block.
type massRow struct {
	IP       string
	Country  string
	Events   int
	Denied   int
	Paths    int // distinct paths touched in the period, any rule
	Sites    []string
	Last     time.Time
	Skip     string // why it cannot be blocked; empty when it can
	Visitor  bool   // touched at most maxFocusPaths paths: may be a real visitor
	Selected bool
}

// massCandidates collects the addresses that match the filter of the
// attack log, with what the panel knows about each.
func (s *Server) massCandidates(f filter) ([]massRow, int) {
	rows := map[string]*massRow{}
	var order []string
	s.Store.Scan(f.since(), func(e *store.Summary) bool {
		if !f.match(e) {
			return true
		}
		r := rows[e.SrcIP]
		if r == nil {
			r = &massRow{IP: e.SrcIP, Country: e.Country, Last: e.Time}
			rows[e.SrcIP] = r
			order = append(order, e.SrcIP)
		}
		r.Events++
		if e.Denied {
			r.Denied++
		}
		if !slices.Contains(r.Sites, e.Site) && len(r.Sites) < 5 {
			r.Sites = append(r.Sites, e.Site)
		}
		return true
	})
	// How many paths each address touched in the period, whatever the
	// rule: a scanner tries many, a visitor using one form touches few.
	paths := map[string]map[string]struct{}{}
	s.Store.Scan(f.since(), func(e *store.Summary) bool {
		if rows[e.SrcIP] == nil {
			return true
		}
		ps := paths[e.SrcIP]
		if ps == nil {
			ps = map[string]struct{}{}
			paths[e.SrcIP] = ps
		}
		if len(ps) <= maxFocusPaths {
			ps[e.Site+e.Path] = struct{}{}
		}
		return true
	})
	visitors := 0
	out := make([]massRow, 0, len(order))
	for _, ip := range order {
		r := rows[ip]
		r.Paths = len(paths[ip])
		r.Visitor = r.Paths <= maxFocusPaths
		if r.Visitor {
			visitors++
		}
		switch {
		case s.allowed(ip):
			r.Skip = "on the allow list"
		default:
			if _, ok := s.Blocks.Lookup(ip); ok {
				r.Skip = "already blocked"
			} else if _, err := s.Blocks.Normalize(ip, ""); err != nil {
				r.Skip = err.Error()
			}
		}
		// Only denied attackers are preselected; an address whose requests
		// all passed is left to the admin.
		r.Selected = r.Skip == "" && r.Denied > 0
		out = append(out, *r)
	}
	slices.SortStableFunc(out, func(a, b massRow) int { return b.Events - a.Events })
	return out, visitors
}

func (f filter) describe(r *http.Request) string {
	var parts []string
	if f.Rule != "" {
		parts = append(parts, tr(r, "rule %s", f.Rule))
	}
	if f.Cat != "" {
		parts = append(parts, tr(r, "class %s", tr(r, event.CategoryName(f.Cat))))
	}
	if f.Site != "" {
		parts = append(parts, tr(r, "site %s", f.Site))
	}
	if f.Path != "" {
		parts = append(parts, tr(r, "path contains %s", f.Path))
	}
	if f.Var != "" {
		parts = append(parts, tr(r, "variable %s", f.Var))
	}
	if f.IP != "" {
		parts = append(parts, "IP "+f.IP)
	}
	if f.Action != "" {
		parts = append(parts, tr(r, "action %s", f.Action))
	}
	if f.Score > 0 {
		parts = append(parts, tr(r, "score ≥ %d", f.Score))
	}
	return strings.Join(parts, ", ")
}

func (s *Server) massBanPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	f := parseFilter(r, "7d")
	f.Page = 1
	p := page{Title: "Ban everyone", Active: "attacks"}
	desc := f.describe(r)
	if f.Rule == "" && f.Cat == "" && f.Path == "" && f.Var == "" && f.IP == "" {
		// Without an attack to go by this would ban every attacker.
		p.Error = tr(r, "Choose an attack first: a rule, a class, a path or a variable")
	}
	rows, visitors := s.massCandidates(f)
	selectable := 0
	for _, x := range rows {
		if x.Skip == "" {
			selectable++
		}
	}
	msg := ""
	if f.Rule != "" {
		msg = s.Store.RuleMsg(f.Rule)
	}
	p.Data = map[string]any{
		"F": f, "Q": f.Query(0), "Desc": desc, "Rows": rows, "Visitors": visitors, "Selectable": selectable,
		"TooMany": selectable > maxMassBan, "Max": maxMassBan, "Periods": periods, "TTLs": blockTTLs,
		"Backends": s.Blocks.Names(), "DefaultBackends": s.Cfg.Block.Default, "RuleMsg": msg,
		"ScanRule": f.Rule != "" && event.ScanRule(f.Rule),
		"Reason":   tr(r, "mass ban: %s", desc),
		"Warn":     len(rows) > 0 && visitors*2 >= len(rows),
	}
	s.render(w, r, rc, "massban.html", p)
}

func (s *Server) massBan(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	r.ParseForm()
	f := parseFilter(r, "7d")
	again := "/massban?" + string(f.Query(0))
	if f.Rule == "" && f.Cat == "" && f.Path == "" && f.Var == "" && f.IP == "" {
		flashRedirect(w, r, again, "", tr(r, "Choose an attack first: a rule, a class, a path or a variable"))
		return
	}
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if reason == "" {
		flashRedirect(w, r, again, "", tr(r, "Give a reason for the block — it goes to the audit log"))
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		flashRedirect(w, r, again, "", tr(r, "Tick the confirmation box"))
		return
	}
	ttl, ok := ttlOf(r.PostFormValue("ttl"))
	if !ok {
		flashRedirect(w, r, again, "", tr(r, "Unknown block duration"))
		return
	}
	backends := r.PostForm["backend"]
	// Only addresses that match the filter now and were ticked; the
	// list from the browser is never trusted on its own.
	rows, _ := s.massCandidates(f)
	picked := r.PostForm["ip"]
	now := time.Now()
	var es []block.Entry
	for _, x := range rows {
		if x.Skip != "" || !slices.Contains(picked, x.IP) {
			continue
		}
		ip, err := s.Blocks.Normalize(x.IP, clientIP(r))
		if err != nil {
			continue
		}
		e := block.Entry{IP: ip, Backends: backends, By: rc.User.Name, Reason: reason, At: now, Via: "massban"}
		if len(x.Sites) == 1 {
			e.Site = x.Sites[0]
		}
		if ttl.D > 0 {
			e.Expires = now.Add(ttl.D)
		}
		es = append(es, e)
	}
	if len(es) == 0 {
		flashRedirect(w, r, again, "", tr(r, "No address to block"))
		return
	}
	if len(es) > maxMassBan {
		flashRedirect(w, r, again, "", tr(r, "At most %d addresses at once; narrow the filter", maxMassBan))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	n, err := s.Blocks.BlockMany(ctx, es)
	var ips []string
	for _, e := range es {
		ips = append(ips, e.IP)
	}
	detail := fmt.Sprintf("%d addresses via %s for %s (%s): %s — %s", len(es), strings.Join(backends, "+"), ttl.Label, f.Query(0), reason, strings.Join(ips, " "))
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "block.mass.failed", detail+" — "+err.Error())
		flashRedirect(w, r, again, "", tr(r, "The block was not applied: %s", errText(r, err)))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "block.mass", detail)
	flashRedirect(w, r, "/blocked", tr(r, "Blocked %d addresses (%s)", n, tr(r, ttl.Label)), "")
}

package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"wafisp/internal/block"
	"wafisp/internal/policy"
	"wafisp/internal/store"
)

type ttlOption struct {
	Key   string
	Label string
	D     time.Duration
}

var blockTTLs = []ttlOption{
	{"1h", "1 hour", time.Hour}, {"24h", "24 hours", 24 * time.Hour}, {"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour}, {"0", "Permanent", 0},
}

func ttlOf(key string) (ttlOption, bool) {
	i := slices.IndexFunc(blockTTLs, func(t ttlOption) bool { return t.Key == key })
	if i < 0 {
		return ttlOption{}, false
	}
	return blockTTLs[i], true
}

// back returns to the page the form was on, or to def.
func back(r *http.Request, def string) string {
	if n := r.FormValue("back"); strings.HasPrefix(n, "/") && !strings.HasPrefix(n, "//") {
		return n
	}
	return def
}

// ---------- sites ----------

type siteView struct {
	Name, Owner, WAF, Override, AuditLog string
	Hosts, Extra                         []string
	Events24, Denied24, Passed24, Week   int
	LastEvent                            time.Time
}

func (s *Server) sitesPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	st := s.Policy.State()
	counts := map[string]*siteView{}
	var list []siteView
	for _, x := range s.Sites.Sites() {
		list = append(list, siteView{Name: x.Name, Owner: x.Owner, WAF: x.WAF, Override: st.ModeOf(x.Name),
			AuditLog: x.AuditLog, Hosts: x.Hosts, Extra: x.Extra})
	}
	for i := range list {
		counts[list[i].Name] = &list[i]
	}
	day := time.Now().Add(-24 * time.Hour)
	s.Store.Scan(time.Now().AddDate(0, 0, -7), func(e *store.Summary) bool {
		v := counts[e.Site]
		if v == nil {
			return true
		}
		v.Week++
		if v.LastEvent.IsZero() {
			v.LastEvent = e.Time
		}
		if e.Time.After(day) {
			v.Events24++
			if e.Denied {
				v.Denied24++
			} else {
				v.Passed24++
			}
		}
		return true
	})
	s.render(w, r, rc, "sites.html", page{Title: "Sites", Active: "sites", Data: map[string]any{"Sites": list}})
}

func (s *Server) siteMode(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("site")
	site, ok := s.Sites.Get(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	engine := r.FormValue("engine")
	if engine != "" && !policy.ValidMode(engine) {
		flashRedirect(w, r, "/sites", "", tr(r, "Unknown mode"))
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		flashRedirect(w, r, "/sites", "", tr(r, "Give a reason for the mode change — it goes to the audit log"))
		return
	}
	if engine == "Off" && r.FormValue("confirm") != name {
		flashRedirect(w, r, "/sites", "", tr(r, "To switch the WAF off, type the site name: %s", name))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	err := s.Policy.Update(ctx, func(st *policy.State) error {
		st.SetMode(policy.Mode{Site: name, Hosts: site.Hosts, Engine: engine,
			Meta: policy.Meta{By: rc.User.Name, Reason: reason, At: time.Now()}})
		return nil
	})
	shown := engine
	if shown == "" {
		shown = tr(r, "as set in ISPmanager")
	}
	detail := fmt.Sprintf("%s → %s: %s", name, shown, reason)
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "site.mode.failed", detail+" — "+err.Error())
		flashRedirect(w, r, "/sites", "", err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "site.mode", detail)
	flashRedirect(w, r, "/sites", tr(r, "Site %s: WAF %s", name, shown), "")
}

// ---------- blocks and the allow list ----------

func (s *Server) blocksPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	live := map[string][]string{}
	liveErr := map[string]string{}
	for _, b := range s.Blocks.Backends {
		ips, err := b.List(ctx)
		if err != nil {
			liveErr[b.Name()] = err.Error()
			continue
		}
		live[b.Name()] = ips
	}
	pending, lastErr, lastApply := s.Policy.Status()
	s.render(w, r, rc, "blocks.html", page{Title: "Blocking", Active: "blocks", Data: map[string]any{
		"Entries": s.Blocks.Entries(), "Allow": s.Policy.State().Allow, "Backends": s.Blocks.Names(),
		"DefaultBackends": s.Cfg.Block.Default, "TTLs": blockTTLs, "Live": live, "LiveErr": liveErr,
		"SyncErr": s.Blocks.Errors(), "Prefill": r.URL.Query().Get("ip"), "MyIP": clientIP(r),
		"Pending": pending, "PolicyErr": lastErr, "LastApply": lastApply, "Ports": s.Cfg.Block.Ports,
		"Protected": s.Cfg.Block.Protected,
	}})
}

func (s *Server) blockAdd(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	to := back(r, "/blocks")
	ip, err := s.Blocks.Normalize(r.FormValue("ip"), clientIP(r))
	if err != nil {
		flashRedirect(w, r, to, "", errText(r, err))
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		flashRedirect(w, r, to, "", tr(r, "Give a reason for the block — it goes to the audit log"))
		return
	}
	ttl, ok := ttlOf(r.FormValue("ttl"))
	if !ok {
		flashRedirect(w, r, to, "", tr(r, "Unknown block duration"))
		return
	}
	backends := r.Form["backend"]
	e := block.Entry{IP: ip, Backends: backends, By: rc.User.Name, Reason: reason, At: time.Now(), Site: r.FormValue("site")}
	if ttl.D > 0 {
		e.Expires = e.At.Add(ttl.D)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	detail := fmt.Sprintf("%s via %s for %s: %s", ip, strings.Join(backends, "+"), ttl.Label, reason)
	if err := s.Blocks.Block(ctx, e); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "block.failed", detail+" — "+err.Error())
		flashRedirect(w, r, to, "", tr(r, "The block was not applied: %s", errText(r, err)))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "block", detail)
	flashRedirect(w, r, to, tr(r, "Blocked %s (%s)", ip, tr(r, ttl.Label)), "")
}

func (s *Server) blockRemove(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	to := back(r, "/blocks")
	ip := r.FormValue("ip")
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if err := s.Blocks.Unblock(ctx, ip); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "unblock.failed", ip+" — "+err.Error())
		flashRedirect(w, r, to, "", tr(r, "The unblock did not go through everywhere: %s", err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "unblock", ip)
	flashRedirect(w, r, to, tr(r, "Unblocked %s", ip), "")
}

func (s *Server) allowAdd(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	to := back(r, "/blocks")
	ip, err := s.Blocks.NormalizeAllow(r.FormValue("ip"))
	if err != nil {
		flashRedirect(w, r, to, "", errText(r, err))
		return
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	if reason == "" {
		flashRedirect(w, r, to, "", tr(r, "Give a reason — it goes to the audit log"))
		return
	}
	ttl, ok := ttlOf(r.FormValue("ttl"))
	if !ok {
		flashRedirect(w, r, to, "", tr(r, "Unknown duration"))
		return
	}
	a := policy.Addr{IP: ip, Meta: policy.Meta{By: rc.User.Name, Reason: reason, At: time.Now()}}
	if ttl.D > 0 {
		a.Expires = a.At.Add(ttl.D)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	err = s.Policy.Update(ctx, func(st *policy.State) error {
		st.Allow = slices.DeleteFunc(st.Allow, func(x policy.Addr) bool { return x.IP == ip })
		st.Allow = append(st.Allow, a)
		return nil
	})
	detail := fmt.Sprintf("%s for %s: %s", ip, ttl.Label, reason)
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "allow.failed", detail+" — "+err.Error())
		flashRedirect(w, r, to, "", err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "allow", detail)
	flashRedirect(w, r, to, tr(r, "The WAF no longer inspects %s (%s)", ip, tr(r, ttl.Label)), "")
}

func (s *Server) allowRemove(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	to := back(r, "/blocks")
	ip := r.FormValue("ip")
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	err := s.Policy.Update(ctx, func(st *policy.State) error {
		st.Allow = slices.DeleteFunc(st.Allow, func(x policy.Addr) bool { return x.IP == ip })
		return nil
	})
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "allow.remove.failed", ip+" — "+err.Error())
		flashRedirect(w, r, to, "", err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "allow.remove", ip)
	flashRedirect(w, r, to, tr(r, "The WAF inspects %s again", ip), "")
}

// ---------- exclusions ----------

func (s *Server) exclusionsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	q := r.URL.Query()
	// Prefill from an event or the analysis page.
	pre := map[string]string{"site": q.Get("site"), "path": q.Get("path"), "rules": q.Get("rule"),
		"tags": q.Get("tag"), "target": q.Get("var"), "reason": q.Get("reason")}
	st := s.Policy.State()
	hits := map[int]int{}
	week := time.Now().AddDate(0, 0, -7)
	// How often each exclusion's rules fired on its scope this week: an
	// exclusion that applies shows no hits after it was added.
	s.Store.Scan(week, func(e *store.Summary) bool {
		for _, x := range st.Exclusions {
			if e.Time.Before(x.At) || (x.Site != "" && e.Site != x.Site) || (x.Path != "" && !strings.HasPrefix(e.Path, x.Path)) {
				continue
			}
			for _, rid := range x.Rules {
				if slices.Contains(e.Rules, rid) {
					hits[x.ID]++
				}
			}
		}
		return true
	})
	s.render(w, r, rc, "exclusions.html", page{Title: "Exclusions", Active: "exclusions", Data: map[string]any{
		"List": st.Exclusions, "Sites": s.Sites.Sites(), "Pre": pre, "Hits": hits,
	}})
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
		if f = strings.TrimSpace(f); f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

func (s *Server) exclusionAdd(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	x := policy.Exclusion{
		Site: r.FormValue("site"), Path: strings.TrimSpace(r.FormValue("path")),
		Rules: splitList(r.FormValue("rules")), Tags: splitList(r.FormValue("tags")),
		Target: strings.TrimSpace(r.FormValue("target")),
		Meta:   policy.Meta{By: rc.User.Name, Reason: strings.TrimSpace(r.FormValue("reason")), At: time.Now()},
	}
	again := "/exclusions?" + url.Values{"site": {x.Site}, "path": {x.Path}, "rule": {strings.Join(x.Rules, ",")},
		"tag": {strings.Join(x.Tags, ",")}, "var": {x.Target}, "reason": {x.Reason}}.Encode()
	if x.Reason == "" {
		flashRedirect(w, r, again, "", tr(r, "Give a reason — it goes to the audit log"))
		return
	}
	if x.Site != "" {
		site, ok := s.Sites.Get(x.Site)
		if !ok {
			flashRedirect(w, r, again, "", tr(r, "Unknown site %s", x.Site))
			return
		}
		x.Hosts = site.Hosts
	}
	if x.Site == "" && x.Path == "" && r.FormValue("everywhere") != "yes" {
		flashRedirect(w, r, again, "", tr(r, "An exclusion without a site or path switches the rule off on every site. Tick the box to confirm."))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	var added policy.Exclusion
	err := s.Policy.Update(ctx, func(st *policy.State) error {
		var err error
		added, err = st.AddExclusion(x)
		return err
	})
	detail := fmt.Sprintf("site=%q path=%q rules=%v tags=%v target=%q: %s", x.Site, x.Path, x.Rules, x.Tags, x.Target, x.Reason)
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "exclusion.add.failed", detail+" — "+err.Error())
		flashRedirect(w, r, again, "", err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "exclusion.add", fmt.Sprintf("#%d %s", added.ID, detail))
	flashRedirect(w, r, "/exclusions", tr(r, "Exclusion #%d added and applied", added.ID), "")
}

func (s *Server) exclusionEnabled(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	on := r.FormValue("enabled") == "true"
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	err := s.Policy.Update(ctx, func(st *policy.State) error {
		x := st.Exclusion(id)
		if x == nil {
			return fmt.Errorf("no exclusion #%d", id)
		}
		x.Disabled = !on
		return nil
	})
	if err != nil {
		flashRedirect(w, r, "/exclusions", "", err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "exclusion.enabled", fmt.Sprintf("#%d %v", id, on))
	flashRedirect(w, r, "/exclusions", tr(r, "Exclusion #%d updated", id), "")
}

func (s *Server) exclusionDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	err := s.Policy.Update(ctx, func(st *policy.State) error {
		if !st.DeleteExclusion(id) {
			return fmt.Errorf("no exclusion #%d", id)
		}
		return nil
	})
	if err != nil {
		flashRedirect(w, r, "/exclusions", "", err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "exclusion.delete", fmt.Sprintf("#%d", id))
	flashRedirect(w, r, "/exclusions", tr(r, "Exclusion #%d deleted", id), "")
}

func (s *Server) policyApply(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	s.Policy.RetryPending(ctx)
	if err := s.Policy.Apply(ctx); err != nil {
		flashRedirect(w, r, back(r, "/blocks"), "", err.Error())
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "policy.apply", "")
	pending, lastErr, _ := s.Policy.Status()
	if pending {
		flashRedirect(w, r, back(r, "/blocks"), "", lastErr)
		return
	}
	flashRedirect(w, r, back(r, "/blocks"), tr(r, "Rules applied"), "")
}

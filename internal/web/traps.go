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
)

// trapsPage lists the traps and the form for a new one; ?site= and ?path=
// prefill it and show who already requested that path.
func (s *Server) trapsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	st := s.Policy.State()
	site, path, match := r.URL.Query().Get("site"), r.URL.Query().Get("path"), r.URL.Query().Get("match")
	banned := map[int]int{}
	for _, e := range s.Blocks.Entries() {
		if id := bannedBy(e); id > 0 {
			banned[id]++
		}
	}
	data := map[string]any{
		"Traps": st.Traps, "Hits": s.Autoban.TrapHits(), "Banned": banned, "Sites": s.siteNames(), "Durations": banDurations,
		"Defaults": policy.DefaultTraps(time.Now()), "DefaultsAdded": st.DefaultTraps,
		"Site": site, "Path": path, "Match": match, "Backends": s.Autoban.Settings().Backends, "Loaded": s.Cfg.Nginx.IncludeFile != "none",
	}
	if path != "" {
		rows, _ := s.massCandidates(filter{Site: site, Path: path, Period: "7d"})
		visitors := 0
		for _, x := range rows {
			if x.Visitor {
				visitors++
			}
		}
		data["Seen"], data["Visitors"] = len(rows), visitors
		data["Risky"] = len(rows) > 0 && visitors*2 >= len(rows)
	}
	s.render(w, r, rc, "traps.html", page{Title: "Traps", Active: "traps", Data: data})
}

func (s *Server) trapAdd(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	t := policy.Trap{Site: r.FormValue("site"), Path: strings.TrimSpace(r.FormValue("path")), Match: r.FormValue("match"), DryRun: r.FormValue("dry_run") == "on",
		Meta: policy.Meta{By: rc.User.Name, Reason: strings.TrimSpace(r.FormValue("reason")), At: time.Now()}}
	again := "/traps?" + url.Values{"site": {t.Site}, "path": {t.Path}, "match": {t.Match}}.Encode()
	if t.Reason == "" {
		flashRedirect(w, r, again, "", tr(r, "Give a reason — it goes to the audit log"))
		return
	}
	i := slices.IndexFunc(banDurations, func(o ttlOption) bool { return o.Key == r.FormValue("ttl") })
	if i < 0 {
		flashRedirect(w, r, again, "", tr(r, "Unknown duration"))
		return
	}
	t.Duration = banDurations[i].D
	if t.Site != "" {
		site, ok := s.Sites.Get(t.Site)
		if !ok {
			flashRedirect(w, r, again, "", tr(r, "Unknown site %s", t.Site))
			return
		}
		t.Hosts = site.Hosts
	}
	if r.FormValue("confirm") != "yes" {
		flashRedirect(w, r, again, "", tr(r, "Tick the box to confirm that everyone who requests this path gets banned."))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	var added policy.Trap
	err := s.Policy.Update(ctx, func(st *policy.State) error {
		var err error
		added, err = st.AddTrap(t)
		return err
	})
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "trap.failed", t.Site+t.Path+" — "+err.Error())
		flashRedirect(w, r, again, "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "trap", fmt.Sprintf("#%d %s%s match=%s for %s dry_run=%v: %s", added.ID, t.Site, t.Path, t.Match, banDurations[i].Label, t.DryRun, t.Reason))
	flashRedirect(w, r, "/traps", tr(r, "Trap %d set on %s%s", added.ID, t.Site, t.Path), "")
}

// trapDefaults adds the default traps, in dry run.
func (s *Server) trapDefaults(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	n := 0
	err := s.Policy.Update(ctx, func(st *policy.State) error { n = st.AddDefaultTraps(time.Now()); return nil })
	if err != nil {
		flashRedirect(w, r, "/traps", "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "trap.defaults", fmt.Sprintf("%d default traps added in dry run", n))
	flashRedirect(w, r, "/traps", tr(r, "%d default traps added in dry run. Look at their hits, then switch them to banning.", n), "")
}

func (s *Server) trapEnabled(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.trapChange(w, r, rc, "trap.enabled", func(t *policy.Trap) {
		t.Disabled = r.FormValue("enabled") != "true"
	})
}

func (s *Server) trapDryRun(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.trapChange(w, r, rc, "trap.dry_run", func(t *policy.Trap) {
		t.DryRun = r.FormValue("dry_run") == "true"
	})
}

// bannedBy is the trap that made block e, or 0.
func bannedBy(e block.Entry) int {
	if e.Via == "trap" && e.Rule != nil {
		return e.Rule.Trap
	}
	return 0
}

// trapDeletePage asks whether the addresses the trap banned stay banned.
func (s *Server) trapDeletePage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	st := s.Policy.State()
	t := st.Trap(id)
	if t == nil {
		flashRedirect(w, r, "/traps", "", tr(r, "no trap %d", id))
		return
	}
	var banned []block.Entry
	for _, e := range s.Blocks.Entries() {
		if bannedBy(e) == id {
			banned = append(banned, e)
		}
	}
	s.render(w, r, rc, "trapdelete.html", page{Title: "Delete trap", Active: "traps", Data: map[string]any{"Trap": t, "Banned": banned}})
}

func (s *Server) trapDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	err := s.Policy.Update(ctx, func(st *policy.State) error {
		n := len(st.Traps)
		st.Traps = slices.DeleteFunc(st.Traps, func(t policy.Trap) bool { return t.ID == id })
		if len(st.Traps) == n {
			return fmt.Errorf("no trap %d", id)
		}
		return nil
	})
	if err != nil {
		flashRedirect(w, r, "/traps", "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "trap.delete", fmt.Sprint("#", id))
	if r.FormValue("unban") != "yes" {
		flashRedirect(w, r, "/traps", tr(r, "Trap %d deleted", id), "")
		return
	}
	// The trap is gone, so are its bans: no hunting the addresses down later.
	removed, err := s.Blocks.UnblockMany(ctx, func(e block.Entry) bool { return bannedBy(e) == id })
	for _, e := range removed {
		s.audit.Log(rc.User.Name, clientIP(r), "unblock", fmt.Sprintf("%s: trap #%d deleted", e.IP, id))
	}
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "unblock.failed", fmt.Sprintf("trap #%d — %s", id, err))
		flashRedirect(w, r, "/traps", "", tr(r, "Trap %d deleted, but the unblock did not go through everywhere: %s", id, err))
		return
	}
	flashRedirect(w, r, "/traps", tr(r, "Trap %d deleted, %d addresses it banned are unblocked", id, len(removed)), "")
}

func (s *Server) trapChange(w http.ResponseWriter, r *http.Request, rc *reqCtx, action string, change func(*policy.Trap)) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	var after policy.Trap
	err := s.Policy.Update(ctx, func(st *policy.State) error {
		t := st.Trap(id)
		if t == nil {
			return fmt.Errorf("no trap %d", id)
		}
		change(t)
		after = *t
		return nil
	})
	if err != nil {
		flashRedirect(w, r, "/traps", "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), action, fmt.Sprintf("#%d disabled=%v dry_run=%v", id, after.Disabled, after.DryRun))
	flashRedirect(w, r, "/traps", tr(r, "Trap %d saved", id), "")
}

package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var banDurations = []ttlOption{
	{"1h", "1 hour", time.Hour}, {"6h", "6 hours", 6 * time.Hour}, {"24h", "24 hours", 24 * time.Hour},
	{"7d", "7 days", 7 * 24 * time.Hour}, {"30d", "30 days", 30 * 24 * time.Hour}, {"0", "Permanent", 0},
}

func durationKey(d time.Duration) string {
	for _, o := range banDurations {
		if o.D == d {
			return o.Key
		}
	}
	return "24h"
}

func (s *Server) autobanPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	st := s.Autoban.Settings()
	keys := make([]string, len(st.Durations))
	for i, d := range st.Durations {
		keys[i] = durationKey(d)
	}
	for len(keys) < 3 {
		keys = append(keys, "")
	}
	s.render(w, r, rc, "autoban.html", page{Title: "Auto-ban", Active: "autoban", Data: map[string]any{
		"S": st, "WindowMin": int(st.Window / time.Minute), "DurKeys": keys, "Durations": banDurations,
		"Cats": categoryOptions(), "Backends": s.Blocks.Names(), "Decisions": s.Autoban.Decisions(),
	}})
}

func (s *Server) autobanSave(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	st := s.Autoban.Settings()
	st.Enabled = r.FormValue("enabled") == "on"
	st.DryRun = r.FormValue("dry_run") == "on"
	st.Threshold, _ = strconv.Atoi(r.FormValue("threshold"))
	mins, _ := strconv.Atoi(r.FormValue("window"))
	st.Window = time.Duration(mins) * time.Minute
	st.Instant = r.Form["instant"]
	st.InstantScore, _ = strconv.Atoi(r.FormValue("instant_score"))
	st.Backends = r.Form["backend"]
	st.Durations = nil
	for _, k := range r.Form["duration"] {
		if k == "" {
			continue
		}
		var t ttlOption
		ok := false
		for _, o := range banDurations {
			if o.Key == k {
				t, ok = o, true
			}
		}
		if !ok {
			flashRedirect(w, r, "/autoban", "", tr(r, "Unknown duration"))
			return
		}
		st.Durations = append(st.Durations, t.D)
	}
	if err := st.Validate(s.Blocks.Names()); err != nil {
		flashRedirect(w, r, "/autoban", "", err.Error())
		return
	}
	if err := s.Autoban.SetSettings(st); err != nil {
		flashRedirect(w, r, "/autoban", "", err.Error())
		return
	}
	var durs []string
	for _, d := range st.Durations {
		durs = append(durs, durationKey(d))
	}
	s.audit.Log(rc.User.Name, clientIP(r), "autoban.settings", fmt.Sprintf("enabled=%v dry_run=%v %d in %s, instant=%s score≥%d, durations=%s via %s",
		st.Enabled, st.DryRun, st.Threshold, st.Window, strings.Join(st.Instant, ","), st.InstantScore, strings.Join(durs, "→"), strings.Join(st.Backends, "+")))
	flashRedirect(w, r, "/autoban", tr(r, "Auto-ban settings saved"), "")
}

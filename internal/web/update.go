package web

import (
	"context"
	"net/http"
	"time"
)

func (s *Server) updatePage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	data := map[string]any{"Off": s.Updater == nil, "Repo": s.Cfg.Update.Repo}
	if s.Updater != nil {
		data["S"] = s.Updater.State()
	}
	s.render(w, r, rc, "update.html", page{Title: "Update", Active: "update", Data: data})
}

func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Updater == nil {
		flashRedirect(w, r, "/update", "", tr(r, "The update check is off in the config"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	rel, err := s.Updater.Check(ctx)
	if err != nil {
		flashRedirect(w, r, "/update", "", tr(r, "Could not ask GitHub: %s", err))
		return
	}
	flashRedirect(w, r, "/update", tr(r, "Latest release: %s", rel.Version), "")
}

// updateInstall downloads, verifies and checks the release, then starts
// the installer; the panel restarts a few seconds later.
func (s *Server) updateInstall(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Updater == nil {
		flashRedirect(w, r, "/update", "", tr(r, "The update check is off in the config"))
		return
	}
	if r.FormValue("confirm") != "yes" {
		flashRedirect(w, r, "/update", "", tr(r, "Tick the box to confirm the update."))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	v, err := s.Updater.Install(ctx)
	if err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "update.failed", err.Error())
		flashRedirect(w, r, "/update", "", tr(r, "Not updated: %s", err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "update", s.Version+" → "+v)
	flashRedirect(w, r, "/update", tr(r, "Installing %s: the panel restarts in a few seconds. Reload this page in a minute.", v), "")
}

func (s *Server) updateRollback(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Updater == nil {
		flashRedirect(w, r, "/update", "", tr(r, "The update check is off in the config"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	if err := s.Updater.Rollback(ctx); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "update.rollback.failed", err.Error())
		flashRedirect(w, r, "/update", "", tr(r, "Not rolled back: %s", err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "update.rollback", "from "+s.Version)
	flashRedirect(w, r, "/update", tr(r, "Rolling back: the panel restarts in a few seconds. Reload this page in a minute."), "")
}

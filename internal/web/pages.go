package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"wafisp/internal/auth"
	"wafisp/internal/config"
	"wafisp/internal/event"
	"wafisp/internal/rules"
)

func urlQuery(s string) string { return url.QueryEscape(s) }

// ---------- login ----------

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, nil, "login.html", page{Title: "Sign in", Data: map[string]string{"Next": safeNext(r.URL.Query().Get("next"))}})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "cross-site request", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(strings.ToLower(r.FormValue("username")))
	ip := clientIP(r)
	next := safeNext(r.FormValue("next"))
	fail := func(msg string) {
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, nil, "login.html", page{Title: "Sign in", Error: msg, Data: map[string]string{"Next": next, "Username": name}})
	}
	if s.throttle.Blocked("ip:"+ip, "user:"+name) {
		s.audit.Log(name, ip, "login.blocked", "")
		fail(tr(r, "Too many failed attempts. Wait 15 minutes."))
		return
	}
	u, err := s.users.Authenticate(name, r.FormValue("password"))
	if err != nil {
		s.throttle.Fail("ip:"+ip, "user:"+name)
		s.audit.Log(name, ip, "login.failed", "")
		fail(tr(r, "Wrong username or password."))
		return
	}
	s.throttle.Reset("user:" + name)
	s.setSession(w, *u)
	s.audit.Log(u.Name, ip, "login", "")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// safeNext allows only local paths after login.
func safeNext(n string) string {
	if !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.HasPrefix(n, "/\\") {
		return "/"
	}
	return n
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	clearSession(w)
	s.audit.Log(rc.User.Name, clientIP(r), "logout", "")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------- alerts ----------

func (s *Server) alerts(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, r, rc, "alerts.html", page{Title: "Alerts", Active: "alerts", Data: s.History.Recent(300)})
}

// ---------- rules ----------

func (s *Server) rulesPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	rs := s.currentRules()
	text, _ := yaml.Marshal(rs)
	s.renderRules(w, r, rc, rs, string(text), "")
}

func (s *Server) renderRules(w http.ResponseWriter, r *http.Request, rc *reqCtx, rs []config.Rule, text, errMsg string) {
	s.render(w, r, rc, "rules.html", page{Title: "Alert rules", Active: "rules", Error: errMsg, Data: map[string]any{
		"Rules": rs, "YAML": text, "Channels": s.Cfg.Channels, "Cats": categoryOptions(),
	}})
}

func (s *Server) rulesSave(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	text := r.FormValue("yaml")
	var rs []config.Rule
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	if err := dec.Decode(&rs); err != nil && err.Error() != "EOF" {
		w.WriteHeader(http.StatusBadRequest)
		s.renderRules(w, r, rc, s.currentRules(), text, tr(r, "YAML error: %s", err))
		return
	}
	if err := s.Cfg.ValidateRules(rs); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		s.renderRules(w, r, rc, s.currentRules(), text, tr(r, "Rule error: %s", err))
		return
	}
	out, _ := yaml.Marshal(rs)
	header := fmt.Sprintf("# WAFISP Panel alert rules. Changed in the panel by %s at %s\n", rc.User.Name, time.Now().Format("2006-01-02 15:04"))
	if err := auth.WriteFileAtomic(s.RuleFile, append([]byte(header), out...), 0o600); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		s.renderRules(w, r, rc, s.currentRules(), text, tr(r, "Could not save: %s", err))
		return
	}
	s.mu.Lock()
	old := s.rules
	s.rules = rs
	s.mu.Unlock()
	s.Rules.SetRules(rs)
	s.audit.Log(rc.User.Name, clientIP(r), "rules.save", ruleDiff(old, rs))
	flashRedirect(w, r, "/rules", tr(r, "Saved and applied: %d rules", len(rs)), "")
}

func ruleDiff(old, now []config.Rule) string {
	names := func(rs []config.Rule) []string {
		var n []string
		for _, r := range rs {
			n = append(n, r.Name)
		}
		return n
	}
	return fmt.Sprintf("was: %s; now: %s", strings.Join(names(old), ", "), strings.Join(names(now), ", "))
}

// ---------- channels ----------

type channelView struct {
	Name, Type, Target string
	Sent, Failed       int64
}

func (s *Server) channelsPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	_, counters, _ := s.Stats.Snapshot()
	var list []channelView
	for _, ch := range s.Cfg.Channels {
		v := channelView{Name: ch.Name, Type: ch.Type,
			Sent:   counters[fmt.Sprintf("alerts_sent_total{channel=%q}", ch.Name)],
			Failed: counters[fmt.Sprintf("alerts_failed_total{channel=%q}", ch.Name)]}
		switch ch.Type {
		case "telegram":
			v.Target = "chat_id " + ch.Telegram.ChatID
		case "email":
			v.Target = strings.Join(ch.Email.To, ", ") + " via " + ch.Email.Host
		case "webhook":
			if u, err := url.Parse(ch.Webhook.URL); err == nil {
				v.Target = u.Scheme + "://" + u.Host + " (" + ch.Webhook.Format + ")"
			}
		}
		list = append(list, v)
	}
	var siem []map[string]any
	for _, t := range s.Cfg.SIEM {
		siem = append(siem, map[string]any{
			"Name": t.Name, "Target": t.Network + "://" + t.Address, "Format": t.Format + ", header " + t.Header,
			"Sent":    counters[fmt.Sprintf("siem_sent_total{target=%q}", t.Name)],
			"Dropped": counters[fmt.Sprintf("siem_dropped_total{target=%q}", t.Name)],
		})
	}
	s.render(w, r, rc, "channels.html", page{Title: "Channels & SIEM", Active: "channels", Data: map[string]any{"Channels": list, "SIEM": siem}})
}

func (s *Server) channelTest(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	snd := s.Senders[name]
	if snd == nil {
		http.NotFound(w, r)
		return
	}
	now := time.Now()
	ev := event.Event{ID: "panel-test", Site: "example.com", SrcIP: "203.0.113.10", Host: "example.com",
		URI: "/test?from=wafisp", Category: "sqli", Denied: true, Score: 5, Time: now,
		Rules: []event.Match{{ID: "942100", Msg: "SQL Injection Attack Detected via libinjection", Severity: 2}}}
	a := rules.Alert{Rule: "panel test (" + rc.User.Name + ")", Severity: "info", GroupBy: "src_ip", GroupKey: ev.SrcIP,
		Count: 1, First: now, Last: now, Denied: 1, Hosts: []string{ev.Host}, Types: []string{"sqli"}, Samples: []event.Event{ev}}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	err := snd.Send(ctx, a)
	detail := "ok"
	if err != nil {
		detail = err.Error()
	}
	s.audit.Log(rc.User.Name, clientIP(r), "channel.test", name+": "+detail)
	if err != nil {
		flashRedirect(w, r, "/channels", "", tr(r, "Channel %s: %s", name, err))
		return
	}
	flashRedirect(w, r, "/channels", tr(r, "Test alert sent to %s", name), "")
}

// ---------- users ----------

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.renderUsers(w, r, rc, "", "")
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, rc *reqCtx, flash, errMsg string) {
	s.render(w, r, rc, "users.html", page{Title: "Users", Active: "users", Flash: flash, Error: errMsg, Data: s.users.List()})
}

func (s *Server) userAdd(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := strings.TrimSpace(strings.ToLower(r.FormValue("name")))
	role := r.FormValue("role")
	pw := r.FormValue("password")
	generated := pw == ""
	if generated {
		pw = auth.RandomPassword()
	}
	if err := s.users.Add(name, pw, role); err != nil {
		s.renderUsers(w, r, rc, "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "user.add", name+" ("+role+")")
	msg := tr(r, "User %s created.", name)
	if generated {
		// Shown once in this response and never stored in plain text.
		msg += " " + tr(r, "Password: %s — pass it to the user, it is not shown again.", pw)
	}
	s.renderUsers(w, r, rc, msg, "")
}

func (s *Server) userRole(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	role := r.FormValue("role")
	if err := s.users.SetRole(name, role); err != nil {
		s.renderUsers(w, r, rc, "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "user.role", name+" → "+role)
	s.renderUsers(w, r, rc, tr(r, "Role of %s changed to %s", name, role), "")
}

func (s *Server) userPassword(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	pw := auth.RandomPassword()
	if err := s.users.SetPassword(name, pw); err != nil {
		s.renderUsers(w, r, rc, "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "user.password_reset", name)
	if name == rc.User.Name {
		s.setSession(w, mustUser(s.users, name))
	}
	s.renderUsers(w, r, rc, tr(r, "New password for %s: %s — it is not shown again.", name, pw), "")
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	name := r.PathValue("name")
	if name == rc.User.Name {
		s.renderUsers(w, r, rc, "", tr(r, "You cannot delete yourself"))
		return
	}
	if err := s.users.Delete(name); err != nil {
		s.renderUsers(w, r, rc, "", errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "user.delete", name)
	s.renderUsers(w, r, rc, tr(r, "User %s deleted", name), "")
}

func mustUser(u *auth.Users, name string) auth.User {
	x, _ := u.Get(name)
	return x
}

// ---------- account ----------

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, r, rc, "account.html", page{Title: "My account", Active: "account"})
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	fail := func(msg string) {
		w.WriteHeader(http.StatusBadRequest)
		s.render(w, r, rc, "account.html", page{Title: "My account", Active: "account", Error: msg})
	}
	if _, err := s.users.Authenticate(rc.User.Name, r.FormValue("current")); err != nil {
		s.audit.Log(rc.User.Name, clientIP(r), "account.password_failed", "")
		fail(tr(r, "The current password is wrong"))
		return
	}
	if r.FormValue("new") != r.FormValue("repeat") {
		fail(tr(r, "The new passwords do not match"))
		return
	}
	if err := s.users.SetPassword(rc.User.Name, r.FormValue("new")); err != nil {
		fail(errText(r, err))
		return
	}
	s.audit.Log(rc.User.Name, clientIP(r), "account.password", "")
	s.setSession(w, mustUser(s.users, rc.User.Name))
	if rc.User.Name == "admin" {
		// The bootstrap password is useless now; don't leave it lying around.
		os.Remove(s.Cfg.Web.DataDir + "/initial-admin-password")
	}
	flashRedirect(w, r, "/account", tr(r, "Password changed. Your other sessions have ended."), "")
}

// ---------- audit ----------

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.render(w, r, rc, "audit.html", page{Title: "Audit", Active: "audit", Data: s.audit.Recent()})
}

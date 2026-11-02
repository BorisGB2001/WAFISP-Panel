package web

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"wafisp/internal/auth"
	"wafisp/internal/event"
	"wafisp/internal/i18n"
)

// page is the data every template gets; Data holds the page's own values.
type page struct {
	Lang    string
	Theme   string // "light", "dark" or "" to follow the system
	Here    string // this page, for the language and theme switches to come back to
	Title   string
	Active  string
	User    auth.User
	IsAdmin bool
	CSRF    string
	Flash   string
	Error   string
	Version string
	Now     time.Time
	// Warnings are problems of the panel's own rules, shown on every page.
	Warnings []string
	// BlockedCount is shown next to "Blocked" in the menu.
	BlockedCount int
	Data         any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, rc *reqCtx, name string, p page) {
	p.Lang, p.Theme = langOf(r), themeOf(r)
	p.Here = r.URL.Path
	if q := r.URL.Query(); r.Method == http.MethodGet && len(q) > 0 {
		q.Del("ok") // a flash message is shown once
		q.Del("err")
		if len(q) > 0 {
			p.Here += "?" + q.Encode()
		}
	}
	t := s.pages[p.Lang][name]
	if t == nil {
		http.Error(w, "no template "+name, http.StatusInternalServerError)
		return
	}
	if rc != nil {
		p.User = rc.User
		p.IsAdmin = rc.User.Role == auth.RoleAdmin
		p.CSRF = rc.CSRF
	}
	if p.Flash == "" {
		p.Flash = r.URL.Query().Get("ok")
	}
	if p.Error == "" {
		p.Error = r.URL.Query().Get("err")
	}
	p.Title = i18n.T(p.Lang, p.Title)
	p.Version = s.Version
	if rc != nil {
		p.Warnings = s.Health.Problems()
		p.BlockedCount = len(s.Blocks.Entries())
	}
	p.Now = time.Now()
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		s.Log.Error("render", "page", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

var funcs = template.FuncMap{
	// splitPath splits a top-list key site+path into [site, path].
	"splitPath": func(k string) []string {
		if i := strings.Index(k, "/"); i >= 0 {
			return []string{k[:i], k[i:]}
		}
		return []string{k, ""}
	},
	"hasSuffix":  strings.HasSuffix,
	"hasPrefix":  strings.HasPrefix,
	"trimSuffix": strings.TrimSuffix,
	"num":        compact,
	"join":       func(s []string, sep string) string { return strings.Join(s, sep) },
	"pct": func(a, b int) int {
		if b == 0 {
			return 0
		}
		return a * 100 / b
	},
	"pct64": func(a, b int64) int64 {
		if b == 0 {
			return 0
		}
		return a * 100 / b
	},
	"add": func(a, b int) int { return a + b },
	"has": func(xs []string, x string) bool {
		for _, v := range xs {
			if v == x {
				return true
			}
		}
		return false
	},
	"q":          url.QueryEscape,
	"int64":      func(i int) int64 { return int64(i) },
	"evaluation": event.Evaluation,
	"scanRule":   event.ScanRule,
	"list":       func(xs ...string) []string { return xs },
	// dict builds the argument of a shared template: dict "k1" v1 "k2" v2.
	"dict": func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			if k, ok := kv[i].(string); ok {
				m[k] = kv[i+1]
			}
		}
		return m
	},
	"sub": func(a, b int) int { return a - b },
	"cut": func(s string, n int) string {
		r := []rune(s)
		if len(r) <= n {
			return s
		}
		return string(r[:n]) + "…"
	},
	"sevclass": func(s string) string {
		switch s {
		case "critical":
			return "bad"
		case "warning":
			return "warn"
		}
		return "info"
	},
	"deliveryclass": func(s string) string {
		switch s {
		case "ok":
			return "good"
		case "queued":
			return "info"
		}
		return "bad"
	},
}

// flashRedirect redirects back with a message shown once on the next page.
func flashRedirect(w http.ResponseWriter, r *http.Request, to, ok, errMsg string) {
	sep := "?"
	if strings.Contains(to, "?") {
		sep = "&"
	}
	switch {
	case errMsg != "":
		to += sep + "err=" + urlQuery(errMsg)
	case ok != "":
		to += sep + "ok=" + urlQuery(ok)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

const langCookie = "wafisp_lang"

// langOf is the reader's language: the cookie set by /lang/{lang}, English
// otherwise.
func langOf(r *http.Request) string {
	if c, err := r.Cookie(langCookie); err == nil && i18n.Valid(c.Value) {
		return c.Value
	}
	return i18n.EN
}

// tr translates a message for the reader of r.
func tr(r *http.Request, s string, args ...any) string { return i18n.T(langOf(r), s, args...) }

// errText renders an error for the reader of r.
func errText(r *http.Request, err error) string { return i18n.Text(langOf(r), err) }

func (s *Server) setLang(w http.ResponseWriter, r *http.Request) {
	lang := r.PathValue("lang")
	if !i18n.Valid(lang) {
		http.NotFound(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: langCookie, Value: lang, Path: "/", MaxAge: 365 * 24 * 3600,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

const themeCookie = "wafisp_theme"

// themeOf is the reader's colour theme; empty follows the system setting.
func themeOf(r *http.Request) string {
	if c, err := r.Cookie(themeCookie); err == nil && (c.Value == "light" || c.Value == "dark") {
		return c.Value
	}
	return ""
}

func (s *Server) setTheme(w http.ResponseWriter, r *http.Request) {
	theme := r.PathValue("theme")
	switch theme {
	case "light", "dark":
		http.SetCookie(w, &http.Cookie{Name: themeCookie, Value: theme, Path: "/", MaxAge: 365 * 24 * 3600,
			HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	case "system":
		http.SetCookie(w, &http.Cookie{Name: themeCookie, Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	default:
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

// prefs are the per-browser display switches kept in cookies.
var prefs = []string{"hide_blocked", "hide_trapped"}

// setPref turns one display switch on or off for a year and goes back.
func (s *Server) setPref(w http.ResponseWriter, r *http.Request) {
	name, value := r.PathValue("name"), r.PathValue("value")
	if !slices.Contains(prefs, name) || (value != "on" && value != "off") {
		http.NotFound(w, r)
		return
	}
	c := &http.Cookie{Name: "wafisp_" + name, Value: "1", Path: "/", MaxAge: 365 * 24 * 3600,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode}
	if value == "off" {
		c.Value, c.MaxAge = "", -1
	}
	http.SetCookie(w, c)
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

// pref tells whether a display switch is on in this browser.
func pref(r *http.Request, name string) bool {
	c, err := r.Cookie("wafisp_" + name)
	return err == nil && c.Value == "1"
}

// langFuncs are the template functions bound to one language.
func langFuncs(lang string) template.FuncMap {
	return template.FuncMap{
		"t":   func(s string, args ...any) string { return i18n.T(lang, s, args...) },
		"cat": func(code string) string { return i18n.T(lang, event.CategoryName(code)) },
		"tx":  func(s string) string { return i18n.T(lang, s) },
		// dur names a ban length the way the forms do: "7 days", "Permanent".
		"dur": func(d time.Duration) string {
			for _, o := range banDurations {
				if o.D == d {
					return i18n.T(lang, o.Label)
				}
			}
			return d.String()
		},
		"dt": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			if lang == i18n.RU {
				return t.Local().Format("02.01.2006 15:04:05")
			}
			return t.Local().Format("2006-01-02 15:04:05")
		},
		// left is the time until t, e.g. "5 h left".
		"left": func(t time.Time) string {
			d := time.Until(t)
			switch {
			case d <= 0:
				return i18n.T(lang, "expiring")
			case d < time.Hour:
				return i18n.T(lang, "%d min left", int(d.Minutes())+1)
			case d < 48*time.Hour:
				return i18n.T(lang, "%d h left", int(d.Hours()))
			}
			return i18n.T(lang, "%d days left", int(d.Hours()/24))
		},
		"ago": func(t time.Time) string {
			if t.IsZero() {
				return i18n.T(lang, "never")
			}
			d := time.Since(t)
			switch {
			case d < time.Minute:
				return i18n.T(lang, "%d s ago", int(d.Seconds()))
			case d < time.Hour:
				return i18n.T(lang, "%d min ago", int(d.Minutes()))
			case d < 48*time.Hour:
				return i18n.T(lang, "%d h ago", int(d.Hours()))
			}
			return i18n.T(lang, "%d days ago", int(d.Hours()/24))
		},
	}
}

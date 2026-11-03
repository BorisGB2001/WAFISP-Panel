package autoban

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"wafisp/internal/block"
	"wafisp/internal/ua"
	"wafisp/internal/visitors"
)

// Access-log rules catch what the WAF does not see, from the sites' nginx
// access logs: scanners probing for files (404 on pages), password
// guessing on login pages, floods. They are switched on and tried in dry
// run separately from the WAF rules, and share their escalation, durations
// and backends.

// DefaultLoginPaths are the sign-in pages of common CMSs; a path matches
// when it starts with one of them.
var DefaultLoginPaths = []string{"/wp-login.php", "/xmlrpc.php", "/administrator/index.php", "/bitrix/admin/",
	"/user/login", "/admin/login", "/login"}

// accessWin is what one address did within the access window.
type accessWin struct {
	notFound, logins, rate []time.Time
	site                   string
	last                   visitors.Request
}

// trim drops the times before cut.
func trim(ts []time.Time, cut time.Time) []time.Time {
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	return ts[i:]
}

func (s *Settings) loginPage(path string) bool {
	p := strings.ToLower(path)
	return slices.ContainsFunc(s.LoginPaths, func(l string) bool { return strings.HasPrefix(p, strings.ToLower(l)) })
}

// Access feeds one access log line of site; it returns a decision when the
// address crossed a line. Lines older than the window (a log read from its
// start) only count towards nothing. Known search engine bots are skipped:
// banning one hurts the sites more than its 404s.
func (e *Engine) Access(site string, r visitors.Request) *Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.st.Settings
	if !s.AccessEnabled || r.IP == "" || time.Since(r.Time) > s.AccessWindow {
		return nil
	}
	if c := ua.Parse(r.Agent); c.Kind == ua.Bot && c.Good {
		return nil
	}
	now := r.Time
	if last, ok := e.accessSeen[r.IP]; ok && now.Sub(last) < s.AccessWindow {
		return nil // decided on this address lately; dry run would repeat itself
	}
	w := e.access[r.IP]
	if w == nil {
		w = &accessWin{}
		e.access[r.IP] = w
	}
	w.site, w.last = site, r
	cut := now.Add(-s.AccessWindow)
	w.notFound, w.logins, w.rate = trim(w.notFound, cut), trim(w.logins, cut), trim(w.rate, now.Add(-time.Minute))
	if s.NotFound > 0 && r.Status == 404 && !visitors.IsAsset(r.Path) {
		w.notFound = append(w.notFound, now)
	}
	if s.Logins > 0 && r.Method == "POST" && s.loginPage(r.Path) {
		w.logins = append(w.logins, now)
	}
	if s.Rate > 0 {
		w.rate = append(w.rate, now)
	}
	win := int(s.AccessWindow / time.Minute)
	var rule block.Rule
	var reason string
	switch {
	case s.Logins > 0 && len(w.logins) >= s.Logins:
		rule = block.Rule{Kind: "access", Metric: "login", Count: s.Logins, WindowMin: win}
		reason = fmt.Sprintf("%d login attempts in %s, last POST %s", len(w.logins), s.AccessWindow, r.Path)
	case s.NotFound > 0 && len(w.notFound) >= s.NotFound:
		rule = block.Rule{Kind: "access", Metric: "404", Count: s.NotFound, WindowMin: win}
		reason = fmt.Sprintf("%d pages not found (404) in %s, last %s", len(w.notFound), s.AccessWindow, r.Path)
	case s.Rate > 0 && len(w.rate) >= s.Rate:
		rule = block.Rule{Kind: "access", Metric: "rate", Count: s.Rate, WindowMin: 1}
		reason = fmt.Sprintf("%d requests in a minute, last %s %s", len(w.rate), r.Method, r.Path)
	default:
		e.gcAccess(now, s.AccessWindow)
		return nil
	}
	delete(e.access, r.IP)
	e.accessSeen[r.IP] = now
	n := e.offence(r.IP, now)
	rule.Offence = n
	return &Decision{IP: r.IP, Site: site, At: now, Offence: n, Duration: s.Durations[min(n-1, len(s.Durations)-1)],
		Reason: reason + " on " + site, DryRun: s.AccessDryRun, Rule: rule}
}

// gcAccess drops addresses that went quiet, once there are many.
func (e *Engine) gcAccess(now time.Time, window time.Duration) {
	if len(e.access) < 20000 && len(e.accessSeen) < 20000 {
		return
	}
	for ip, w := range e.access {
		if now.Sub(w.last.Time) > window {
			delete(e.access, ip)
		}
	}
	for ip, at := range e.accessSeen {
		if now.Sub(at) > window {
			delete(e.accessSeen, ip)
		}
	}
}

func validateAccess(s *Settings) error {
	if s.AccessWindow < time.Minute || s.AccessWindow > 24*time.Hour {
		return fmt.Errorf("the access log window must be between 1 minute and 24 hours")
	}
	if s.NotFound != 0 && (s.NotFound < 5 || s.NotFound > 100000) {
		return fmt.Errorf("the 404 limit must be 0 (off) or between 5 and 100000")
	}
	if s.Logins != 0 && (s.Logins < 3 || s.Logins > 100000) {
		return fmt.Errorf("the login attempt limit must be 0 (off) or between 3 and 100000")
	}
	if s.Rate != 0 && (s.Rate < 60 || s.Rate > 1000000) {
		return fmt.Errorf("the request rate limit must be 0 (off) or between 60 and 1000000 a minute")
	}
	if len(s.LoginPaths) > 30 {
		return fmt.Errorf("give at most 30 login pages")
	}
	for _, p := range s.LoginPaths {
		if !strings.HasPrefix(p, "/") || len(p) > 200 || strings.ContainsAny(p, " \t\"'<>") {
			return fmt.Errorf("a login page is a path starting with /: %q", p)
		}
	}
	if s.AccessEnabled && s.NotFound == 0 && s.Logins == 0 && s.Rate == 0 {
		return fmt.Errorf("the access log rules are on but every limit is 0")
	}
	return nil
}

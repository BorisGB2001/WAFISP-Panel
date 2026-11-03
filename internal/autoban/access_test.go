package autoban

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wafisp/internal/visitors"
)

func accessEngine(t *testing.T, change func(*Settings)) *Engine {
	e := open(t)
	s := e.Settings()
	s.AccessEnabled, s.AccessDryRun, s.NotFound, s.Logins, s.Rate = true, false, 5, 3, 60
	if change != nil {
		change(&s)
	}
	if err := s.Validate([]string{"ipset"}); err != nil {
		t.Fatal(err)
	}
	e.SetSettings(s)
	return e
}

const browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"

func line(ago time.Duration, ip, method, path string, status int, agent string) visitors.Request {
	return visitors.Request{Time: time.Now().Add(-ago), IP: ip, Method: method, Path: path, Status: status, Agent: agent}
}

// feed sends n lines and returns the first decision.
func feed(e *Engine, n int, r visitors.Request) *Decision {
	for range n {
		if d := e.Access("shop.example", r); d != nil {
			return d
		}
	}
	return nil
}

func TestAccessNotFound(t *testing.T) {
	e := accessEngine(t, nil)
	// Missing images, styles and scripts are not a scan.
	if d := feed(e, 20, line(0, "203.0.113.5", "GET", "/img/banner.png", 404, browser)); d != nil {
		t.Fatalf("banned for missing images: %+v", d)
	}
	if d := feed(e, 4, line(0, "203.0.113.5", "GET", "/.env", 404, browser)); d != nil {
		t.Fatalf("banned under the limit: %+v", d)
	}
	d := feed(e, 1, line(0, "203.0.113.5", "GET", "/backup.zip", 404, browser))
	if d == nil || d.Rule.Kind != "access" || d.Rule.Metric != "404" || d.Rule.Count != 5 || d.Offence != 1 || d.DryRun {
		t.Fatalf("decision %+v", d)
	}
	if !strings.Contains(d.Reason, "/backup.zip") || d.Site != "shop.example" {
		t.Fatalf("reason %q", d.Reason)
	}
	// One decision per address within the window, even in dry run.
	if d := feed(e, 10, line(0, "203.0.113.5", "GET", "/.git/config", 404, browser)); d != nil {
		t.Fatalf("decided twice: %+v", d)
	}
}

func TestAccessLogins(t *testing.T) {
	e := accessEngine(t, nil)
	// Opening the login page is not an attempt; a POST is.
	if d := feed(e, 10, line(0, "203.0.113.6", "GET", "/wp-login.php", 200, browser)); d != nil {
		t.Fatalf("banned for GETs: %+v", d)
	}
	d := feed(e, 3, line(0, "203.0.113.6", "POST", "/WP-LOGIN.PHP", 200, browser))
	if d == nil || d.Rule.Metric != "login" {
		t.Fatalf("decision %+v", d)
	}
	if d := feed(e, 10, line(0, "203.0.113.7", "POST", "/checkout", 200, browser)); d != nil {
		t.Fatalf("banned for POSTs to another page: %+v", d)
	}
}

func TestAccessRateAndSkips(t *testing.T) {
	e := accessEngine(t, func(s *Settings) { s.AccessDryRun = true })
	if d := feed(e, 60, line(0, "203.0.113.8", "GET", "/", 200, browser)); d == nil || d.Rule.Metric != "rate" || !d.DryRun {
		t.Fatalf("decision %+v", d)
	}
	// Search engine bots never count.
	if d := feed(e, 200, line(0, "203.0.113.9", "GET", "/missing", 404, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")); d != nil {
		t.Fatalf("banned a search engine: %+v", d)
	}
	// Lines older than the window, from a log read from its start, do not count.
	if d := feed(e, 200, line(time.Hour, "203.0.113.10", "GET", "/missing", 404, browser)); d != nil {
		t.Fatalf("banned for old lines: %+v", d)
	}
	// Off means off.
	s := e.Settings()
	s.AccessEnabled = false
	e.SetSettings(s)
	if d := feed(e, 200, line(0, "203.0.113.11", "GET", "/missing", 404, browser)); d != nil {
		t.Fatalf("banned while off: %+v", d)
	}
}

func TestAccessValidate(t *testing.T) {
	for _, change := range []func(*Settings){
		func(s *Settings) { s.AccessWindow = 0 },
		func(s *Settings) { s.NotFound = 2 },
		func(s *Settings) { s.Rate = 10 },
		func(s *Settings) { s.LoginPaths = []string{"wp-login.php"} },
		func(s *Settings) { s.AccessEnabled, s.NotFound, s.Logins, s.Rate = true, 0, 0, 0 },
	} {
		s := Defaults()
		change(&s)
		if s.Validate([]string{"ipset"}) == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	if s := Defaults(); s.Validate([]string{"ipset"}) != nil || s.AccessEnabled || !s.AccessDryRun {
		t.Fatal("the defaults must be valid, off and in dry run")
	}
}

func TestAccessOldSettingsFile(t *testing.T) {
	// autoban.json from before the access-log rules gets their defaults.
	f := filepath.Join(t.TempDir(), "autoban.json")
	os.WriteFile(f, []byte(`{"settings":{"enabled":true,"dry_run":false,"threshold":7,"window":600000000000,"durations":[86400000000000],"backends":["ipset"]}}`), 0o600)
	e, err := Open(f)
	if err != nil {
		t.Fatal(err)
	}
	s := e.Settings()
	if s.Threshold != 7 || s.AccessEnabled || !s.AccessDryRun || s.AccessWindow != 5*time.Minute || len(s.LoginPaths) == 0 {
		t.Fatalf("settings %+v", s)
	}
	if err := s.Validate([]string{"ipset"}); err != nil {
		t.Fatal(err)
	}
}

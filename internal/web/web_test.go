package web

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"wafisp/internal/autoban"
	"wafisp/internal/block"
	"wafisp/internal/collector"
	"wafisp/internal/config"
	"wafisp/internal/event"
	"wafisp/internal/history"
	"wafisp/internal/policy"
	"wafisp/internal/sites"
	"wafisp/internal/stats"
	"wafisp/internal/store"
)

type ruleSink struct{ got []config.Rule }

func (r *ruleSink) SetRules(rs []config.Rule) { r.got = rs }

// memBackend is a block backend that only remembers.
type memBackend struct{ ips []string }

func (m *memBackend) Name() string                               { return "ipset" }
func (m *memBackend) Ensure(context.Context) error               { return nil }
func (m *memBackend) Sync(_ context.Context, ips []string) error { m.ips = ips; return nil }
func (m *memBackend) List(context.Context) ([]string, error)     { return m.ips, nil }

type testEnv struct {
	*Server
	ipset *memBackend
	nginx []string // commands run
}

func newTestServer(t *testing.T) (*httptest.Server, *testEnv, *ruleSink) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// A vhost tree as ISPmanager writes it.
	os.MkdirAll(filepath.Join(dir, "vhosts", "shop"), 0o755)
	os.WriteFile(filepath.Join(dir, "vhosts", "shop", "shop.example.ru.conf"), []byte("server {\n\tserver_name shop.example.ru www.shop.example.ru;\n}\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "res", "shop.example.ru"), 0o755)
	os.WriteFile(filepath.Join(dir, "res", "shop.example.ru", "modsecurity.conf"), []byte("modsecurity on;\nmodsecurity_rules '\n\tSecRuleEngine On\n\tSecAuditLog /x/shop.example.ru.audit.log\n';\n"), 0o644)

	cfg := &config.Config{
		Channels: []config.Channel{{Name: "tg", Type: "telegram", Telegram: &config.Telegram{ChatID: "1"}}},
		Web:      config.Web{DataDir: dir, SessionTTL: config.Duration(time.Hour)},
		DataDir:  dir,
		Block:    config.Block{Backends: []string{"ipset", "modsec"}, Default: []string{"ipset"}, Ports: "80,443"},
	}
	st, err := store.Open(dir, 30*24*time.Hour, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	now := time.Now()
	st.Add(&event.Event{ID: "ev1", Site: "shop.example.ru", Host: "shop.example.ru", Time: now.Add(-time.Minute), SrcIP: "198.51.100.7",
		Method: "GET", URI: "/q?id=1'or 1=1", Status: 403, Denied: true, Score: 10, Category: "sqli", Country: "NL",
		Headers: []event.Header{{Name: "Host", Value: "shop.example.ru"}},
		Rules: []event.Match{{ID: "942100", Msg: "SQL Injection Attack Detected via libinjection", Data: "Matched Data: 1'or 1=1 found within ARGS:id: 1'or 1=1", Var: "ARGS:id", Severity: 2},
			{ID: "949110", Msg: "Inbound Anomaly Score Exceeded", Denied: true}}})
	for i, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		st.Add(&event.Event{ID: fmt.Sprint("fp", i), Site: "shop.example.ru", Host: "shop.example.ru", Time: now.Add(-time.Hour), SrcIP: ip,
			Method: "POST", URI: "/admin/save", Status: 403, Denied: true, Score: 5, Category: "xss",
			Rules: []event.Match{{ID: "941100", Msg: "XSS Attack Detected via libinjection", Var: "ARGS:text", Severity: 2}}})
	}

	env := &testEnv{ipset: &memBackend{}}
	pol := &policy.Manager{File: filepath.Join(dir, "policy.json"), Dir: filepath.Join(dir, "rules"),
		Test: []string{"nginx", "-t"}, Reload: []string{"reload"}, Log: log,
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			env.nginx = append(env.nginx, name)
			return nil, nil
		}}
	pol.Load()
	blocks := &block.Manager{File: filepath.Join(dir, "blocks.json"), Log: log,
		Backends: []block.Backend{env.ipset, &block.ModSec{Policy: pol}}}

	hist, _ := history.Open(filepath.Join(dir, "h.jsonl"), 100)
	sink := &ruleSink{}
	ban, _ := autoban.Open(filepath.Join(dir, "autoban.json"))
	env.Server = &Server{Cfg: cfg, Store: st, Collector: &collector.Collector{}, Policy: pol, Blocks: blocks, Autoban: ban, Health: &Health{},
		Sites: &sites.Reader{VhostsDir: filepath.Join(dir, "vhosts"), ResourcesDir: filepath.Join(dir, "res")},
		Stats: stats.New(), History: hist, Rules: sink, Log: log, Version: "test", RuleFile: filepath.Join(dir, "rules.yaml")}
	if err := env.Server.Open(nil); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(env.Server.Handler())
	t.Cleanup(ts.Close)
	return ts, env, sink
}

// browser is a separate client with its own cookies; ts.Client() returns
// the same shared client every time.
func browser(ts *httptest.Server) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Transport:     ts.Client().Transport,
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func login(t *testing.T, ts *httptest.Server, c *http.Client, user, pw string) {
	t.Helper()
	resp, err := c.PostForm(ts.URL+"/login", url.Values{"username": {user}, "password": {pw}, "next": {"/"}})
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login %s: status %d", user, resp.StatusCode)
	}
}

func get(t *testing.T, ts *httptest.Server, c *http.Client, path string) (int, string) {
	t.Helper()
	resp, err := c.Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body(t, resp)
}

func TestPanel(t *testing.T) {
	ts, s, sink := newTestServer(t)
	c := browser(ts)

	if code, _ := get(t, ts, c, "/"); code != http.StatusSeeOther {
		t.Fatalf("anonymous dashboard: %d", code)
	}
	resp, _ := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"wrong-password"}})
	if body(t, resp); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))

	for path, want := range map[string]string{
		"/":                    "Top attackers",
		"/attacks":             "198.51.100.7",
		"/attacks?rule=941100": "Found: 3",
		"/attacks/ev1":         "ARGS:id",
		"/analysis":            "/admin/save",
		"/ip/198.51.100.7":     "942100",
		"/sites":               "www.shop.example.ru",
		"/blocks":              "No addresses are blocked",
		"/exclusions?rule=1":   "New exclusion",
		"/alerts":              "No alerts yet",
		"/rules":               "Rule editor",
		"/channels":            "chat_id 1",
		"/users":               "admin",
		"/audit":               "login.failed",
		"/account":             "Change password",
		"/attacks.csv":         "ev1",
	} {
		code, b := get(t, ts, c, path)
		if code != http.StatusOK || !strings.Contains(b, want) {
			t.Errorf("%s: status %d, %q not found", path, code, want)
		}
	}
	_, page := get(t, ts, c, "/rules")
	csrf := csrfRe.FindStringSubmatch(page)[1]

	// Missing CSRF token.
	resp, _ = c.PostForm(ts.URL+"/rules", url.Values{"yaml": {"[]"}})
	if body(t, resp); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rules without csrf: %d", resp.StatusCode)
	}
	// Unknown channel is rejected and nothing is applied.
	resp, _ = c.PostForm(ts.URL+"/rules", url.Values{"csrf": {csrf}, "yaml": {"- name: x\n  channels: [nope]\n"}})
	if b := body(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(b, "unknown channel") || sink.got != nil {
		t.Fatalf("bad rules: %d", resp.StatusCode)
	}
	resp, _ = c.PostForm(ts.URL+"/rules", url.Values{"csrf": {csrf}, "yaml": {"- name: burst\n  threshold: 5\n  window: 1m\n  channels: [tg]\n"}})
	if body(t, resp); resp.StatusCode != http.StatusSeeOther || len(sink.got) != 1 || sink.got[0].Cooldown.D() != time.Minute {
		t.Fatalf("save rules: %d %+v", resp.StatusCode, sink.got)
	}
	if b, _ := os.ReadFile(s.RuleFile); !strings.Contains(string(b), "burst") {
		t.Fatal("rules file not written")
	}

	// A viewer reads but cannot change anything.
	resp, _ = c.PostForm(ts.URL+"/users", url.Values{"csrf": {csrf}, "name": {"viewer1"}, "role": {"viewer"}, "password": {"viewer-password-1"}})
	if b := body(t, resp); !strings.Contains(b, "User viewer1 created") {
		t.Fatalf("add user: %d", resp.StatusCode)
	}
	v := browser(ts)
	login(t, ts, v, "viewer1", "viewer-password-1")
	if code, _ := get(t, ts, v, "/attacks"); code != http.StatusOK {
		t.Fatalf("viewer attacks: %d", code)
	}
	if code, _ := get(t, ts, v, "/users"); code != http.StatusForbidden {
		t.Fatalf("viewer users: %d", code)
	}
	_, vp := get(t, ts, v, "/rules")
	if strings.Contains(vp, "Rule editor") {
		t.Fatal("viewer sees the rule editor")
	}
	vcsrf := csrfRe.FindStringSubmatch(vp)[1]
	resp, _ = v.PostForm(ts.URL+"/rules", url.Values{"csrf": {vcsrf}, "yaml": {"[]"}})
	if body(t, resp); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer saved rules: %d", resp.StatusCode)
	}

	// Changing the role ends the viewer's sessions.
	resp, _ = c.PostForm(ts.URL+"/users/viewer1/role", url.Values{"csrf": {csrf}, "role": {"admin"}})
	if b := body(t, resp); !strings.Contains(b, "Role of viewer1 changed") {
		t.Fatalf("role change: %d %s", resp.StatusCode, b[:min(len(b), 300)])
	}
	if code, _ := get(t, ts, v, "/attacks"); code != http.StatusSeeOther {
		t.Fatalf("old session still valid after role change: %d", code)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/attacks?ip=1": "/attacks?ip=1", "//evil.com": "/", "https://evil.com": "/", "/\\evil": "/"} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q", in, got)
		}
	}
}

func TestCertLoader(t *testing.T) {
	cert, key, err := selfSigned(filepath.Join(t.TempDir(), "tls"))
	if err != nil {
		t.Fatal(err)
	}
	cl := &certLoader{cert: cert, key: key}
	c1, err := cl.get(nil)
	if err != nil || c1 == nil {
		t.Fatalf("load: %v", err)
	}
	// A broken file after a successful load keeps serving the old certificate.
	os.WriteFile(cert, []byte("broken"), 0o644)
	cl.checked = time.Time{}
	if c2, err := cl.get(nil); err != nil || c2 != c1 {
		t.Fatalf("broken renewal replaced the certificate: %v", err)
	}
}

func TestLanguageSwitch(t *testing.T) {
	ts, s, _ := newTestServer(t)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))
	if _, b := get(t, ts, c, "/attacks"); !strings.Contains(b, "Attack log") || !strings.Contains(b, `lang="en"`) {
		t.Fatal("English is not the default")
	}
	if code, _ := get(t, ts, c, "/lang/ru?next=/attacks"); code != http.StatusSeeOther {
		t.Fatalf("switch: %d", code)
	}
	if _, b := get(t, ts, c, "/attacks"); !strings.Contains(b, "Журнал атак") || !strings.Contains(b, "Найдено") {
		t.Fatal("Russian not applied")
	}
	if code, _ := get(t, ts, c, "/lang/de"); code != http.StatusNotFound {
		t.Fatal("unknown language accepted")
	}
	if _, loc := get(t, ts, c, "/lang/en?next=//evil.example"); strings.Contains(loc, "evil") {
		t.Fatal("open redirect")
	}
}

func TestThemeSwitch(t *testing.T) {
	ts, s, _ := newTestServer(t)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))
	// The switches come back to the page they were used on, without its flash.
	_, b := get(t, ts, c, "/attacks?period=7d&ok=done")
	if strings.Contains(b, "data-theme=") || !strings.Contains(b, `href="/theme/dark?next=%2Fattacks%3Fperiod%3D7d"`) ||
		!strings.Contains(b, `href="/lang/ru?next=%2Fattacks%3Fperiod%3D7d"`) {
		t.Fatal("system theme by default, switches return to this page")
	}
	for theme, want := range map[string]string{"dark": `data-theme="dark"`, "light": `data-theme="light"`, "system": ""} {
		resp, err := c.Get(ts.URL + "/theme/" + theme + "?next=/attacks")
		if err != nil {
			t.Fatal(err)
		}
		body(t, resp)
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/attacks" {
			t.Fatalf("%s: %d %s", theme, resp.StatusCode, loc)
		}
		_, b := get(t, ts, c, "/attacks")
		if (want == "" && strings.Contains(b, "data-theme=")) || (want != "" && !strings.Contains(b, want)) {
			t.Errorf("%s not applied", theme)
		}
	}
	if code, _ := get(t, ts, c, "/theme/pink"); code != http.StatusNotFound {
		t.Fatal("unknown theme accepted")
	}
}

func TestBlockingAndExclusions(t *testing.T) {
	ts, env, _ := newTestServer(t)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(env.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))
	_, page := get(t, ts, c, "/blocks")
	csrf := csrfRe.FindStringSubmatch(page)[1]
	post := func(path string, v url.Values) *http.Response {
		v.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		body(t, resp)
		return resp
	}

	// Block through two backends.
	resp := post("/blocks", url.Values{"ip": {"198.51.100.7"}, "reason": {"sqli"}, "ttl": {"24h"}, "backend": {"ipset", "modsec"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "ok=") {
		t.Fatalf("block: %s", loc)
	}
	if len(env.ipset.ips) != 1 || env.Policy.State().Deny[0] != "198.51.100.7" {
		t.Fatalf("backends not synced: %v %v", env.ipset.ips, env.Policy.State().Deny)
	}
	deny, _ := os.ReadFile(filepath.Join(env.Cfg.DataDir, "rules", "deny.txt"))
	if string(deny) != "198.51.100.7\n" {
		t.Fatalf("deny.txt %q", deny)
	}
	if _, b := get(t, ts, c, "/ip/198.51.100.7"); !strings.Contains(b, "Unblock 198.51.100.7") {
		t.Fatal("ip page does not show the block")
	}
	// A private address is refused.
	resp = post("/blocks", url.Values{"ip": {"10.1.2.3"}, "reason": {"x"}, "ttl": {"1h"}, "backend": {"ipset"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatalf("private address blocked: %s", loc)
	}
	post("/blocks/unblock", url.Values{"ip": {"198.51.100.7"}})
	if len(env.ipset.ips) != 0 || len(env.Policy.State().Deny) != 0 {
		t.Fatal("not unblocked")
	}

	// A site exclusion becomes a runtime rule in before.conf.
	resp = post("/exclusions", url.Values{"site": {"shop.example.ru"}, "path": {"/admin/"}, "rules": {"941100"}, "target": {"ARGS:text"}, "reason": {"editor"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "ok=") {
		t.Fatalf("exclusion: %s", loc)
	}
	before, _ := os.ReadFile(filepath.Join(env.Cfg.DataDir, "rules", "before.conf"))
	if !strings.Contains(string(before), "ctl:ruleRemoveTargetById=941100;ARGS:text") || !strings.Contains(string(before), `www\.shop\.example\.ru`) {
		t.Fatalf("before.conf:\n%s", before)
	}
	// One for every site needs the confirmation box.
	resp = post("/exclusions", url.Values{"rules": {"942100"}, "reason": {"x"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatal("global exclusion without confirmation accepted")
	}
	// Injection attempts are refused.
	resp = post("/exclusions", url.Values{"site": {"shop.example.ru"}, "rules": {`942100,deny"`}, "reason": {"x"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatal("bad rule id accepted")
	}

	// One-click ban from the attack log: the form carries everything.
	if _, b := get(t, ts, c, "/attacks"); !strings.Contains(b, `name="ttl" value="0"`) || !strings.Contains(b, "quick ban") {
		t.Fatal("no quick-ban buttons in the attack log")
	}
	resp = post("/blocks", url.Values{"ip": {"198.51.100.7"}, "reason": {"quick ban: x"}, "ttl": {"0"}, "backend": {"ipset"}, "back": {"/attacks?period=24h"}})
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/attacks?period=24h") || !strings.Contains(loc, "ok=") {
		t.Fatalf("quick ban: %s", loc)
	}
	if e, ok := env.Blocks.Lookup("198.51.100.7"); !ok || !e.Expires.IsZero() {
		t.Fatal("permanent quick ban not stored")
	}
	post("/blocks/unblock", url.Values{"ip": {"198.51.100.7"}})

	// Auto-ban settings are validated and audited.
	resp = post("/autoban", url.Values{"enabled": {"on"}, "dry_run": {"on"}, "threshold": {"1"}, "window": {"10"}, "duration": {"24h"}, "backend": {"ipset"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatal("threshold 1 accepted")
	}
	resp = post("/autoban", url.Values{"enabled": {"on"}, "dry_run": {"on"}, "threshold": {"30"}, "window": {"5"}, "instant": {"rce"},
		"instant_score": {"10"}, "duration": {"24h", "7d", "0"}, "backend": {"ipset"}})
	if st := env.Autoban.Settings(); !st.Enabled || st.Threshold != 30 || st.Window != 5*time.Minute || len(st.Durations) != 3 || st.Durations[2] != 0 {
		t.Fatalf("settings %+v (%s)", st, resp.Header.Get("Location"))
	}

	// Site mode override.
	resp = post("/sites/shop.example.ru/mode", url.Values{"engine": {"DetectionOnly"}, "reason": {"tuning"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "ok=") || env.Policy.State().ModeOf("shop.example.ru") != "DetectionOnly" {
		t.Fatalf("mode: %s", loc)
	}
	resp = post("/sites/shop.example.ru/mode", url.Values{"engine": {"Off"}, "reason": {"x"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatal("WAF off without typing the site name")
	}
	if _, b := get(t, ts, c, "/audit"); !strings.Contains(b, "exclusion.add") || !strings.Contains(b, "site.mode") {
		t.Fatal("audit misses the changes")
	}
}

func TestBlockedList(t *testing.T) {
	ts, env, _ := newTestServer(t)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(env.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))
	_, page := get(t, ts, c, "/blocked")
	csrf := csrfRe.FindStringSubmatch(page)[1]
	post := func(path string, v url.Values) string {
		v.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		body(t, resp)
		return resp.Header.Get("Location")
	}
	post("/blocks", url.Values{"ip": {"198.51.100.7"}, "reason": {"sqli"}, "ttl": {"1h"}, "backend": {"ipset"}})

	// Blocked addresses are red in the top lists and the log, and counted in the menu.
	if _, b := get(t, ts, c, "/"); !strings.Contains(b, `<li class="blocked">`) || !strings.Contains(b, `class="count">1<`) {
		t.Fatal("dashboard does not mark the blocked attacker")
	}
	if _, b := get(t, ts, c, "/attacks"); !strings.Contains(b, `class="blocked"`) {
		t.Fatal("attack log does not mark the blocked address")
	}
	if _, b := get(t, ts, c, "/blocked"); !strings.Contains(b, "198.51.100.7") || !strings.Contains(b, "Set time") {
		t.Fatal("blocked page")
	}
	// The search box: a full address opens its page, a prefix the log.
	for q, want := range map[string]string{"198.51.100.7": "/ip/198.51.100.7", "198.51.100.": "ip=198.51.100.%2A", "198.51.100.0/24": "ip=198.51.100.0%2F24", "<script>": "err="} {
		resp, _ := c.Get(ts.URL + "/search?q=" + url.QueryEscape(q))
		body(t, resp)
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, want) {
			t.Errorf("search %q: %s", q, loc)
		}
	}
	if _, b := get(t, ts, c, "/attacks?period=30d&ip=198.51.100.*"); !strings.Contains(b, "Found: 1") {
		t.Error("prefix filter")
	}

	// A new time: permanent.
	if loc := post("/blocks/expiry", url.Values{"ip": {"198.51.100.7"}, "ttl": {"0"}}); !strings.Contains(loc, "ok=") {
		t.Fatalf("expiry: %s", loc)
	}
	if e, _ := env.Blocks.Lookup("198.51.100.7"); !e.Expires.IsZero() {
		t.Fatal("not permanent")
	}
	// To the allow list: unblocked everywhere and allowed.
	if loc := post("/blocks/allow", url.Values{"ip": {"198.51.100.7"}, "reason": {"partner"}}); !strings.Contains(loc, "ok=") {
		t.Fatalf("to allow: %s", loc)
	}
	if _, ok := env.Blocks.Lookup("198.51.100.7"); ok || len(env.ipset.ips) != 0 || !env.allowed("198.51.100.7") {
		t.Fatal("not moved to the allow list")
	}
	allow, _ := os.ReadFile(filepath.Join(env.Cfg.DataDir, "rules", "allow.txt"))
	if string(allow) != "198.51.100.7\n" {
		t.Fatalf("allow.txt %q", allow)
	}
}

func TestMassBan(t *testing.T) {
	ts, env, _ := newTestServer(t)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(env.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))

	// The buttons: on every row of the log and on the event card.
	if _, b := get(t, ts, c, "/attacks"); !strings.Contains(b, `/massban?rule=941100&amp;period=24h`) {
		t.Fatal("no mass-ban link in the log")
	}
	if _, b := get(t, ts, c, "/attacks/ev1"); !strings.Contains(b, "/massban?rule=942100&amp;site=shop.example.ru&amp;period=7d") {
		t.Fatal("no scoped mass-ban links on the card")
	}
	// Without an attack it refuses to list everyone.
	if _, b := get(t, ts, c, "/massban"); !strings.Contains(b, "Choose an attack first") {
		t.Fatal("mass ban without a filter")
	}
	// Three addresses hit 941100 on one path: they look like visitors.
	code, page := get(t, ts, c, "/massban?rule=941100&period=7d")
	if code != http.StatusOK || !strings.Contains(page, "Addresses: 3") || !strings.Contains(page, "look like ordinary visitors") {
		t.Fatalf("preview %d", code)
	}
	csrf := csrfRe.FindStringSubmatch(page)[1]
	env.nginx = nil
	v := url.Values{"csrf": {csrf}, "reason": {"xss wave"}, "ttl": {"7d"}, "backend": {"ipset", "modsec"},
		"ip": {"203.0.113.1", "203.0.113.2", "198.51.100.7"}} // the last one does not match the filter
	// Without the confirmation nothing happens.
	resp, _ := c.PostForm(ts.URL+"/massban?rule=941100&period=7d", v)
	body(t, resp)
	if len(env.Blocks.Entries()) != 0 {
		t.Fatal("blocked without confirmation")
	}
	v.Set("confirm", "yes")
	resp, _ = c.PostForm(ts.URL+"/massban?rule=941100&period=7d", v)
	body(t, resp)
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "/blocked") {
		t.Fatalf("mass ban: %s", loc)
	}
	got := env.Blocks.Entries()
	if len(got) != 2 || len(env.ipset.ips) != 2 {
		t.Fatalf("want the 2 ticked matching addresses, got %+v", got)
	}
	if _, ok := env.Blocks.Lookup("198.51.100.7"); ok {
		t.Fatal("an address outside the filter was blocked")
	}
	// One nginx -t and one reload for the whole batch.
	if len(env.nginx) != 2 {
		t.Fatalf("nginx ran %d times: %v", len(env.nginx), env.nginx)
	}
	if _, b := get(t, ts, c, "/audit"); !strings.Contains(b, "block.mass") {
		t.Fatal("not audited")
	}
}

func TestAllowFrom(t *testing.T) {
	s := &Server{Cfg: &config.Config{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	s.Cfg.Web.Allowed = []netip.Prefix{netip.MustParsePrefix("10.6.0.0/16"), netip.MustParsePrefix("10.0.0.7/32")}
	h := s.allowFrom(ok)
	for addr, want := range map[string]int{"10.6.250.110:5000": 200, "10.0.0.7:1": 200, "10.0.0.8:1": 403, "10.7.0.1:1": 403, "[::ffff:10.6.1.1]:1": 200, "[2001:db8::1]:1": 403} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/login", nil)
		r.RemoteAddr = addr
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s: %d, want %d", addr, w.Code, want)
		}
	}
}

func TestAllowListNeverBans(t *testing.T) {
	ts, env, _ := newTestServer(t)
	c := browser(ts)
	pw, _ := os.ReadFile(filepath.Join(env.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))
	_, page := get(t, ts, c, "/blocks")
	csrf := csrfRe.FindStringSubmatch(page)[1]
	post := func(path string, v url.Values) string {
		v.Set("csrf", csrf)
		resp, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		body(t, resp)
		return resp.Header.Get("Location")
	}

	// A blocked address shows who, when and why.
	post("/blocks", url.Values{"ip": {"198.51.100.7"}, "reason": {"sqli probes"}, "ttl": {"0"}, "backend": {"ipset"}})
	if _, b := get(t, ts, c, "/ip/198.51.100.7"); !strings.Contains(b, "manually by admin") || !strings.Contains(b, "sqli probes") {
		t.Fatal("the address page does not say who blocked it and why")
	}
	// Putting it on the allow list lifts the block.
	post("/allow", url.Values{"ip": {"198.51.100.0/24"}, "reason": {"partner"}, "ttl": {"0"}})
	if _, ok := env.Blocks.Lookup("198.51.100.7"); ok || len(env.ipset.ips) != 0 {
		t.Fatal("still blocked after going on the allow list")
	}
	// And it cannot be blocked again, alone or as part of a subnet.
	for _, ip := range []string{"198.51.100.7", "198.51.100.0/25"} {
		post("/blocks", url.Values{"ip": {ip}, "reason": {"again"}, "ttl": {"24h"}, "backend": {"ipset"}})
		if len(env.Blocks.Entries()) != 0 {
			t.Fatalf("%s blocked although allowed", ip)
		}
	}
	if _, b := get(t, ts, c, "/ip/198.51.100.7"); !strings.Contains(b, "On the allow list: 198.51.100.0/24") {
		t.Fatal("the address page does not show the allow-list entry")
	}
	if !strings.Contains(env.Policy.State().Allow[0].IP, "198.51.100.0/24") {
		t.Fatal("allow list not saved")
	}
	before, _ := os.ReadFile(filepath.Join(env.Policy.Dir, "before.conf"))
	if !strings.Contains(string(before), "ctl:ruleEngine=DetectionOnly") {
		t.Fatal("allowed addresses must be logged, not ignored")
	}
}

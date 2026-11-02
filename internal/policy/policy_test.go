package policy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFiles(t *testing.T) {
	s := State{
		Allow: []Addr{{IP: "198.51.100.1"}},
		Deny:  []string{"203.0.113.0/24", "203.0.113.9"},
		Modes: []Mode{{Site: "shop.example.com", Hosts: []string{"shop.example.com", "www.shop.example.com"}, Engine: "DetectionOnly"}},
		Exclusions: []Exclusion{
			{ID: 1, Rules: []string{"942100"}},
			{ID: 2, Rules: []string{"941100"}, Target: "ARGS:text"},
			{ID: 3, Site: "shop.example.com", Hosts: []string{"shop.example.com"}, Path: "/admin/", Tags: []string{"attack-xss"}, Target: "ARGS:jform[articletext]"},
			{ID: 4, Path: "/api/", Rules: []string{"920100-920199"}},
			{ID: 5, Disabled: true, Rules: []string{"1"}},
		},
	}
	before, after := s.Files("/etc/modsecurity/wafisp")
	for _, want := range []string{
		`SecRule REMOTE_ADDR "@ipMatchFromFile /etc/modsecurity/wafisp/allow.txt" "id:7710001,phase:1,pass,nolog,ctl:ruleEngine=Off"`,
		`id:7710002,phase:1,deny,status:403`,
		`SecRule REQUEST_HEADERS:Host "@rx ^(?:shop\.example\.com|www\.shop\.example\.com)(?::[0-9]+)?$" "id:7710100,phase:1,pass,nolog,t:lowercase,ctl:ruleEngine=DetectionOnly"`,
		`SecRule REQUEST_HEADERS:Host "@rx ^(?:shop\.example\.com)(?::[0-9]+)?$" "id:7711003,phase:1,pass,nolog,t:none,t:lowercase,chain"`,
		"\tSecRule REQUEST_FILENAME \"@beginsWith /admin/\" \"t:none,ctl:ruleRemoveTargetByTag=attack-xss;ARGS:jform[articletext]\"",
		`SecRule REQUEST_FILENAME "@beginsWith /api/" "id:7711004,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=920100-920199"`,
	} {
		if !strings.Contains(before, want) {
			t.Errorf("before.conf misses\n%s\nin\n%s", want, before)
		}
	}
	for _, want := range []string{"SecRuleRemoveById 942100\n", "SecRuleUpdateTargetById 941100 \"!ARGS:text\"\n"} {
		if !strings.Contains(after, want) {
			t.Errorf("after.conf misses %q in\n%s", want, after)
		}
	}
	if strings.Contains(before+after, "exclusion 5") {
		t.Error("disabled exclusion written")
	}
	if got := AddrList(s.Deny); got != "203.0.113.0/24\n203.0.113.9\n" {
		t.Errorf("deny list %q", got)
	}
	if got := AddrList(nil); got != Placeholder+"\n" {
		t.Errorf("empty list %q", got)
	}
}

func TestValidateRefusesInjection(t *testing.T) {
	for name, x := range map[string]Exclusion{
		"no rules":       {},
		"quote in rule":  {Rules: []string{`942100"`}},
		"bad target":     {Rules: []string{"942100"}, Target: `ARGS:a",deny,"`},
		"bad path":       {Rules: []string{"942100"}, Path: `/a" "id:1`},
		"range target":   {Rules: []string{"942100-942200"}, Target: "ARGS:a"},
		"empty range":    {Rules: []string{"942200-942100"}},
		"site no hosts":  {Rules: []string{"942100"}, Site: "x"},
		"bad host":       {Rules: []string{"942100"}, Site: "x", Hosts: []string{"a b"}},
		"bad tag":        {Tags: []string{"a'b"}},
		"newline in tag": {Tags: []string{"a\nb"}},
	} {
		if err := x.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	ok := Exclusion{ID: 1, Site: "x", Hosts: []string{"*.example.com"}, Path: "/a/b.php", Rules: []string{"942100"}, Target: "REQUEST_COOKIES:sess_1"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRestoresOnFailedTest(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	m := &Manager{File: filepath.Join(dir, "policy.json"), Dir: filepath.Join(dir, "rules"),
		Test: []string{"nginx", "-t"}, Reload: []string{"reload"}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Run: func(_ context.Context, name string, _ ...string) ([]byte, error) {
			calls++
			if name == "nginx" && calls > 2 {
				return []byte("nginx: [emerg] bad\nnginx: configuration file test failed"), errors.New("exit 1")
			}
			return nil, nil
		}}
	m.Load()
	if err := m.Update(context.Background(), func(s *State) error { s.Deny = []string{"203.0.113.1"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("want test and reload, got %d calls", calls)
	}
	err := m.Update(context.Background(), func(s *State) error { s.Deny = []string{"203.0.113.2"}; return nil })
	if err == nil || !strings.Contains(err.Error(), "configuration file test failed") {
		t.Fatalf("want nginx error, got %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "rules", "deny.txt"))
	if string(b) != "203.0.113.1\n" {
		t.Fatalf("deny.txt not restored: %q", b)
	}
	if got := m.State().Deny; len(got) != 1 || got[0] != "203.0.113.1" {
		t.Fatalf("state changed after a failed test: %v", got)
	}
	// Unchanged files: no nginx -t, no reload.
	calls = 0
	m.Update(context.Background(), func(s *State) error { return nil })
	if calls != 0 {
		t.Fatalf("unchanged policy ran %d commands", calls)
	}
}

func TestCheckInclude(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{Dir: filepath.Join(dir, "rules")}
	os.MkdirAll(m.Dir, 0o755)
	for _, n := range []string{"before.conf", "after.conf", "allow.txt", "deny.txt"} {
		os.WriteFile(filepath.Join(m.Dir, n), nil, 0o644)
	}
	inc := filepath.Join(dir, "crs.conf")
	good := "# comment\nmodsecurity_rules_file " + m.Dir + "/before.conf;\nmodsecurity_rules_file /etc/modsecurity/admin/main.conf;\nmodsecurity_rules_file " + m.Dir + "/after.conf;\n"
	os.WriteFile(inc, []byte(good), 0o644)
	if p := m.CheckInclude(inc); p != nil {
		t.Fatalf("good include: %v", p)
	}
	// An update put the file back to CRS only.
	os.WriteFile(inc, []byte("modsecurity_rules_file /etc/modsecurity/admin/main.conf;\n"), 0o644)
	if p := m.CheckInclude(inc); len(p) != 2 {
		t.Fatalf("want 2 problems, got %v", p)
	}
	os.Remove(filepath.Join(m.Dir, "deny.txt"))
	os.Remove(inc)
	if p := m.CheckInclude(inc); len(p) != 2 {
		t.Fatalf("missing file and include: %v", p)
	}
}

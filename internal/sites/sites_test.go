package sites

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vhost(t *testing.T, dir, owner, site, body string) {
	t.Helper()
	os.MkdirAll(filepath.Join(dir, owner), 0o755)
	if err := os.WriteFile(filepath.Join(dir, owner, site+".conf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAccessLogAndSwitch(t *testing.T) {
	dir := t.TempDir()
	vhost(t, dir, "a", "on.example", "server {\n\tserver_name on.example;\n\tlocation ~* \\.(jpg)$ {\n\t\taccess_log off;\n\t}\n\taccess_log /var/www/httpd-logs/on.example.access.log;\n}\n")
	vhost(t, dir, "b", "off.example", "server {\n\tserver_name off.example;\n\tlocation / {\n\t\taccess_log off;\n\t}\n\taccess_log off;\n}\n")
	r := &Reader{VhostsDir: dir, ResourcesDir: filepath.Join(dir, "none")}
	got := map[string]bool{}
	for _, s := range r.Sites() {
		got[s.Name] = s.AccessLog
	}
	if !got["on.example"] || got["off.example"] {
		t.Fatalf("access logs: %v", got)
	}

	var calls []string
	l := &LogSwitch{Mgrctl: "mgrctl", Sites: r, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return []byte("OK\n"), nil
	}}
	if err := l.Set(context.Background(), "off.example", true); err != nil {
		t.Fatal(err)
	}
	if want := "mgrctl -m ispmgr webdomain.edit elid=off.example log_access=on sok=ok"; len(calls) != 1 || calls[0] != want {
		t.Fatalf("calls %q, want %q", calls, want)
	}
	if err := l.Set(context.Background(), "evil.example sok=ok", false); err == nil || len(calls) != 1 {
		t.Fatalf("an unknown site must not reach mgrctl: %v %q", err, calls)
	}
	l.Run = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ERROR value(log_access)\n"), nil
	}
	if err := l.Set(context.Background(), "on.example", false); err == nil {
		t.Fatal("an ERROR from mgrctl must fail")
	}
}

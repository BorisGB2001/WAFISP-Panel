package web

import (
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wafisp/internal/policy"
)

func TestTrustedSource(t *testing.T) {
	_, s, _ := newTestServer(t)
	s.Blocks.Protected = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	s.Policy.Update(t.Context(), func(st *policy.State) error {
		st.Allow = append(st.Allow,
			policy.Addr{IP: "198.51.100.10"},
			policy.Addr{IP: "198.51.100.20", Meta: policy.Meta{Expires: time.Now().Add(-time.Hour)}})
		return nil
	})
	for ip, want := range map[string]bool{
		"127.0.0.1":     true,
		"10.6.1.2":      true,
		"192.168.0.5":   true,
		"::1":           true,
		"192.0.2.7":     true,  // block.protected
		"198.51.100.10": true,  // allow list
		"198.51.100.20": false, // expired allow entry
		"203.0.113.9":   false,
		"garbage":       false,
	} {
		if got := s.trustedSource(ip); got != want {
			t.Errorf("trustedSource(%s) = %v, want %v", ip, got, want)
		}
	}
}

// Failed logins from a trusted source (the test client is on loopback)
// never lock the user out.
func TestLoginNoLockoutFromTrusted(t *testing.T) {
	ts, s, _ := newTestServer(t)
	c := browser(ts)
	for range 10 {
		resp, err := c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"wrong"}})
		if err != nil {
			t.Fatal(err)
		}
		if b := body(t, resp); strings.Contains(b, "Too many failed attempts") {
			t.Fatal("trusted source was locked out")
		}
	}
	pw, _ := os.ReadFile(filepath.Join(s.Cfg.Web.DataDir, "initial-admin-password"))
	login(t, ts, c, "admin", strings.TrimSpace(string(pw)))
	if code, _ := get(t, ts, c, "/audit"); code != http.StatusOK {
		t.Fatalf("audit: %d", code)
	}
}

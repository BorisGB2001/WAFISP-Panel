package update

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.3.6", "0.3.5", true}, {"0.4.0", "0.3.9", true}, {"1.0.0", "0.9.9", true}, {"0.3.10", "0.3.9", true},
		{"0.3.5", "0.3.5", false}, {"0.3.4", "0.3.5", false}, {"0.4.0", "0.3.5-dev", false}, {"0.4.0", "dev", false}, {"x", "0.3.5", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig := Sign(priv, []byte("binary"))
	if err := Verify(pub, []byte("binary"), sig); err != nil {
		t.Fatal(err)
	}
	if Verify(pub, []byte("binarY"), sig) == nil {
		t.Fatal("a changed binary passed")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if Verify(other, []byte("binary"), sig) == nil {
		t.Fatal("another key passed")
	}
}

// fakeGitHub serves a latest release with a binary and its signature.
func fakeGitHub(t *testing.T, version string, bin, sig []byte) *httptest.Server {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v%s","body":"notes","html_url":"%s/rel","published_at":"2026-11-03T00:00:00Z",
				"assets":[{"name":"%s","browser_download_url":"%s/bin"},{"name":"%s.sig","browser_download_url":"%s/sig"}]}`,
				version, ts.URL, Asset, ts.URL, Asset, ts.URL)
		case "/bin":
			w.Write(bin)
		case "/sig":
			w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestCheckStageInstall(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	bin := []byte("new binary")
	dir := t.TempDir()
	var calls []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) == 1 && args[0] == "-version" {
			return []byte("0.4.0\n"), nil
		}
		return nil, nil
	}
	u := &Updater{Repo: "o/r", Current: "0.3.5", Dir: dir, ConfigPath: "/etc/wafisp/wafisp.yaml", Exe: "/usr/local/bin/wafisp",
		PublicKey: pub, HTTP: http.DefaultClient, Run: run}

	u.API = fakeGitHub(t, "0.4.0", bin, Sign(priv, bin)).URL
	if _, err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := u.State(); !st.Available || st.Latest.Version != "0.4.0" || st.Latest.Notes != "notes" {
		t.Fatalf("state %+v", st)
	}
	v, err := u.Install(context.Background())
	if err != nil || v != "0.4.0" {
		t.Fatal(v, err)
	}
	staged := filepath.Join(dir, "wafisp-0.4.0")
	if b, _ := os.ReadFile(staged); string(b) != "new binary" {
		t.Fatal("not staged")
	}
	want := []string{staged + " -version", staged + " -config /etc/wafisp/wafisp.yaml -check"}
	if len(calls) != 3 || calls[0] != want[0] || calls[1] != want[1] ||
		!strings.HasPrefix(calls[2], "systemd-run --unit=wafisp-update-") || !strings.HasSuffix(calls[2], "/usr/local/bin/wafisp -config /etc/wafisp/wafisp.yaml -apply-update "+staged) {
		t.Fatalf("calls %q", calls)
	}
	if s := ReadStatus(dir); s == nil || s.State != "installing" {
		t.Fatalf("status %+v", s)
	}

	// A binary signed with another key is refused before anything runs.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	u.API = fakeGitHub(t, "0.4.1", bin, Sign(otherPriv, bin)).URL
	u.Check(context.Background())
	calls = nil
	if _, err := u.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "signature") || len(calls) != 0 {
		t.Fatalf("a badly signed release: %v, calls %q", err, calls)
	}
	// Nothing newer: nothing to do.
	u.Current = "0.4.1"
	if _, err := u.Install(context.Background()); err == nil {
		t.Fatal("installed a release that is not newer")
	}
}

func TestInstaller(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var healthy atomic.Bool
	hz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer hz.Close()
	setup := func() (*Installer, string, *[]string) {
		dir := t.TempDir()
		exe := filepath.Join(dir, "wafisp")
		os.WriteFile(exe, []byte("old"), 0o755)
		staged := filepath.Join(dir, "update", "wafisp-0.4.0")
		os.MkdirAll(filepath.Dir(staged), 0o700)
		os.WriteFile(staged, []byte("new"), 0o700)
		os.WriteFile(staged+".sig", Sign(priv, []byte("new")), 0o600)
		var calls []string
		in := &Installer{Exe: exe, Dir: filepath.Join(dir, "update"), Service: "wafisp", Healthz: hz.URL, PublicKey: pub, From: "0.3.5",
			HTTP: http.DefaultClient, Wait: 300 * time.Millisecond, Every: 10 * time.Millisecond,
			Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
				calls = append(calls, name+" "+strings.Join(args, " "))
				switch {
				case name == "systemctl" && args[0] == "is-active":
					return []byte("active\n"), nil
				case len(args) == 1 && args[0] == "-version":
					b, _ := os.ReadFile(name)
					return map[string][]byte{"new": []byte("0.4.0"), "old": []byte("0.3.5")}[string(b)], nil
				}
				return nil, nil
			}}
		return in, staged, &calls
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }

	// The new version comes up: it stays, the old one is kept as .prev.
	healthy.Store(true)
	in, staged, _ := setup()
	if err := in.Install(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	if read(in.Exe) != "new" || read(in.Exe+".prev") != "old" {
		t.Fatalf("exe %q prev %q", read(in.Exe), read(in.Exe+".prev"))
	}
	if s := ReadStatus(in.Dir); s.State != "ok" || s.To != "0.4.0" || s.From != "0.3.5" {
		t.Fatalf("status %+v", s)
	}
	// Rolling back swaps them.
	if err := in.Rollback(context.Background()); err != nil || read(in.Exe) != "old" || read(in.Exe+".prev") != "new" {
		t.Fatalf("rollback: %v, exe %q", err, read(in.Exe))
	}

	// The new version never answers: the old one is put back.
	healthy.Store(false)
	in, staged, calls := setup()
	if err := in.Install(context.Background(), staged); err == nil {
		t.Fatal("a version that does not come up was kept")
	}
	if read(in.Exe) != "old" {
		t.Fatalf("not rolled back: %q", read(in.Exe))
	}
	if s := ReadStatus(in.Dir); s.State != "failed" && s.State != "rolled_back" {
		t.Fatalf("status %+v", s)
	}
	restarts := 0
	for _, c := range *calls {
		if c == "systemctl restart wafisp" {
			restarts++
		}
	}
	if restarts != 2 {
		t.Fatalf("%d restarts, want the update and the rollback", restarts)
	}

	// A staged file that is not what was signed is not installed.
	healthy.Store(true)
	in, staged, _ = setup()
	os.WriteFile(staged, []byte("evil"), 0o700)
	if err := in.Install(context.Background(), staged); err == nil || read(in.Exe) != "old" {
		t.Fatal("installed a binary with a wrong signature")
	}
}

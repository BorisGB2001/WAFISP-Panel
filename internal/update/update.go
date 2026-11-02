// Package update finds a newer release on GitHub and installs it: the
// panel downloads the binary, checks its ed25519 signature, the version
// and that it accepts the current config, then hands the swap to a
// one-shot systemd unit outside the panel's sandbox (the service cannot
// write /usr/local/bin). That unit runs the old, known-good binary with
// -apply-update: it keeps the old binary as <exe>.prev, restarts the
// service and puts the old one back if the new one does not come up.
package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultRepo is where releases are published.
const DefaultRepo = "BorisGB2001/WAFISP-Panel"

// Asset is the release file the panel installs; Asset+".sig" is its
// signature.
const Asset = "wafisp-linux-amd64"

const maxBinary = 64 << 20

// Release is the latest release on GitHub.
type Release struct {
	Version   string // without the leading "v"
	Notes     string
	URL       string // the release page
	Published time.Time
	BinURL    string
	SigURL    string
}

// Status is the outcome of the last install or rollback, written by the
// installer to <Dir>/status.json.
type Status struct {
	State   string    `json:"state"` // installing | ok | rolled_back | failed
	From    string    `json:"from,omitempty"`
	To      string    `json:"to,omitempty"`
	Message string    `json:"message,omitempty"`
	At      time.Time `json:"at"`
}

// State is what the panel shows.
type State struct {
	Current   string
	Latest    *Release
	Available bool // Latest is newer than Current
	Checked   time.Time
	CheckErr  string
	Status    *Status
	HasPrev   bool
	Busy      bool
}

// Runner runs a command; tests replace it.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func execRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Updater checks for and stages releases inside the panel.
type Updater struct {
	Repo       string
	Current    string
	Dir        string // staging dir and status.json, under the data dir
	ConfigPath string
	Exe        string // the installed binary, e.g. /usr/local/bin/wafisp
	PublicKey  ed25519.PublicKey
	HTTP       *http.Client
	API        string // https://api.github.com unless a test sets it
	Run        Runner
	Log        *slog.Logger

	mu       sync.Mutex
	latest   *Release
	checked  time.Time
	checkErr string
	busy     bool
}

func (u *Updater) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if u.Run != nil {
		return u.Run(ctx, name, args...)
	}
	return execRun(ctx, name, args...)
}

// Loop checks now and then every interval.
func (u *Updater) Loop(ctx context.Context, every time.Duration) {
	for {
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		if _, err := u.Check(cctx); err != nil && u.Log != nil {
			u.Log.Warn("update: check", "err", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// Check asks GitHub for the latest release.
func (u *Updater) Check(ctx context.Context) (*Release, error) {
	rel, err := u.fetchLatest(ctx)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.checked = time.Now()
	if err != nil {
		u.checkErr = err.Error()
		return nil, err
	}
	u.latest, u.checkErr = rel, ""
	return rel, nil
}

func (u *Updater) fetchLatest(ctx context.Context) (*Release, error) {
	api := u.API
	if api == "" {
		api = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+"/repos/"+u.Repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := u.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %s", resp.Status)
	}
	var gh struct {
		Tag       string    `json:"tag_name"`
		Body      string    `json:"body"`
		URL       string    `json:"html_url"`
		Published time.Time `json:"published_at"`
		Assets    []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&gh); err != nil {
		return nil, fmt.Errorf("GitHub release: %w", err)
	}
	rel := &Release{Version: strings.TrimPrefix(gh.Tag, "v"), Notes: gh.Body, URL: gh.URL, Published: gh.Published}
	if _, ok := parseVersion(rel.Version); !ok {
		return nil, fmt.Errorf("latest release %q is not a version", gh.Tag)
	}
	for _, a := range gh.Assets {
		switch a.Name {
		case Asset:
			rel.BinURL = a.URL
		case Asset + ".sig":
			rel.SigURL = a.URL
		}
	}
	return rel, nil
}

// State is the current picture for the panel.
func (u *Updater) State() State {
	u.mu.Lock()
	st := State{Current: u.Current, Latest: u.latest, Checked: u.checked, CheckErr: u.checkErr, Busy: u.busy}
	u.mu.Unlock()
	st.Available = st.Latest != nil && Newer(st.Latest.Version, u.Current)
	st.Status = ReadStatus(u.Dir)
	if _, err := os.Stat(u.Exe + ".prev"); err == nil {
		st.HasPrev = true
	}
	return st
}

// Install stages the latest release and starts the installer. It returns
// once the installer runs; the service restarts a moment later.
func (u *Updater) Install(ctx context.Context) (string, error) {
	u.mu.Lock()
	rel := u.latest
	if u.busy {
		u.mu.Unlock()
		return "", errors.New("an update is already running")
	}
	u.busy = true
	u.mu.Unlock()
	defer func() { u.mu.Lock(); u.busy = false; u.mu.Unlock() }()
	switch {
	case rel == nil:
		return "", errors.New("no release known yet: check first")
	case !Newer(rel.Version, u.Current):
		return "", fmt.Errorf("%s is not newer than %s", rel.Version, u.Current)
	case rel.BinURL == "" || rel.SigURL == "":
		return "", fmt.Errorf("release %s has no signed %s", rel.Version, Asset)
	}
	path, err := u.Stage(ctx, rel)
	if err != nil {
		return "", err
	}
	if err := u.launch(ctx, "-apply-update", path); err != nil {
		return "", err
	}
	return rel.Version, nil
}

// Rollback starts the installer to put <exe>.prev back.
func (u *Updater) Rollback(ctx context.Context) error {
	if _, err := os.Stat(u.Exe + ".prev"); err != nil {
		return errors.New("no previous version kept")
	}
	return u.launch(ctx, "-rollback")
}

func (u *Updater) launch(ctx context.Context, args ...string) error {
	writeStatus(u.Dir, Status{State: "installing", From: u.Current, At: time.Now()})
	unit := fmt.Sprintf("wafisp-update-%d", time.Now().Unix())
	full := append([]string{"--unit=" + unit, "--collect", "--quiet", u.Exe, "-config", u.ConfigPath}, args...)
	if out, err := u.run(ctx, "systemd-run", full...); err != nil {
		writeStatus(u.Dir, Status{State: "failed", From: u.Current, Message: "systemd-run: " + strings.TrimSpace(string(out)) + " " + err.Error(), At: time.Now()})
		return fmt.Errorf("systemd-run: %v %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// Stage downloads and checks a release: signature, version, config.
func (u *Updater) Stage(ctx context.Context, rel *Release) (string, error) {
	if err := os.MkdirAll(u.Dir, 0o700); err != nil {
		return "", err
	}
	bin, err := u.get(ctx, rel.BinURL, maxBinary)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	sig, err := u.get(ctx, rel.SigURL, 4096)
	if err != nil {
		return "", fmt.Errorf("download signature: %w", err)
	}
	if err := Verify(u.PublicKey, bin, sig); err != nil {
		return "", err
	}
	path := filepath.Join(u.Dir, "wafisp-"+rel.Version)
	if err := os.WriteFile(path, bin, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path+".sig", sig, 0o600); err != nil {
		return "", err
	}
	out, err := u.run(ctx, path, "-version")
	if v := strings.TrimSpace(string(out)); err != nil || v != rel.Version {
		os.Remove(path)
		return "", fmt.Errorf("the downloaded binary says it is %q, not %s (%v)", v, rel.Version, err)
	}
	if out, err := u.run(ctx, path, "-config", u.ConfigPath, "-check"); err != nil {
		os.Remove(path)
		return "", fmt.Errorf("version %s refuses the current config: %s", rel.Version, lastLines(string(out), 3))
	}
	return path, nil
}

func (u *Updater) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("%s is larger than %d bytes", url, limit)
	}
	return b, err
}

// ---------- signatures ----------

// Sign returns the signature file for data: base64 and a newline.
func Sign(priv ed25519.PrivateKey, data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)) + "\n")
}

// Verify checks a signature file made by Sign.
func Verify(pub ed25519.PublicKey, data, sigFile []byte) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigFile)))
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, data, sig) {
		return errors.New("the release signature does not match: not installing it")
	}
	return nil
}

// ParsePublicKey reads a base64 ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not an ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey reads a key file written by -genkey.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("not an ed25519 private key")
	}
	return ed25519.PrivateKey(b), nil
}

// ---------- versions ----------

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Newer tells whether release version a is newer than the running b. A
// development build ("0.3.5-dev", "dev") is never updated.
func Newer(a, b string) bool {
	x, ok1 := parseVersion(a)
	y, ok2 := parseVersion(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := range 3 {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return false
}

// ---------- status ----------

// ReadStatus reads <dir>/status.json, nil when there is none.
func ReadStatus(dir string) *Status {
	b, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		return nil
	}
	var s Status
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	return &s
}

func writeStatus(dir string, s Status) {
	os.MkdirAll(dir, 0o700)
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := filepath.Join(dir, "status.json.tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, filepath.Join(dir, "status.json"))
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " / ")
}

package share

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"wafisp/internal/block"

	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type memBackend struct{ ips []string }

func (b *memBackend) Name() string                 { return "ipset" }
func (b *memBackend) Ensure(context.Context) error { return nil }
func (b *memBackend) Sync(_ context.Context, ips []string) error {
	b.ips = slices.Clone(ips)
	return nil
}
func (b *memBackend) List(context.Context) ([]string, error) { return b.ips, nil }

type memStore struct {
	mu    sync.Mutex
	files map[string][]byte
}

func (m *memStore) Get(_ context.Context, s string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.files[s]; ok {
		return b, nil
	}
	return nil, ErrNotFound
}

func (m *memStore) Put(_ context.Context, s string, b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[s] = b
	return nil
}

type server struct {
	s       *Syncer
	m       *block.Manager
	be      *memBackend
	pub     ed25519.PublicKey
	allowed []string
}

func newServer(t *testing.T, name string, store Store, protected ...string) *server {
	pub, priv, _ := ed25519.GenerateKey(nil)
	be := &memBackend{}
	var prot []netip.Prefix
	for _, p := range protected {
		prot = append(prot, netip.MustParsePrefix(p))
	}
	dir := t.TempDir()
	m := &block.Manager{File: filepath.Join(dir, "blocks.json"), Backends: []block.Backend{be}, Protected: prot,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv := &server{m: m, be: be, pub: pub}
	srv.s = &Syncer{Name: name, Key: priv, Peers: map[string]ed25519.PublicKey{}, Store: store, Blocks: m, Backends: []string{"ipset"},
		Apply: true, StateFile: filepath.Join(dir, "share.json"), Allowed: func(ip string) bool { return slices.Contains(srv.allowed, ip) }}
	return srv
}

func trust(a, b *server) {
	a.s.Peers[b.s.Name] = b.pub
	b.s.Peers[a.s.Name] = a.pub
}

func ban(t *testing.T, srv *server, ip string, d time.Duration) {
	e := block.Entry{IP: ip, Backends: []string{"ipset"}, By: "autoban", Via: "trap", Reason: "trap 17: GET /.env", At: time.Now()}
	if d > 0 {
		e.Expires = e.At.Add(d)
	}
	if err := srv.m.Block(context.Background(), e); err != nil {
		t.Fatal(err)
	}
}

func ips(m *block.Manager) []string {
	var out []string
	for _, e := range m.Entries() {
		out = append(out, e.IP)
	}
	slices.Sort(out)
	return out
}

func TestShareFollowsThePeer(t *testing.T) {
	ctx := context.Background()
	store := &memStore{files: map[string][]byte{}}
	a := newServer(t, "nominis", store)
	b := newServer(t, "crcp", store, "198.51.100.0/24")
	trust(a, b)

	ban(t, a, "203.0.113.5", 24*time.Hour)
	ban(t, a, "198.51.100.9", 0) // protected on b
	a.s.Once(ctx)
	b.s.Once(ctx)
	if got := ips(b.m); !slices.Equal(got, []string{"203.0.113.5"}) {
		t.Fatalf("b blocks %v", got)
	}
	e, _ := b.m.Lookup("203.0.113.5")
	if e.Peer != "nominis" || !strings.Contains(e.Reason, "from nominis: trap 17") || e.Expires.IsZero() {
		t.Fatalf("entry %+v", e)
	}
	_, peers := b.s.Statuses()
	if peers[0].Applied != 1 || peers[0].Skipped["protected"] != 1 || peers[0].Err != "" {
		t.Fatalf("status %+v", peers[0])
	}
	// b does not publish what it got from a: no loops.
	b.s.Once(ctx)
	a.s.Once(ctx)
	if got := ips(a.m); len(got) != 2 {
		t.Fatalf("a got its own blocks back: %v", got)
	}

	// A new term follows; an unblock there unblocks here.
	a.m.SetExpiry("203.0.113.5", time.Time{})
	a.s.Once(ctx)
	b.s.Once(ctx)
	if e, _ := b.m.Lookup("203.0.113.5"); !e.Expires.IsZero() {
		t.Fatalf("term not followed: %+v", e)
	}
	// A term changed here by hand stands while the peer keeps its own.
	short := time.Now().Add(time.Hour).Truncate(time.Second)
	b.m.SetExpiry("203.0.113.5", short)
	a.s.Once(ctx)
	b.s.Once(ctx)
	if e, _ := b.m.Lookup("203.0.113.5"); !e.Expires.Equal(short) {
		t.Fatalf("the term set here was overwritten: %+v", e)
	}
	a.m.Unblock(ctx, "203.0.113.5")
	a.s.Once(ctx)
	b.s.Once(ctx)
	if got := ips(b.m); len(got) != 0 {
		t.Fatalf("still blocked on b: %v", got)
	}
}

func TestShareRespectsThisServer(t *testing.T) {
	ctx := context.Background()
	store := &memStore{files: map[string][]byte{}}
	a := newServer(t, "nominis", store)
	b := newServer(t, "crcp", store)
	trust(a, b)
	b.allowed = []string{"203.0.113.7"}
	ban(t, a, "203.0.113.6", 0)
	ban(t, a, "203.0.113.7", 0)
	ban(t, b, "203.0.113.8", time.Hour) // b's own block of the same address
	ban(t, a, "203.0.113.8", 0)
	a.s.Once(ctx)
	b.s.Once(ctx)
	if got := ips(b.m); !slices.Equal(got, []string{"203.0.113.6", "203.0.113.8"}) {
		t.Fatalf("b blocks %v", got)
	}
	if e, _ := b.m.Lookup("203.0.113.8"); e.Peer != "" {
		t.Fatal("a peer's block replaced b's own")
	}
	// Unblocked on b by hand: it stays unblocked while a keeps it...
	b.m.Unblock(ctx, "203.0.113.6")
	b.s.Once(ctx)
	b.s.Once(ctx)
	if _, ok := b.m.Lookup("203.0.113.6"); ok {
		t.Fatal("blocked again after an unblock by hand")
	}
	// ...and comes back when a blocks it anew.
	a.m.Unblock(ctx, "203.0.113.6")
	time.Sleep(time.Millisecond)
	ban(t, a, "203.0.113.6", 0)
	a.s.Once(ctx)
	b.s.Once(ctx)
	if _, ok := b.m.Lookup("203.0.113.6"); !ok {
		t.Fatal("a new block was not applied")
	}
}

func TestShareDryRunAndTrust(t *testing.T) {
	ctx := context.Background()
	store := &memStore{files: map[string][]byte{}}
	a := newServer(t, "nominis", store)
	b := newServer(t, "crcp", store)
	trust(a, b)
	b.s.Apply = false
	ban(t, a, "203.0.113.9", 0)
	a.s.Once(ctx)
	b.s.Once(ctx)
	_, peers := b.s.Statuses()
	if len(ips(b.m)) != 0 || peers[0].Would != 1 {
		t.Fatalf("dry run blocked %v, status %+v", ips(b.m), peers[0])
	}

	// A list signed with another key is refused.
	b.s.Apply = true
	mallory, _, _ := ed25519.GenerateKey(nil)
	b.s.Peers["nominis"] = mallory
	b.s.Once(ctx)
	_, peers = b.s.Statuses()
	if len(ips(b.m)) != 0 || !strings.Contains(peers[0].Err, "signature") {
		t.Fatalf("forged list: %v, %+v", ips(b.m), peers[0])
	}

	// An old copy of a list is refused once a newer one was applied.
	b.s.Peers["nominis"] = a.pub
	old := store.files["nominis"]
	time.Sleep(time.Millisecond)
	a.m.Unblock(ctx, "203.0.113.9")
	a.s.publish(ctx)
	b.s.Once(ctx)
	store.files["nominis"] = old
	b.s.Once(ctx)
	_, peers = b.s.Statuses()
	if len(ips(b.m)) != 0 || !strings.Contains(peers[0].Err, "older list") {
		t.Fatalf("replay: %v, %+v", ips(b.m), peers[0])
	}

	// A server taken off the peers loses its blocks here.
	ban(t, a, "203.0.113.10", 0)
	a.s.Once(ctx)
	b.s.Once(ctx)
	if len(ips(b.m)) != 1 {
		t.Fatalf("not applied: %v", ips(b.m))
	}
	delete(b.s.Peers, "nominis")
	b.s.dropUnknownPeers(ctx)
	if len(ips(b.m)) != 0 {
		t.Fatalf("blocks of a removed peer stay: %v", ips(b.m))
	}
}

func TestSealKeepsTheBytes(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	l := List{Server: "a", At: time.Now().UTC(), Items: []Item{{IP: "203.0.113.1", Reason: `<script> & "quotes"`}}}
	data, _ := Seal(priv, l)
	got, err := Unseal(data, "a", pub)
	if err != nil || got.Items[0].Reason != l.Items[0].Reason {
		t.Fatal(got, err)
	}
	if _, err := Unseal(data, "b", pub); err == nil {
		t.Fatal("a list of another server was accepted under this name")
	}
}

func TestGitHubStore(t *testing.T) {
	var mu sync.Mutex
	files := map[string]string{} // path -> base64
	shas := map[string]string{}
	n := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok" || !strings.HasPrefix(r.URL.Path, "/repos/o/r/contents/blocks/") {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/repos/o/r/contents/")
		switch r.Method {
		case http.MethodGet:
			c, ok := files[p]
			if !ok {
				http.NotFound(w, r)
				return
			}
			if r.Header.Get("If-None-Match") == `"`+shas[p]+`"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"`+shas[p]+`"`)
			json.NewEncoder(w).Encode(map[string]string{"sha": shas[p], "content": c[:4] + "\n" + c[4:], "encoding": "base64"})
		case http.MethodPut:
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if _, ok := files[p]; ok && body["sha"] != shas[p] {
				http.Error(w, "sha", http.StatusConflict)
				return
			}
			n++
			files[p], shas[p] = body["content"], strings.Repeat("s", n)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"content": map[string]string{"sha": shas[p]}})
		}
	}))
	defer ts.Close()
	g := &GitHub{API: ts.URL, Repo: "o/r", Token: "tok", HTTP: ts.Client()}
	other := &GitHub{API: ts.URL, Repo: "o/r", Token: "tok", HTTP: ts.Client()}
	ctx := context.Background()
	if _, err := g.Get(ctx, "a"); err != ErrNotFound {
		t.Fatal(err)
	}
	if err := g.Put(ctx, "a", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if b, err := other.Get(ctx, "a"); err != nil || string(b) != "one" {
		t.Fatal(string(b), err)
	}
	if b, err := other.Get(ctx, "a"); err != nil || string(b) != "one" { // 304 from the cache
		t.Fatal(string(b), err)
	}
	// Written elsewhere meanwhile: the stale sha is refused and read again.
	if err := other.Put(ctx, "a", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if err := g.Put(ctx, "a", []byte("three")); err != nil {
		t.Fatal(err)
	}
	if b, _ := other.Get(ctx, "a"); string(b) != "three" {
		t.Fatalf("got %q", b)
	}
	if got, _ := base64.StdEncoding.DecodeString(files["blocks/a.json"]); string(got) != "three" {
		t.Fatal(string(got))
	}
}

func TestGitStore(t *testing.T) {
	ctx := context.Background()
	// A bare repository with a first commit, as GitHub makes with a README.
	dir := t.TempDir()
	bare := filepath.Join(dir, "share.git")
	seed := filepath.Join(dir, "seed")
	if _, err := git.PlainInit(bare, true); err != nil {
		t.Fatal(err)
	}
	r, _ := git.PlainInit(seed, false)
	os.WriteFile(filepath.Join(seed, "README.md"), []byte("blocks\n"), 0o644)
	wt, _ := r.Worktree()
	wt.Add("README.md")
	sig := &object.Signature{Name: "t", Email: "t@t", When: time.Now()}
	wt.Commit("first", &git.CommitOptions{Author: sig})
	head, _ := r.Head()
	r.Storer.SetReference(plumbing.NewHashReference("refs/heads/main", head.Hash()))
	r.CreateRemote(&gitconfig.RemoteConfig{Name: "origin", URLs: []string{bare}})
	if err := r.Push(&git.PushOptions{RefSpecs: []gitconfig.RefSpec{"refs/heads/main:refs/heads/main"}}); err != nil {
		t.Fatal(err)
	}

	a := &Git{URL: bare, Dir: filepath.Join(dir, "a"), Name: "a"}
	b := &Git{URL: bare, Dir: filepath.Join(dir, "b"), Name: "b"}
	if _, err := b.Get(ctx, "a"); err != ErrNotFound {
		t.Fatal(err)
	}
	if err := a.Put(ctx, "a", []byte("one")); err != nil {
		t.Fatal(err)
	}
	// b has an old clone: its push is refused, it fetches and pushes again.
	if err := b.Put(ctx, "b", []byte("two")); err != nil {
		t.Fatal(err)
	}
	b.fetched = time.Time{}
	if got, err := b.Get(ctx, "a"); err != nil || string(got) != "one" {
		t.Fatal(string(got), err)
	}
	a.fetched = time.Time{}
	if got, err := a.Get(ctx, "b"); err != nil || string(got) != "two" {
		t.Fatal(string(got), err)
	}
	if err := a.Put(ctx, "a", []byte("three")); err != nil {
		t.Fatal(err)
	}
	b.fetched = time.Time{}
	if got, _ := b.Get(ctx, "a"); string(got) != "three" {
		t.Fatalf("got %q", got)
	}
}

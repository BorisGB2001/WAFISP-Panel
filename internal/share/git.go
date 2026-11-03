package share

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"golang.org/x/crypto/ssh"
)

// GitHubHostKey is github.com's SSH host key, as GitHub publishes it
// (api.github.com/meta). Pinned, so nobody on the way can pose as GitHub.
const GitHubHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

// Git keeps the lists in a repository reached over SSH with a deploy key:
// a key of this server that can write to that one repository and nothing
// else, so no account token lives on the server. The repository is cloned
// into Dir and fetched before reading; git itself is not needed on the
// host.
type Git struct {
	URL     string // git@github.com:owner/name.git
	Branch  string // main by default
	Key     []byte // the deploy key, OpenSSH private key; nil for a local path (tests)
	HostKey string // authorized_keys line of the server; GitHubHostKey by default
	Dir     string
	Name    string // this server, for the commits

	mu      sync.Mutex
	repo    *git.Repository
	fetched time.Time
	auth    transport.AuthMethod
}

// sshAuth is a deploy key with a pinned host key.
type sshAuth struct {
	signer ssh.Signer
	host   ssh.PublicKey
}

func (a *sshAuth) Name() string   { return "ssh-deploy-key" }
func (a *sshAuth) String() string { return "deploy key " + ssh.FingerprintSHA256(a.signer.PublicKey()) }
func (a *sshAuth) ClientConfig() (*ssh.ClientConfig, error) {
	return &ssh.ClientConfig{User: "git", Auth: []ssh.AuthMethod{ssh.PublicKeys(a.signer)}, Timeout: 30 * time.Second,
		HostKeyAlgorithms: []string{a.host.Type()},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !keysEqual(key, a.host) {
				return fmt.Errorf("the server's SSH key %s is not the pinned key of the repository host", ssh.FingerprintSHA256(key))
			}
			return nil
		}}, nil
}

func keysEqual(a, b ssh.PublicKey) bool { return string(a.Marshal()) == string(b.Marshal()) }

func (g *Git) branch() string {
	if g.Branch == "" {
		return "main"
	}
	return g.Branch
}

// open clones the repository the first time. Callers hold mu.
func (g *Git) open(ctx context.Context) error {
	if g.auth == nil && g.Key != nil {
		signer, err := ssh.ParsePrivateKey(g.Key)
		if err != nil {
			return fmt.Errorf("deploy key: %w", err)
		}
		hk := g.HostKey
		if hk == "" {
			hk = GitHubHostKey
		}
		host, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk))
		if err != nil {
			return fmt.Errorf("host key: %w", err)
		}
		g.auth = &sshAuth{signer: signer, host: host}
	}
	if g.repo != nil {
		return nil
	}
	repo, err := git.PlainOpen(g.Dir)
	if err == nil {
		g.repo = repo
		return nil
	}
	os.RemoveAll(g.Dir)
	repo, err = git.PlainCloneContext(ctx, g.Dir, false, &git.CloneOptions{URL: g.URL, Auth: g.auth,
		ReferenceName: plumbing.NewBranchReferenceName(g.branch()), SingleBranch: true})
	if err != nil {
		os.RemoveAll(g.Dir)
		return fmt.Errorf("clone %s: %w", g.URL, err)
	}
	g.repo, g.fetched = repo, time.Now()
	return nil
}

// refresh fetches the branch and puts the work tree on it, at most every
// few seconds unless forced. Callers hold mu.
func (g *Git) refresh(ctx context.Context, force bool) error {
	if !force && time.Since(g.fetched) < 5*time.Second {
		return nil
	}
	b := g.branch()
	err := g.repo.FetchContext(ctx, &git.FetchOptions{RemoteName: "origin", Auth: g.auth, Force: true,
		RefSpecs: []gitconfig.RefSpec{gitconfig.RefSpec("+refs/heads/" + b + ":refs/remotes/origin/" + b)}})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("fetch: %w", err)
	}
	ref, err := g.repo.Reference(plumbing.NewRemoteReferenceName("origin", b), true)
	if err != nil {
		return err
	}
	wt, err := g.repo.Worktree()
	if err != nil {
		return err
	}
	if err := wt.Reset(&git.ResetOptions{Commit: ref.Hash(), Mode: git.HardReset}); err != nil {
		return err
	}
	g.fetched = time.Now()
	return nil
}

func (g *Git) file(server string) string { return filepath.Join(g.Dir, "blocks", server+".json") }

// Get returns the file of server.
func (g *Git) Get(ctx context.Context, server string) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.open(ctx); err != nil {
		return nil, err
	}
	if err := g.refresh(ctx, false); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(g.file(server))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return b, err
}

// Put commits the file of server and pushes it; when another server pushed
// meanwhile, it fetches and tries again.
func (g *Git) Put(ctx context.Context, server string, data []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.open(ctx); err != nil {
		return err
	}
	var err error
	for try := 0; try < 3; try++ {
		if err = g.refresh(ctx, true); err != nil {
			return err
		}
		if old, rerr := os.ReadFile(g.file(server)); rerr == nil && string(old) == string(data) {
			return nil
		}
		if err = os.MkdirAll(filepath.Dir(g.file(server)), 0o700); err != nil {
			return err
		}
		if err = os.WriteFile(g.file(server), data, 0o600); err != nil {
			return err
		}
		wt, werr := g.repo.Worktree()
		if werr != nil {
			return werr
		}
		if _, err = wt.Add(filepath.Join("blocks", server+".json")); err != nil {
			return err
		}
		sig := &object.Signature{Name: "wafisp " + g.Name, Email: g.Name + "@wafisp.invalid", When: time.Now()}
		if _, err = wt.Commit("blocks of "+server, &git.CommitOptions{Author: sig, Committer: sig}); err != nil {
			return err
		}
		b := g.branch()
		err = g.repo.PushContext(ctx, &git.PushOptions{RemoteName: "origin", Auth: g.auth,
			RefSpecs: []gitconfig.RefSpec{gitconfig.RefSpec("refs/heads/" + b + ":refs/heads/" + b)}})
		if err == nil || errors.Is(err, git.NoErrAlreadyUpToDate) {
			g.fetched = time.Time{}
			return nil
		}
	}
	return fmt.Errorf("push: %w", err)
}

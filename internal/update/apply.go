package update

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Installer swaps the binary and restarts the service. It runs in the
// one-shot unit that Updater.launch starts, as the old binary.
type Installer struct {
	Exe       string
	Dir       string
	Service   string // systemd unit, "wafisp"
	Healthz   string // URL that answers 200 once the panel works; "" to rely on systemd alone
	PublicKey ed25519.PublicKey
	From      string // the running (old) version
	Run       Runner
	HTTP      *http.Client
	Wait      time.Duration // how long the new binary has to come up
	Every     time.Duration // between health checks
}

func (in *Installer) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if in.Run != nil {
		return in.Run(ctx, name, args...)
	}
	return execRun(ctx, name, args...)
}

// Install puts a staged release in place; it checks the signature again,
// since the staging dir is only as safe as the data dir.
func (in *Installer) Install(ctx context.Context, path string) error {
	bin, err := os.ReadFile(path)
	if err != nil {
		return in.fail("", err)
	}
	sig, err := os.ReadFile(path + ".sig")
	if err == nil {
		err = Verify(in.PublicKey, bin, sig)
	}
	if err != nil {
		return in.fail("", err)
	}
	to := in.version(ctx, path)
	if err := in.swap(bin); err != nil {
		return in.fail(to, err)
	}
	if err := in.restartAndWait(ctx); err != nil {
		// Back to the old binary, which <exe>.prev now holds.
		old, rerr := os.ReadFile(in.Exe + ".prev")
		if rerr == nil {
			rerr = in.replace(old)
		}
		if rerr == nil {
			rerr = in.restartAndWait(ctx)
		}
		if rerr != nil {
			return in.fail(to, fmt.Errorf("%v; putting %s back failed too: %v", err, in.From, rerr))
		}
		writeStatus(in.Dir, Status{State: "rolled_back", From: in.From, To: to, Message: err.Error(), At: time.Now()})
		return err
	}
	os.Remove(path)
	os.Remove(path + ".sig")
	writeStatus(in.Dir, Status{State: "ok", From: in.From, To: to, At: time.Now()})
	return nil
}

// Rollback swaps <exe>.prev and <exe>: the version before becomes the
// running one and the current one is kept as .prev.
func (in *Installer) Rollback(ctx context.Context) error {
	prev, err := os.ReadFile(in.Exe + ".prev")
	if err != nil {
		return in.fail("", errors.New("no previous version kept"))
	}
	to := in.version(ctx, in.Exe+".prev")
	if err := in.swap(prev); err != nil {
		return in.fail(to, err)
	}
	if err := in.restartAndWait(ctx); err != nil {
		return in.fail(to, err)
	}
	writeStatus(in.Dir, Status{State: "ok", From: in.From, To: to, Message: "rollback", At: time.Now()})
	return nil
}

// swap installs bin as the binary and keeps the current one as .prev.
// Renames on one file system: the running process keeps its old inode.
func (in *Installer) swap(bin []byte) error {
	cur, err := os.ReadFile(in.Exe)
	if err != nil {
		return err
	}
	if err := os.WriteFile(in.Exe+".prev.tmp", cur, 0o755); err != nil {
		return err
	}
	if err := in.replace(bin); err != nil {
		os.Remove(in.Exe + ".prev.tmp")
		return err
	}
	return os.Rename(in.Exe+".prev.tmp", in.Exe+".prev")
}

func (in *Installer) replace(bin []byte) error {
	if err := os.WriteFile(in.Exe+".new", bin, 0o755); err != nil {
		return err
	}
	return os.Rename(in.Exe+".new", in.Exe)
}

// restartAndWait restarts the service and waits until systemd calls it
// active and the health URL answers 200 twice in a row.
func (in *Installer) restartAndWait(ctx context.Context) error {
	if out, err := in.run(ctx, "systemctl", "restart", in.Service); err != nil {
		return fmt.Errorf("systemctl restart: %v %s", err, strings.TrimSpace(string(out)))
	}
	ok := 0
	var last string
	for deadline := time.Now().Add(in.Wait); time.Now().Before(deadline); {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(in.Every):
		}
		if last = in.health(ctx); last == "" {
			if ok++; ok >= 2 {
				return nil
			}
		} else {
			ok = 0
		}
	}
	return fmt.Errorf("the new version did not come up within %s: %s", in.Wait, last)
}

// health is "" when the service is up, else what is wrong.
func (in *Installer) health(ctx context.Context) string {
	out, _ := in.run(ctx, "systemctl", "is-active", in.Service)
	if s := strings.TrimSpace(string(out)); s != "active" {
		return "systemd: " + s
	}
	if in.Healthz == "" {
		return ""
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, in.Healthz, nil)
	resp, err := in.HTTP.Do(req)
	if err != nil {
		return "healthz: " + err.Error()
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "healthz: " + resp.Status
	}
	return ""
}

func (in *Installer) version(ctx context.Context, path string) string {
	out, _ := in.run(ctx, path, "-version")
	return strings.TrimSpace(string(out))
}

func (in *Installer) fail(to string, err error) error {
	writeStatus(in.Dir, Status{State: "failed", From: in.From, To: to, Message: err.Error(), At: time.Now()})
	return err
}

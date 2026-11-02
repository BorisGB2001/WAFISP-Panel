package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestExampleConfig keeps deploy/wafisp.example.yaml loadable.
func TestExampleConfig(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile("../../deploy/wafisp.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "wafisp.yaml"), b, 0o600)
	os.Mkdir(filepath.Join(dir, "secrets"), 0o700)
	for _, f := range []string{"telegram.token", "smtp.password", "webhook.secret"} {
		os.WriteFile(filepath.Join(dir, "secrets", f), []byte("x\n"), 0o600)
	}
	c, err := Load(filepath.Join(dir, "wafisp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.ModSec.PollInterval.D() != 2*time.Second || c.Nginx.MinAvailMB != 1024 || c.Block.IPSet != "wafisp" {
		t.Fatalf("defaults not applied: %+v %+v %+v", c.ModSec, c.Nginx, c.Block)
	}
	if r := c.Rules[1]; r.Cooldown.D() != 15*time.Minute || r.GroupBy != "src_ip" {
		t.Fatalf("rule defaults %+v", r)
	}
	if c.SIEM[0].QueueSize != 10000 || c.Channels[1].Email.Password != "x" {
		t.Fatal("defaults not applied")
	}
}

func load(t *testing.T, yaml string) error {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.yaml"), []byte(yaml), 0o600)
	_, err := Load(filepath.Join(dir, "c.yaml"))
	return err
}

func TestRejects(t *testing.T) {
	for name, y := range map[string]string{
		"unknown channel": `rules: [{name: r, channels: [nope]}]`,
		"unknown backend": `block: {backends: [pf]}`,
		"default not on":  `block: {backends: [ipset], default: [modsec]}`,
		"bad protected":   `block: {protected: [nonsense]}`,
		"bad allow_from":  `web: {allow_from: [nonsense]}`,
		"unaligned net":   `web: {allow_from: [10.6.0.0/14]}`,
	} {
		if load(t, y) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestPlainHTTPOnlyOnLoopback(t *testing.T) {
	for listen, ok := range map[string]bool{"127.0.0.1:8080": true, "localhost:8080": true, "0.0.0.0:12443": false, "10.0.0.1:80": false} {
		err := load(t, `web: {listen: ["`+listen+`"], plain_http: true}`)
		if (err == nil) != ok {
			t.Errorf("%s: err=%v", listen, err)
		}
	}
}

func TestAllowFrom(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.yaml"), []byte(`web: {allow_from: [10.0.0.0/24, 10.6.0.0/16, 10.6.250.110, "2001:db8::/32"]}`), 0o600)
	c, err := Load(filepath.Join(dir, "c.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(c.Web.Allowed) != "[10.0.0.0/24 10.6.0.0/16 10.6.250.110/32 2001:db8::/32]" {
		t.Errorf("allowed %v", c.Web.Allowed)
	}
}

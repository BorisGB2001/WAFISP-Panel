package block

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	prot := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("198.51.100.10/32")}
	for in, want := range map[string]string{
		"203.0.113.7":      "203.0.113.7",
		"203.0.113.7/24":   "203.0.113.0/24",
		"::ffff:203.0.1.1": "203.0.1.1",
		"2001:db8::1":      "2001:db8::1",
	} {
		got, err := normalize(in, "192.0.2.50", prot)
		if err != nil || got != want {
			t.Errorf("%s: got %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"203.0.0.0/8", "10.1.2.3", "127.0.0.1", "100.100.1.1", "198.51.100.0/24", "192.0.2.0/24", "x"} {
		if _, err := normalize(bad, "192.0.2.50", prot); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// fakeIPSet records ipset and iptables calls.
type fakeIPSet struct {
	members map[string]bool
	rule    bool
	log     []string
}

func (f *fakeIPSet) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.log = append(f.log, name+" "+strings.Join(args, " "))
	switch {
	case name == "ipset" && args[0] == "list":
		out := "Name: " + args[1] + "\nMembers:\n"
		for m := range f.members {
			if strings.Contains(m, ":") == strings.HasSuffix(args[1], "6") {
				out += m + " timeout 0\n"
			}
		}
		return []byte(out), nil
	case name == "ipset" && args[0] == "add":
		f.members[args[2]] = true
	case name == "ipset" && args[0] == "del":
		delete(f.members, args[2])
	case strings.HasSuffix(name, "tables") && args[1] == "-C":
		if !f.rule {
			return nil, errors.New("exit 1")
		}
	case strings.HasSuffix(name, "tables") && args[1] == "-I":
		f.rule = true
	}
	return nil, nil
}

func TestManagerWithIPSet(t *testing.T) {
	f := &fakeIPSet{members: map[string]bool{"198.51.100.99": true}} // left by hand: removed on sync
	s := &IPSet{Set: "wafisp", Ports: "80,443", Run: f.run}
	m := &Manager{File: filepath.Join(t.TempDir(), "blocks.json"), Backends: []Backend{s},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()
	if err := m.Block(ctx, Entry{IP: "203.0.113.7", Backends: []string{"ipset"}, By: "admin", Reason: "scan", At: time.Now(),
		Expires: time.Now().Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if !f.members["203.0.113.7"] || f.members["198.51.100.99"] || !f.rule {
		t.Fatalf("ipset state %v rule=%v", f.members, f.rule)
	}
	if !slices.ContainsFunc(f.log, func(s string) bool {
		return strings.HasPrefix(s, "iptables -w -I INPUT 1 -m set --match-set wafisp4 src -p tcp -m multiport --dports 80,443")
	}) {
		t.Fatalf("no iptables insert in %v", f.log)
	}
	if e, ok := m.Lookup("203.0.113.7"); !ok || e.By != "admin" {
		t.Fatal("lookup")
	}
	if exp := m.Expired(time.Now()); len(exp) != 1 {
		t.Fatalf("expired %v", exp)
	}
	if err := m.Unblock(ctx, "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if len(f.members) != 0 || len(m.Entries()) != 0 {
		t.Fatalf("not unblocked: %v", f.members)
	}
	if err := m.Block(ctx, Entry{IP: "203.0.113.8", Backends: []string{"nope"}}); err == nil {
		t.Fatal("unknown backend accepted")
	}
}

func TestParseKV(t *testing.T) {
	m := parseKV("key=-d 0.0.0.0/0 -s 203.0.113.7 -m comment --comment 'wafisp-panel' -j DROP type=deny sourceip=203.0.113.7 proto=all dport=all depend=0 isdepend=no comment=wafisp-panel scan")
	if m["type"] != "deny" || m["sourceip"] != "203.0.113.7" || m["comment"] != "wafisp-panel scan" || !strings.HasPrefix(m["key"], "-d 0.0.0.0/0 -s 203.0.113.7") {
		t.Fatalf("%v", m)
	}
}

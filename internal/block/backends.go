package block

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"wafisp/internal/policy"
)

// Runner runs a command and returns its combined output.
type Runner = policy.Runner

// IPSet drops the listed addresses on the web ports with one ipset per
// family and one iptables rule per family, inserted first in INPUT so
// ISPmanager's own allow rules cannot let them through. The rule is
// re-inserted when ISPmanager rewrites the chain.
type IPSet struct {
	Set   string // base name; the sets are <Set>4 and <Set>6
	Ports string // e.g. "80,443"; empty blocks every port
	Run   Runner
}

func (s *IPSet) Name() string { return "ipset" }

func (s *IPSet) set(v6 bool) string {
	if v6 {
		return s.Set + "6"
	}
	return s.Set + "4"
}

func (s *IPSet) ruleArgs(v6 bool) []string {
	args := []string{"INPUT", "-m", "set", "--match-set", s.set(v6), "src"}
	if s.Ports != "" {
		args = append(args, "-p", "tcp", "-m", "multiport", "--dports", s.Ports)
	}
	return append(args, "-m", "comment", "--comment", "wafisp-panel", "-j", "DROP")
}

func (s *IPSet) Ensure(ctx context.Context) error {
	for _, v6 := range []bool{false, true} {
		family, ipt := "inet", "iptables"
		if v6 {
			family, ipt = "inet6", "ip6tables"
		}
		if out, err := s.Run(ctx, "ipset", "create", s.set(v6), "hash:net", "family", family, "timeout", "0", "-exist"); err != nil {
			return fmt.Errorf("ipset create %s: %v %s", s.set(v6), err, bytes.TrimSpace(out))
		}
		check := append([]string{"-w", "-C"}, s.ruleArgs(v6)...)
		if _, err := s.Run(ctx, ipt, check...); err == nil {
			continue
		}
		ins := append([]string{"-w", "-I"}, s.ruleArgs(v6)[0])
		ins = append(ins, "1")
		ins = append(ins, s.ruleArgs(v6)[1:]...)
		if out, err := s.Run(ctx, ipt, ins...); err != nil {
			return fmt.Errorf("%s -I INPUT: %v %s", ipt, err, bytes.TrimSpace(out))
		}
	}
	return nil
}

func (s *IPSet) List(ctx context.Context) ([]string, error) {
	var out []string
	for _, v6 := range []bool{false, true} {
		b, err := s.Run(ctx, "ipset", "list", s.set(v6))
		if err != nil {
			return nil, fmt.Errorf("ipset list: %v %s", err, bytes.TrimSpace(b))
		}
		members := false
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "Members:" {
				members = true
				continue
			}
			if members && line != "" {
				f := strings.Fields(line)
				out = append(out, canon(f[0]))
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func (s *IPSet) Sync(ctx context.Context, ips []string) error {
	have, err := s.List(ctx)
	if err != nil {
		return err
	}
	want := canonAll(ips)
	for _, ip := range want {
		if !slices.Contains(have, ip) {
			if out, err := s.Run(ctx, "ipset", "add", s.set(is6(ip)), ip, "-exist"); err != nil {
				return fmt.Errorf("ipset add %s: %v %s", ip, err, bytes.TrimSpace(out))
			}
		}
	}
	for _, ip := range have {
		if !slices.Contains(want, ip) {
			if out, err := s.Run(ctx, "ipset", "del", s.set(is6(ip)), ip, "-exist"); err != nil {
				return fmt.Errorf("ipset del %s: %v %s", ip, err, bytes.TrimSpace(out))
			}
		}
	}
	return nil
}

// canon writes a single address without /32 or /128, as ipset lists it.
func canon(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.IsSingleIP() {
			return p.Addr().String()
		}
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return s
}

func canonAll(ips []string) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, canon(ip))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func is6(ip string) bool {
	if p, err := netip.ParsePrefix(ip); err == nil {
		return p.Addr().Is6()
	}
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Is6()
}

// ModSec puts the addresses on the deny list of the panel's ModSecurity
// rules. Sites in DetectionOnly only log them.
type ModSec struct {
	Policy *policy.Manager
}

func (m *ModSec) Name() string                     { return "modsec" }
func (m *ModSec) Ensure(ctx context.Context) error { return nil }

func (m *ModSec) List(ctx context.Context) ([]string, error) {
	return canonAll(m.Policy.State().Deny), nil
}

func (m *ModSec) Sync(ctx context.Context, ips []string) error {
	want := canonAll(ips)
	if slices.Equal(want, canonAll(m.Policy.State().Deny)) {
		return nil
	}
	return m.Policy.Update(ctx, func(s *policy.State) error {
		s.Deny = want
		return nil
	})
}

// ISPmgr adds deny rules to ISPmanager's firewall through mgrctl. The
// panel only touches rules whose comment starts with Comment.
type ISPmgr struct {
	Mgrctl  string // /usr/local/mgr5/sbin/mgrctl
	Comment string // "wafisp-panel"
	Run     Runner
}

func (f *ISPmgr) Name() string                     { return "ispmgr" }
func (f *ISPmgr) Ensure(ctx context.Context) error { return nil }

type fwRule struct{ key, ip string }

func (f *ISPmgr) rules(ctx context.Context) ([]fwRule, error) {
	b, err := f.Run(ctx, f.Mgrctl, "-m", "ispmgr", "firewall")
	if err != nil {
		return nil, fmt.Errorf("mgrctl firewall: %v %s", err, bytes.TrimSpace(b))
	}
	if bytes.Contains(b, []byte("Object: 'locked'")) {
		return nil, fmt.Errorf("ISPmanager is busy (locked), try again later")
	}
	var out []fwRule
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		kv := parseKV(sc.Text())
		if kv["type"] != "deny" || !strings.HasPrefix(kv["comment"], f.Comment) {
			continue
		}
		out = append(out, fwRule{key: kv["key"], ip: canon(kv["sourceip"])})
	}
	return out, nil
}

// parseKV splits a mgrctl line "key=... type=deny sourceip=... comment=..."
// where only the key value may contain spaces: it ends where " type=" begins.
func parseKV(line string) map[string]string {
	m := map[string]string{}
	if rest, ok := strings.CutPrefix(line, "key="); ok {
		if i := strings.Index(rest, " type="); i >= 0 {
			m["key"] = rest[:i]
			line = rest[i+1:]
		}
	}
	// The comment is last and may contain spaces.
	if i := strings.Index(line, " comment="); i >= 0 {
		m["comment"] = line[i+len(" comment="):]
		line = line[:i]
	}
	for _, f := range strings.Fields(line) {
		if k, v, ok := strings.Cut(f, "="); ok {
			m[k] = v
		}
	}
	return m
}

func (f *ISPmgr) List(ctx context.Context) ([]string, error) {
	rs, err := f.rules(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rs {
		out = append(out, r.ip)
	}
	slices.Sort(out)
	return out, nil
}

func (f *ISPmgr) Sync(ctx context.Context, ips []string) error {
	have, err := f.rules(ctx)
	if err != nil {
		return err
	}
	want := canonAll(ips)
	for _, ip := range want {
		if slices.ContainsFunc(have, func(r fwRule) bool { return r.ip == ip }) {
			continue
		}
		// The form of ISPmanager 6 (mgrctl -m ispmgr firewall.edit): action,
		// src_ip, proto, port, comment; an empty port means every port.
		out, err := f.Run(ctx, f.Mgrctl, "-m", "ispmgr", "firewall.edit", "sok=ok",
			"action=deny", "src_ip="+ip, "proto=any", "port=", "comment="+f.Comment)
		if err != nil || bytes.Contains(out, []byte("ERROR")) {
			return fmt.Errorf("mgrctl firewall.edit %s: %v %s", ip, err, bytes.TrimSpace(out))
		}
	}
	for _, r := range have {
		if slices.Contains(want, r.ip) {
			continue
		}
		out, err := f.Run(ctx, f.Mgrctl, "-m", "ispmgr", "firewall.delete", "elid="+r.key, "sok=ok")
		if err != nil || bytes.Contains(out, []byte("ERROR")) {
			return fmt.Errorf("mgrctl firewall.delete %s: %v %s", r.ip, err, bytes.TrimSpace(out))
		}
	}
	return nil
}

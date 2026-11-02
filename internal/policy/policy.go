// Package policy is what the panel adds to ModSecurity: allowed and denied
// addresses, rule exclusions and per-site engine modes. The panel keeps it
// in policy.json and writes it as two rule files that nginx loads around
// the CRS rules:
//
//	before.conf  runtime rules (phase 1): allow and deny lists, site modes,
//	             exclusions limited to a site or a path (ctl:ruleRemove…)
//	after.conf   configure-time exclusions for every site (SecRuleRemoveById,
//	             SecRuleUpdateTargetById), which must follow the rules they edit
//
// Every change is checked with nginx -t before nginx reloads; when the test
// fails the previous files are put back.
package policy

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Rule ids the panel writes; CRS uses 9xxxxx and the sites' own
// exclusions 100xxxx.
const (
	idAllow     = 7710001
	idDeny      = 7710002
	idModeBase  = 7710100
	idExclBase  = 7711000
	maxExclRule = 7719999
	idTrapBase  = 7720000
	maxTrapRule = 7729999
)

// Placeholder keeps the address files non-empty (TEST-NET-1).
const Placeholder = "192.0.2.255"

type Meta struct {
	By      string    `json:"by"`
	Reason  string    `json:"reason"`
	At      time.Time `json:"at"`
	Expires time.Time `json:"expires,omitzero"`
}

// Addr is an allowed address: the WAF only logs its requests, never
// blocks them, and the panel never bans it.
type Addr struct {
	IP string `json:"ip"`
	Meta
}

// Exclusion switches rules off, everywhere or for a site, a path and one
// request variable.
type Exclusion struct {
	ID       int    `json:"id"`
	Disabled bool   `json:"disabled,omitempty"`
	Site     string `json:"site,omitempty"` // empty: every site
	// Hosts are the server names of Site, matched against Host.
	Hosts []string `json:"hosts,omitempty"`
	// Path limits the exclusion to URIs starting with it.
	Path string `json:"path,omitempty"`
	// Rules are rule ids ("942100") or ranges ("942100-942199"), Tags CRS
	// tags ("attack-xss"). At least one of them is set.
	Rules []string `json:"rules,omitempty"`
	Tags  []string `json:"tags,omitempty"`
	// Target limits the exclusion to one variable, e.g. ARGS:jform[text]
	// or REQUEST_COOKIES:session; empty excludes the whole rule.
	Target string `json:"target,omitempty"`
	Meta
}

// Trap bans whoever requests a path: the WAF denies and logs the request,
// and the auto-ban blocks the address for Duration (0: for good).
type Trap struct {
	ID       int  `json:"id"`
	Disabled bool `json:"disabled,omitempty"`
	// DryRun logs and records whom it would ban, blocks nothing.
	DryRun bool   `json:"dry_run,omitempty"`
	Site   string `json:"site,omitempty"` // empty: every site
	// Hosts are the server names of Site, matched against Host.
	Hosts []string `json:"hosts,omitempty"`
	// Path is a prefix of the request path or, with Match "contains", any
	// part of it ("/.env", ".git/"); compared without case.
	Path     string        `json:"path"`
	Match    string        `json:"match,omitempty"` // "" (prefix) | "contains"
	Duration time.Duration `json:"duration"`
	Meta
}

func (t *Trap) Validate() error {
	switch t.Match {
	case "":
		if !pathRe.MatchString(t.Path) || len(t.Path) < 2 {
			return fmt.Errorf("the trap path must start with /, be longer than / alone and hold no spaces or quotes")
		}
	case "contains":
		if !partRe.MatchString(t.Path) || strings.Trim(t.Path, "/.") == "" {
			return fmt.Errorf("the part of the path must be 3 to 255 characters, more than slashes and dots, with no spaces or quotes")
		}
	default:
		return fmt.Errorf("unknown match %q", t.Match)
	}
	if t.Site != "" && len(t.Hosts) == 0 {
		return fmt.Errorf("site %s has no server names", t.Site)
	}
	for _, h := range t.Hosts {
		if !hostRe.MatchString(h) {
			return fmt.Errorf("%q is not a host name", h)
		}
	}
	if t.Duration < 0 || (t.Duration > 0 && t.Duration < time.Minute) {
		return fmt.Errorf("a ban must last at least 1 minute, or 0 for good")
	}
	if t.ID <= 0 || idTrapBase+t.ID > maxTrapRule {
		return fmt.Errorf("trap id %d is out of range", t.ID)
	}
	return nil
}

// Matches tells whether a request for path on site falls into the trap.
func (t *Trap) Matches(site, path string) bool {
	if t.Disabled || (t.Site != "" && t.Site != site) {
		return false
	}
	if t.Match == "contains" {
		return strings.Contains(strings.ToLower(path), strings.ToLower(t.Path))
	}
	return strings.HasPrefix(strings.ToLower(path), strings.ToLower(t.Path))
}

// Mode overrides the WAF engine of one site.
type Mode struct {
	Site   string   `json:"site"`
	Hosts  []string `json:"hosts"`
	Engine string   `json:"engine"` // DetectionOnly | Off
	Meta
}

// State is policy.json.
type State struct {
	Allow      []Addr      `json:"allow"`
	Deny       []string    `json:"deny"` // owned by the block manager
	Exclusions []Exclusion `json:"exclusions"`
	Modes      []Mode      `json:"modes"`
	Traps      []Trap      `json:"traps,omitempty"`
	NextID     int         `json:"next_id"`
}

var (
	ruleRe   = regexp.MustCompile(`^\d{1,7}(-\d{1,7})?$`)
	tagRe    = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,64}$`)
	targetRe = regexp.MustCompile(`^(ARGS|ARGS_GET|ARGS_POST|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|XML|FILES|FILES_NAMES)(:[A-Za-z0-9_\-\[\].$/@ ]{1,128})?$`)
	hostRe   = regexp.MustCompile(`^[a-z0-9*]([a-z0-9.\-*]{0,251}[a-z0-9])?$`)
	pathRe   = regexp.MustCompile(`^/[^\s"'\\]{0,255}$`)
	partRe   = regexp.MustCompile(`^[^\s"'\\]{3,255}$`)
)

// Validate checks an exclusion before it is saved; values end up inside
// ModSecurity directives, so anything that could break out is refused.
func (x *Exclusion) Validate() error {
	if len(x.Rules) == 0 && len(x.Tags) == 0 {
		return fmt.Errorf("give at least one rule id or tag")
	}
	for _, r := range x.Rules {
		if !ruleRe.MatchString(r) {
			return fmt.Errorf("%q is not a rule id or range", r)
		}
		if lo, hi, ok := strings.Cut(r, "-"); ok {
			a, _ := strconv.Atoi(lo)
			b, _ := strconv.Atoi(hi)
			if a >= b {
				return fmt.Errorf("range %q is empty", r)
			}
		}
	}
	for _, t := range x.Tags {
		if !tagRe.MatchString(t) {
			return fmt.Errorf("%q is not a tag", t)
		}
	}
	if x.Target != "" && !targetRe.MatchString(x.Target) {
		return fmt.Errorf("%q is not a supported variable (ARGS:name, REQUEST_COOKIES:name, REQUEST_HEADERS:name, ...)", x.Target)
	}
	if x.Path != "" && !pathRe.MatchString(x.Path) {
		return fmt.Errorf("the path must start with / and hold no spaces or quotes")
	}
	if x.Site != "" && len(x.Hosts) == 0 {
		return fmt.Errorf("site %s has no server names", x.Site)
	}
	for _, h := range x.Hosts {
		if !hostRe.MatchString(h) {
			return fmt.Errorf("%q is not a host name", h)
		}
	}
	if x.Target != "" {
		for _, r := range x.Rules {
			if strings.Contains(r, "-") {
				return fmt.Errorf("a range cannot be limited to one variable; list the rule ids")
			}
		}
	}
	if x.ID < 0 || idExclBase+x.ID > maxExclRule {
		return fmt.Errorf("exclusion id %d is out of range", x.ID)
	}
	return nil
}

// Scope tells whether an exclusion needs a runtime rule.
func (x *Exclusion) runtime() bool { return x.Site != "" || x.Path != "" }

// ValidMode checks an engine name.
// AllowedFor returns the allow-list entry that covers ip, an address or a
// subnet: the entry contains it, or a subnet ip overlaps the entry.
func (s *State) AllowedFor(ip string) (Addr, bool) {
	p, ok := prefixOf(ip)
	if !ok {
		return Addr{}, false
	}
	for _, a := range s.Allow {
		if q, ok := prefixOf(a.IP); ok && q.Overlaps(p) {
			return a, true
		}
	}
	return Addr{}, false
}

func prefixOf(s string) (netip.Prefix, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	return p.Masked(), err == nil
}

func ValidMode(m string) bool { return m == "DetectionOnly" || m == "Off" }

// Files renders before.conf and after.conf; dir is where the address
// files live.
func (s *State) Files(dir string) (before, after string) {
	var b, a strings.Builder
	head := "# Generated by WAFISP Panel. Do not edit: the panel rewrites this file.\n"
	b.WriteString(head)
	a.WriteString(head)

	fmt.Fprintf(&b, "SecRule REMOTE_ADDR \"@ipMatchFromFile %s/allow.txt\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly\"\n", dir, idAllow)
	fmt.Fprintf(&b, "SecRule REMOTE_ADDR \"@ipMatchFromFile %s/deny.txt\" \"id:%d,phase:1,deny,status:403,log,auditlog,msg:'WAFISP Panel: address on the deny list',tag:'wafisp-panel'\"\n", dir, idDeny)

	for i, m := range s.Modes {
		if !ValidMode(m.Engine) || len(m.Hosts) == 0 {
			continue
		}
		fmt.Fprintf(&b, "# %s: %s (%s, %s)\n", m.Site, m.Engine, oneLine(m.By), oneLine(m.Reason))
		fmt.Fprintf(&b, "SecRule REQUEST_HEADERS:Host \"@rx %s\" \"id:%d,phase:1,pass,nolog,t:lowercase,ctl:ruleEngine=%s\"\n",
			hostsRx(m.Hosts), idModeBase+i, m.Engine)
	}

	// Traps come before the CRS rules: the request is denied and logged even
	// when no attack rule fires, so the panel sees it and bans the address.
	for _, t := range s.Traps {
		if t.Disabled || t.Validate() != nil {
			continue
		}
		action := "deny,status:403"
		if t.DryRun {
			action = "pass"
		}
		fmt.Fprintf(&b, "# trap %d: %s%s (%s, %s)\n", t.ID, t.Site, t.Path, oneLine(t.By), oneLine(t.Reason))
		head := fmt.Sprintf("id:%d,phase:1,%s,log,auditlog,msg:'WAFISP Panel: trap %s',tag:'wafisp-panel',tag:'wafisp-trap'", idTrapBase+t.ID, action, t.Path)
		op := "@beginsWith " + strings.ToLower(t.Path)
		if t.Match == "contains" {
			op = "@contains " + strings.ToLower(t.Path)
		}
		if t.Site == "" {
			fmt.Fprintf(&b, "SecRule REQUEST_FILENAME \"%s\" \"%s,t:lowercase\"\n", op, head)
			continue
		}
		fmt.Fprintf(&b, "SecRule REQUEST_HEADERS:Host \"@rx %s\" \"%s,t:lowercase,chain\"\n", hostsRx(t.Hosts), head)
		fmt.Fprintf(&b, "\tSecRule REQUEST_FILENAME \"%s\" \"t:lowercase\"\n", op)
	}

	for _, x := range s.Exclusions {
		if x.Disabled || x.Validate() != nil {
			continue
		}
		comment := fmt.Sprintf("# exclusion %d: %s (%s, %s)\n", x.ID, x.describe(), oneLine(x.By), oneLine(x.Reason))
		if x.runtime() {
			b.WriteString(comment)
			writeRuntime(&b, x)
			continue
		}
		a.WriteString(comment)
		writeConfigTime(&a, x)
	}
	return b.String(), a.String()
}

func (x *Exclusion) describe() string {
	var parts []string
	if x.Site != "" {
		parts = append(parts, "site "+x.Site)
	} else {
		parts = append(parts, "all sites")
	}
	if x.Path != "" {
		parts = append(parts, "path "+x.Path)
	}
	parts = append(parts, "rules "+strings.Join(append(slices.Clone(x.Rules), x.Tags...), ","))
	if x.Target != "" {
		parts = append(parts, "only "+x.Target)
	}
	return strings.Join(parts, ", ")
}

// writeRuntime emits a phase 1 rule that removes rules for the requests
// it matches. A chain is needed when both a site and a path apply.
func writeRuntime(b *strings.Builder, x Exclusion) {
	var ctls []string
	for _, r := range x.Rules {
		if x.Target != "" {
			ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveTargetById=%s;%s", r, x.Target))
		} else {
			ctls = append(ctls, "ctl:ruleRemoveById="+r)
		}
	}
	for _, t := range x.Tags {
		if x.Target != "" {
			ctls = append(ctls, fmt.Sprintf("ctl:ruleRemoveTargetByTag=%s;%s", t, x.Target))
		} else {
			ctls = append(ctls, "ctl:ruleRemoveByTag="+t)
		}
	}
	id := idExclBase + x.ID
	type cond struct{ v, op string }
	var conds []cond
	if x.Site != "" {
		conds = append(conds, cond{"REQUEST_HEADERS:Host", "@rx " + hostsRx(x.Hosts)})
	}
	if x.Path != "" {
		conds = append(conds, cond{"REQUEST_FILENAME", "@beginsWith " + x.Path})
	}
	for i, c := range conds {
		last := i == len(conds)-1
		var actions string
		switch {
		case i == 0 && last:
			actions = fmt.Sprintf("id:%d,phase:1,pass,nolog,t:none%s,%s", id, lower(c.v), strings.Join(ctls, ","))
		case i == 0:
			actions = fmt.Sprintf("id:%d,phase:1,pass,nolog,t:none%s,chain", id, lower(c.v))
		case last:
			actions = "t:none" + lower(c.v) + "," + strings.Join(ctls, ",")
		default:
			actions = "t:none" + lower(c.v) + ",chain"
		}
		indent := ""
		if i > 0 {
			indent = "\t"
		}
		fmt.Fprintf(b, "%sSecRule %s \"%s\" \"%s\"\n", indent, c.v, c.op, actions)
	}
}

func lower(v string) string {
	if v == "REQUEST_HEADERS:Host" {
		return ",t:lowercase"
	}
	return ""
}

// writeConfigTime emits directives that edit the loaded CRS rules.
func writeConfigTime(b *strings.Builder, x Exclusion) {
	for _, r := range x.Rules {
		if x.Target != "" {
			fmt.Fprintf(b, "SecRuleUpdateTargetById %s \"!%s\"\n", r, x.Target)
		} else {
			fmt.Fprintf(b, "SecRuleRemoveById %s\n", r)
		}
	}
	for _, t := range x.Tags {
		if x.Target != "" {
			fmt.Fprintf(b, "SecRuleUpdateTargetByTag \"%s\" \"!%s\"\n", t, x.Target)
		} else {
			fmt.Fprintf(b, "SecRuleRemoveByTag \"%s\"\n", t)
		}
	}
}

// hostsRx matches the Host header of any of hosts, with an optional port.
func hostsRx(hosts []string) string {
	var alts []string
	for _, h := range hosts {
		q := regexp.QuoteMeta(strings.ToLower(h))
		q = strings.ReplaceAll(q, `\*`, `[a-z0-9-]+`)
		alts = append(alts, q)
	}
	slices.Sort(alts)
	alts = slices.Compact(alts)
	return "^(?:" + strings.Join(alts, "|") + ")(?::[0-9]+)?$"
}

func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// AddrList renders an address file for @ipMatchFromFile.
func AddrList(ips []string) string {
	var out []string
	for _, ip := range ips {
		if _, err := netip.ParsePrefix(ip); err == nil {
			out = append(out, ip)
		} else if _, err := netip.ParseAddr(ip); err == nil {
			out = append(out, ip)
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) == 0 {
		out = []string{Placeholder}
	}
	return strings.Join(out, "\n") + "\n"
}

// Package config loads the YAML configuration of the panel.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that is written as "30s" or "5m" in YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) D() time.Duration { return time.Duration(d) }

type Config struct {
	// Language of alert texts: "en" (default) or "ru".
	Language string    `yaml:"language"`
	DataDir  string    `yaml:"data_dir"`
	HTTP     HTTP      `yaml:"http"`
	Web      Web       `yaml:"web"`
	ModSec   ModSec    `yaml:"modsecurity"`
	Nginx    Nginx     `yaml:"nginx"`
	Block    Block     `yaml:"block"`
	Channels []Channel `yaml:"channels"`
	Rules    []Rule    `yaml:"rules"`
	SIEM     []SIEM    `yaml:"siem"`
	// GeoIPDB is a MaxMind-format Country or City database.
	GeoIPDB string `yaml:"geoip_db"`
	// Retention of the event store, 30 days by default.
	Retention Duration `yaml:"retention"`
	// SystemChannels receive the panel's own notices: auto-bans and
	// problems with its rules (an update removed the nginx include, ...).
	SystemChannels []string `yaml:"system_channels"`
}

// ModSec is where the audit logs are and where the panel's rules go.
type ModSec struct {
	// AuditGlob matches the sites' audit logs; the site is the file name
	// without AuditSuffix.
	AuditGlob    string   `yaml:"audit_glob"`
	AuditSuffix  string   `yaml:"audit_suffix"`
	PollInterval Duration `yaml:"poll_interval"`
	// RulesDir receives before.conf, after.conf, allow.txt and deny.txt;
	// nginx must load before.conf ahead of CRS and after.conf behind it.
	RulesDir string `yaml:"rules_dir"`
}

// Nginx is how the panel finds the sites and applies its rules.
type Nginx struct {
	VhostsDir    string   `yaml:"vhosts_dir"`
	ResourcesDir string   `yaml:"resources_dir"`
	Test         []string `yaml:"test"`
	Reload       []string `yaml:"reload"`
	// MinAvailMB postpones reloads while less memory is available.
	MinAvailMB int `yaml:"min_avail_mb"`
	// IncludeFile is the file that loads the panel's rules around CRS;
	// the panel only reads it, to warn when an update removed the lines.
	IncludeFile string `yaml:"include_file"`
}

// Block configures the ways to block an address.
type Block struct {
	// Backends that are available, in the order shown: ipset, modsec, ispmgr.
	Backends []string `yaml:"backends"`
	// Default backends preselected in the panel.
	Default []string `yaml:"default"`
	IPSet   string   `yaml:"ipset_name"`
	// Ports the ipset rule drops; empty drops every port.
	Ports  string `yaml:"ports"`
	Mgrctl string `yaml:"mgrctl"`
	// Protected addresses and subnets can never be blocked.
	Protected []string `yaml:"protected"`
}

type HTTP struct {
	// Listen serves /healthz and /metrics. Empty disables it.
	Listen string `yaml:"listen"`
}

// Web is the panel UI.
type Web struct {
	// Listen is one or more addresses, e.g. "10.0.0.5:12443".
	Listen []string `yaml:"listen"`
	// TLSCert and TLSKey; when empty a self-signed certificate is created
	// in DataDir/tls on the first start.
	TLSCert    string   `yaml:"tls_cert"`
	TLSKey     string   `yaml:"tls_key"`
	SessionTTL Duration `yaml:"session_ttl"`
	// PlainHTTP serves without TLS. Only allowed on loopback addresses.
	PlainHTTP bool `yaml:"plain_http"`
	// DataDir is set from the top-level data_dir.
	DataDir string `yaml:"-"`
}

type Channel struct {
	Name     string    `yaml:"name"`
	Type     string    `yaml:"type"` // telegram | email | webhook
	Telegram *Telegram `yaml:"telegram"`
	Email    *Email    `yaml:"email"`
	Webhook  *Webhook  `yaml:"webhook"`
}

type Telegram struct {
	BotTokenFile string `yaml:"bot_token_file"`
	ChatID       string `yaml:"chat_id"`
	ThreadID     int64  `yaml:"thread_id"`
	// APIURL overrides https://api.telegram.org, e.g. for a local Bot API server.
	APIURL string `yaml:"api_url"`

	BotToken string `yaml:"-"`
}

type Email struct {
	Host         string   `yaml:"host"`
	Port         int      `yaml:"port"`
	TLS          string   `yaml:"tls"` // starttls | tls | none
	Username     string   `yaml:"username"`
	PasswordFile string   `yaml:"password_file"`
	From         string   `yaml:"from"`
	To           []string `yaml:"to"`

	Password string `yaml:"-"`
}

type Webhook struct {
	URL     string            `yaml:"url"`
	Format  string            `yaml:"format"` // json | slack
	Headers map[string]string `yaml:"headers"`
	// SecretFile enables an X-WAFPanel-Signature HMAC-SHA256 header.
	SecretFile string `yaml:"secret_file"`

	Secret string `yaml:"-"`
}

// Rule turns matching events into alerts.
type Rule struct {
	Name     string `yaml:"name"`
	Disabled bool   `yaml:"disabled,omitempty"`
	Severity string `yaml:"severity,omitempty"` // info | warning | critical

	// Filters; an empty list matches everything.
	Sites      []string `yaml:"sites,omitempty"`
	Hosts      []string `yaml:"hosts,omitempty"` // exact host or "*.example.com"
	Categories []string `yaml:"categories,omitempty"`
	Actions    []string `yaml:"actions,omitempty"` // deny | pass
	MinRisk    int      `yaml:"min_risk,omitempty"`
	MinScore   int      `yaml:"min_score,omitempty"`

	// Threshold events of one group within Window fire one alert.
	// Threshold 1 alerts on every event (still subject to Cooldown).
	Threshold int      `yaml:"threshold"`
	Window    Duration `yaml:"window,omitempty"`
	GroupBy   string   `yaml:"group_by,omitempty"` // src_ip | host | site | none
	Cooldown  Duration `yaml:"cooldown,omitempty"`

	Channels []string `yaml:"channels"`
}

// SIEM forwards every event (not alerts) to a syslog receiver.
type SIEM struct {
	Name    string `yaml:"name"`
	Network string `yaml:"network"` // udp | tcp | tls
	Address string `yaml:"address"`
	Format  string `yaml:"format"`  // cef | json
	Framing string `yaml:"framing"` // newline | octet (tcp/tls only)
	// Header is the syslog header before the message. Wazuh does not
	// pre-decode RFC 5424 and decodes JSON only without a header, so it
	// needs "none" with format json.
	Header string `yaml:"header"` // rfc5424 | none
	// JSONRaw adds every matched rule with its data in the json format.
	JSONRaw bool   `yaml:"json_raw"`
	CAFile  string `yaml:"ca_file"`
	// Facility is a syslog facility number, 16 (local0) by default.
	Facility   int      `yaml:"facility"`
	Hostname   string   `yaml:"hostname"`
	AppName    string   `yaml:"app_name"`
	Sites      []string `yaml:"sites"`
	OnlyDenied bool     `yaml:"only_denied"`
	QueueSize  int      `yaml:"queue_size"`
}

// Load reads path, expands ${ENV} references and reads secret files.
// Relative file paths are resolved from the directory of path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(os.ExpandEnv(string(raw))))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.finish(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) finish(dir string) error {
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	secret := func(p, what string) (string, error) {
		if p == "" {
			return "", nil
		}
		b, err := os.ReadFile(abs(p))
		if err != nil {
			return "", fmt.Errorf("%s: %w", what, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	var err error

	if c.Language == "" {
		c.Language = "en"
	}
	if c.Language != "en" && c.Language != "ru" {
		return fmt.Errorf("language must be en or ru")
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/wafisp"
	}
	c.DataDir = abs(c.DataDir)
	c.Web.DataDir = c.DataDir
	c.Web.TLSCert = abs(c.Web.TLSCert)
	c.Web.TLSKey = abs(c.Web.TLSKey)
	if (c.Web.TLSCert == "") != (c.Web.TLSKey == "") {
		return fmt.Errorf("web: tls_cert and tls_key go together")
	}
	for _, l := range c.Web.Listen {
		host, _, err := net.SplitHostPort(l)
		if err != nil {
			return fmt.Errorf("web: listen %q: %w", l, err)
		}
		if ip := net.ParseIP(host); c.Web.PlainHTTP && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("web: plain_http is only allowed on a loopback listen address")
		}
	}
	if c.Web.SessionTTL == 0 {
		c.Web.SessionTTL = Duration(12 * time.Hour)
	}
	c.GeoIPDB = abs(c.GeoIPDB)
	if c.Retention == 0 {
		c.Retention = Duration(30 * 24 * time.Hour)
	}
	if c.Retention.D() < 48*time.Hour {
		return fmt.Errorf("retention must be at least 48h")
	}

	m := &c.ModSec
	if m.AuditGlob == "" {
		m.AuditGlob = "/var/www/httpd-logs/*.audit.log"
	}
	if m.AuditSuffix == "" {
		m.AuditSuffix = ".audit.log"
	}
	if m.PollInterval == 0 {
		m.PollInterval = Duration(2 * time.Second)
	}
	if m.RulesDir == "" {
		// Outside /etc/modsecurity: ISPmanager's WAF module owns that
		// directory and treats its subdirectories as rule sets.
		m.RulesDir = "/etc/wafisp/modsec"
	}
	n := &c.Nginx
	if n.VhostsDir == "" {
		n.VhostsDir = "/etc/nginx/vhosts"
	}
	if n.ResourcesDir == "" {
		n.ResourcesDir = "/etc/nginx/vhosts-resources"
	}
	if n.Test == nil {
		n.Test = []string{"nginx", "-t", "-q"}
	}
	if n.Reload == nil {
		n.Reload = []string{"systemctl", "reload", "nginx"}
	}
	if n.MinAvailMB == 0 {
		n.MinAvailMB = 1024
	}
	if n.IncludeFile == "" {
		n.IncludeFile = "/etc/nginx/conf.d/modsecurity-crs.conf"
	}
	bl := &c.Block
	if bl.Backends == nil {
		bl.Backends = []string{"ipset", "modsec"}
	}
	for _, b := range bl.Backends {
		if b != "ipset" && b != "modsec" && b != "ispmgr" {
			return fmt.Errorf("block: unknown backend %q (ipset, modsec, ispmgr)", b)
		}
	}
	if bl.Default == nil {
		bl.Default = bl.Backends[:1]
	}
	for _, b := range bl.Default {
		if !contains(bl.Backends, b) {
			return fmt.Errorf("block: default backend %q is not in backends", b)
		}
	}
	if bl.IPSet == "" {
		bl.IPSet = "wafisp"
	}
	if bl.Ports == "" {
		bl.Ports = "80,443"
	}
	if bl.Mgrctl == "" {
		bl.Mgrctl = "/usr/local/mgr5/sbin/mgrctl"
	}
	for _, p := range bl.Protected {
		if _, err := ParsePrefix(p); err != nil {
			return fmt.Errorf("block: protected %q: %w", p, err)
		}
	}

	chans := map[string]bool{}
	for i := range c.Channels {
		ch := &c.Channels[i]
		if ch.Name == "" || chans[ch.Name] {
			return fmt.Errorf("channel #%d: name is empty or duplicated", i+1)
		}
		chans[ch.Name] = true
		switch ch.Type {
		case "telegram":
			if ch.Telegram == nil || ch.Telegram.ChatID == "" {
				return fmt.Errorf("channel %s: telegram.chat_id is required", ch.Name)
			}
			if ch.Telegram.BotToken, err = secret(ch.Telegram.BotTokenFile, "channel "+ch.Name+" bot_token_file"); err != nil {
				return err
			}
			if ch.Telegram.BotToken == "" {
				return fmt.Errorf("channel %s: telegram.bot_token_file is required", ch.Name)
			}
		case "email":
			e := ch.Email
			if e == nil || e.Host == "" || e.From == "" || len(e.To) == 0 {
				return fmt.Errorf("channel %s: email.host, from and to are required", ch.Name)
			}
			if e.TLS == "" {
				e.TLS = "starttls"
			}
			if e.Port == 0 {
				e.Port = map[string]int{"tls": 465, "starttls": 587, "none": 25}[e.TLS]
			}
			if e.Password, err = secret(e.PasswordFile, "channel "+ch.Name+" password_file"); err != nil {
				return err
			}
		case "webhook":
			if ch.Webhook == nil || ch.Webhook.URL == "" {
				return fmt.Errorf("channel %s: webhook.url is required", ch.Name)
			}
			if ch.Webhook.Format == "" {
				ch.Webhook.Format = "json"
			}
			if ch.Webhook.Secret, err = secret(ch.Webhook.SecretFile, "channel "+ch.Name+" secret_file"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("channel %s: unknown type %q", ch.Name, ch.Type)
		}
	}

	if err := c.ValidateRules(c.Rules); err != nil {
		return err
	}
	for _, n := range c.SystemChannels {
		if !chans[n] {
			return fmt.Errorf("system_channels: unknown channel %q", n)
		}
	}

	for i := range c.SIEM {
		s := &c.SIEM[i]
		if s.Name == "" {
			s.Name = fmt.Sprintf("siem-%d", i+1)
		}
		if s.Address == "" {
			return fmt.Errorf("siem %s: address is required", s.Name)
		}
		if s.Network == "" {
			s.Network = "udp"
		}
		if s.Network != "udp" && s.Network != "tcp" && s.Network != "tls" {
			return fmt.Errorf("siem %s: network must be udp, tcp or tls", s.Name)
		}
		if s.Format == "" {
			s.Format = "cef"
		}
		if s.Format != "cef" && s.Format != "json" {
			return fmt.Errorf("siem %s: format must be cef or json", s.Name)
		}
		if s.Framing == "" {
			s.Framing = "newline"
		}
		if s.Framing != "newline" && s.Framing != "octet" {
			return fmt.Errorf("siem %s: framing must be newline or octet", s.Name)
		}
		if s.Header == "" {
			s.Header = "rfc5424"
		}
		if s.Header != "rfc5424" && s.Header != "none" {
			return fmt.Errorf("siem %s: header must be rfc5424 or none", s.Name)
		}
		if s.Facility == 0 {
			s.Facility = 16
		}
		if s.AppName == "" {
			s.AppName = "wafisp"
		}
		if s.QueueSize == 0 {
			s.QueueSize = 10000
		}
		s.CAFile = abs(s.CAFile)
	}
	return nil
}

// ValidateRules checks rules against the configured channels and instances
// and fills in defaults. The web UI uses it before saving edited rules.
func (c *Config) ValidateRules(rules []Rule) error {
	chans := map[string]bool{}
	for _, ch := range c.Channels {
		chans[ch.Name] = true
	}
	names := map[string]bool{}
	for i := range rules {
		r := &rules[i]
		if r.Name == "" {
			return fmt.Errorf("rule #%d: name is required", i+1)
		}
		if names[r.Name] {
			return fmt.Errorf("rule %s: duplicated name", r.Name)
		}
		names[r.Name] = true
		if len(r.Channels) == 0 {
			return fmt.Errorf("rule %s: no channels", r.Name)
		}
		for _, n := range r.Channels {
			if !chans[n] {
				return fmt.Errorf("rule %s: unknown channel %q", r.Name, n)
			}
		}
		for _, a := range r.Actions {
			if a != "deny" && a != "pass" {
				return fmt.Errorf("rule %s: action must be deny or pass, got %q", r.Name, a)
			}
		}
		if r.Threshold <= 0 {
			r.Threshold = 1
		}
		if r.Threshold > 1 && r.Window == 0 {
			return fmt.Errorf("rule %s: window is required when threshold > 1", r.Name)
		}
		if r.GroupBy == "" {
			r.GroupBy = "src_ip"
		}
		if r.GroupBy != "src_ip" && r.GroupBy != "host" && r.GroupBy != "site" && r.GroupBy != "none" {
			return fmt.Errorf("rule %s: unknown group_by %q", r.Name, r.GroupBy)
		}
		if r.Cooldown == 0 {
			r.Cooldown = r.Window
		}
		if r.Severity == "" {
			r.Severity = "warning"
		}
		if r.Severity != "info" && r.Severity != "warning" && r.Severity != "critical" {
			return fmt.Errorf("rule %s: severity must be info, warning or critical", r.Name)
		}
	}
	return nil
}

// MarshalYAML writes a Duration back as "5m".
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// String is time.Duration without the zero tails: "5m" instead of "5m0s".
func (d Duration) String() string {
	s := time.Duration(d).String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// ParsePrefix accepts an address or a subnet.
func ParsePrefix(s string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	return p.Masked(), err
}

// Package sites reads the web sites of ISPmanager from nginx's config:
// /etc/nginx/vhosts/<owner>/<site>.conf for names and owners, and
// /etc/nginx/vhosts-resources/<site>/ for the WAF settings ISPmanager
// writes there. It never writes to either.
package sites

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

type Site struct {
	Name  string
	Owner string
	// Hosts are the server names (without the ones nginx uses internally).
	Hosts []string
	// WAF is "On", "DetectionOnly", "Off" or "" when the site has no
	// ModSecurity settings.
	WAF      string
	AuditLog string
	// Extra are the site's own rule files next to ISPmanager's
	// (zz-waf-exclusions.conf, ...).
	Extra []string
	// AccessLog is whether nginx writes the site's request log: ISPmanager
	// puts access_log <file> in the vhost when its request log is on and
	// only access_log off when it is not.
	AccessLog bool
}

type Reader struct {
	VhostsDir    string // /etc/nginx/vhosts
	ResourcesDir string // /etc/nginx/vhosts-resources

	mu    sync.Mutex
	cache []Site
	at    time.Time
}

var (
	serverNameRe = regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	engineRe     = regexp.MustCompile(`^\s*SecRuleEngine\s+(\w+)`)
	auditRe      = regexp.MustCompile(`^\s*SecAuditLog\s+(\S+)`)
	modsecOnRe   = regexp.MustCompile(`^\s*modsecurity\s+(on|off)\s*;`)
	accessLogRe  = regexp.MustCompile(`^\s*access_log\s+([^\s;]+)`)
)

// Sites returns the sites, re-read at most once a minute.
func (r *Reader) Sites() []Site {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache != nil && time.Since(r.at) < time.Minute {
		return r.cache
	}
	r.cache, r.at = r.read(), time.Now()
	return r.cache
}

// Forget drops the cache, so the next call reads the vhosts again.
func (r *Reader) Forget() {
	r.mu.Lock()
	r.cache = nil
	r.mu.Unlock()
}

// Get returns one site by name.
func (r *Reader) Get(name string) (Site, bool) {
	for _, s := range r.Sites() {
		if s.Name == name {
			return s, true
		}
	}
	return Site{}, false
}

// SiteOfHost maps a Host header to its site.
func (r *Reader) SiteOfHost(host string) string {
	host = strings.ToLower(host)
	for _, s := range r.Sites() {
		if slices.Contains(s.Hosts, host) {
			return s.Name
		}
	}
	return ""
}

func (r *Reader) read() []Site {
	byName := map[string]*Site{}
	files, _ := filepath.Glob(filepath.Join(r.VhostsDir, "*", "*.conf"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".conf")
		s := byName[name]
		if s == nil {
			s = &Site{Name: name, Owner: filepath.Base(filepath.Dir(f))}
			byName[name] = s
		}
		eachLine(f, func(line string) {
			if m := serverNameRe.FindStringSubmatch(line); m != nil {
				for _, h := range strings.Fields(m[1]) {
					h = strings.ToLower(h)
					if h != "_" && !slices.Contains(s.Hosts, h) {
						s.Hosts = append(s.Hosts, h)
					}
				}
			}
			if m := accessLogRe.FindStringSubmatch(line); m != nil && m[1] != "off" {
				s.AccessLog = true
			}
		})
	}
	dirs, _ := os.ReadDir(r.ResourcesDir)
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		s := byName[d.Name()]
		if s == nil {
			continue // resources of a site that no longer exists
		}
		dir := filepath.Join(r.ResourcesDir, d.Name())
		on := false
		eachLine(filepath.Join(dir, "modsecurity.conf"), func(line string) {
			if m := modsecOnRe.FindStringSubmatch(line); m != nil {
				on = m[1] == "on"
			}
			if m := engineRe.FindStringSubmatch(line); m != nil {
				s.WAF = m[1]
			}
			if m := auditRe.FindStringSubmatch(line); m != nil {
				s.AuditLog = strings.Trim(m[1], `"'`)
			}
		})
		if !on && s.WAF != "" {
			s.WAF = "Off"
		}
		extra, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
		for _, e := range extra {
			if b := filepath.Base(e); b != "modsecurity.conf" {
				s.Extra = append(s.Extra, b)
			}
		}
	}
	out := make([]Site, 0, len(byName))
	for _, s := range byName {
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b Site) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func eachLine(path string, fn func(string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fn(sc.Text())
	}
}

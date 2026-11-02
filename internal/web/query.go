package web

import (
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"wafisp/internal/store"
)

// filter selects events of the store; every field is optional.
type filter struct {
	Period string
	Site   string
	IP     string
	Rule   string
	Cat    string
	Action string // deny | pass
	Path   string // substring of the path
	Var    string // matched variable, e.g. ARGS:id
	Score  int    // minimal anomaly score
	Page   int

	net netip.Prefix // IP as a subnet, when it is one
}

var periods = []struct{ Key, Label string }{
	{"1h", "1 hour"}, {"today", "Today"}, {"24h", "24 hours"}, {"7d", "7 days"}, {"30d", "30 days"}, {"all", "All time"},
}

func periodStart(p string, now time.Time) time.Time {
	switch p {
	case "1h":
		return now.Add(-time.Hour)
	case "today": // since local midnight
		y, m, d := now.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, now.Location())
	case "7d":
		return now.AddDate(0, 0, -7)
	case "30d":
		return now.AddDate(0, 0, -30)
	case "all":
		return time.Time{}
	}
	return now.Add(-24 * time.Hour)
}

func parseFilter(r *http.Request, defPeriod string) filter {
	q := r.URL.Query()
	f := filter{
		Period: q.Get("period"), Site: q.Get("site"), IP: strings.TrimSpace(q.Get("ip")),
		Rule: strings.TrimSpace(q.Get("rule")), Cat: q.Get("cat"), Action: q.Get("action"),
		Path: strings.TrimSpace(q.Get("path")), Var: strings.TrimSpace(q.Get("var")),
	}
	if p, err := netip.ParsePrefix(f.IP); err == nil {
		f.net = p.Masked()
	}
	f.Score, _ = strconv.Atoi(q.Get("score"))
	f.Page, _ = strconv.Atoi(q.Get("page"))
	f.Page = max(f.Page, 1)
	if !slices.ContainsFunc(periods, func(p struct{ Key, Label string }) bool { return p.Key == f.Period }) {
		f.Period = defPeriod
	}
	return f
}

func (f filter) since() time.Time { return periodStart(f.Period, time.Now()) }

func (f filter) match(e *store.Summary) bool {
	switch {
	case f.Site != "" && e.Site != f.Site,
		f.IP != "" && !f.ipMatch(e.SrcIP),
		f.Cat != "" && e.Category != f.Cat,
		f.Action == "deny" && !e.Denied,
		f.Action == "pass" && e.Denied,
		f.Score > 0 && e.Score < f.Score,
		f.Path != "" && !strings.Contains(strings.ToLower(e.Path), strings.ToLower(f.Path)),
		f.Rule != "" && !slices.Contains(e.Rules, f.Rule),
		f.Var != "" && !slices.Contains(e.Vars, f.Var):
		return false
	}
	return true
}

// ipMatch takes an address, a subnet, or the start of an address ending
// in "*".
func (f filter) ipMatch(ip string) bool {
	switch {
	case f.net.IsValid():
		a, err := netip.ParseAddr(ip)
		return err == nil && f.net.Contains(a.Unmap())
	case strings.HasSuffix(f.IP, "*"):
		return strings.HasPrefix(ip, strings.TrimSuffix(f.IP, "*"))
	}
	return ip == f.IP
}

// Query writes the filter as a query string; page 0 leaves it out. It is
// a template.URL so that html/template puts it after "?" as it is: a plain
// string there gets its "=" and "&" escaped and the server sees no
// parameters at all (the pager kept opening page 1). url.Values.Encode
// has already escaped every value.
func (f filter) Query(page int) template.URL {
	v := url.Values{}
	for k, x := range map[string]string{"period": f.Period, "site": f.Site, "ip": f.IP, "rule": f.Rule, "cat": f.Cat,
		"action": f.Action, "path": f.Path, "var": f.Var} {
		if x != "" {
			v.Set(k, x)
		}
	}
	if f.Score > 0 {
		v.Set("score", strconv.Itoa(f.Score))
	}
	if page > 1 {
		v.Set("page", strconv.Itoa(page))
	}
	return template.URL(v.Encode())
}

// With returns the filter's query with one field replaced, for links that
// narrow the current view.
func (f filter) With(k, v string) template.URL {
	q, _ := url.ParseQuery(string(f.Query(0)))
	q.Set(k, v)
	return template.URL(q.Encode())
}

// kv is one line of a top list.
type kv struct {
	Key   string
	Count int
	Extra string
}

type counter map[string]int

func (c counter) add(k string) {
	if k != "" {
		c[k]++
	}
}

func (c counter) top(n int) []kv {
	out := make([]kv, 0, len(c))
	for k, v := range c {
		out = append(out, kv{Key: k, Count: v})
	}
	slices.SortFunc(out, func(a, b kv) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Key, b.Key)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// agg sums up the events of a filter.
type agg struct {
	Total, Denied, Passed int
	IPs                   counter
	Sites                 counter
	Rules                 counter
	Cats                  counter
	Paths                 counter
	// PathsOutside counts the requests to each path from addresses not
	// on the allow list; zero means only allowed addresses went there.
	PathsOutside counter
	Countries    counter
	RuleMsg      map[string]string
	// Hourly (or daily) buckets for the chart, oldest first.
	Labels       []string
	BucketDenied []float64
	BucketPassed []float64
}

// aggregate sums up the events of f; allowed tells whether an address is
// on the allow list and may be nil.
func aggregate(st *store.Store, f filter, now time.Time, allowed func(string) bool) *agg {
	a := &agg{IPs: counter{}, Sites: counter{}, Rules: counter{}, Cats: counter{}, Paths: counter{},
		PathsOutside: counter{}, Countries: counter{}, RuleMsg: map[string]string{}}
	isAllowed := map[string]bool{}
	since := f.since()
	if since.IsZero() {
		since = st.Oldest()
	}
	// Buckets: hours up to 48 h, days beyond.
	step := time.Hour
	if now.Sub(since) > 48*time.Hour {
		step = 24 * time.Hour
	}
	start := since.Truncate(step)
	if step == 24*time.Hour {
		y, m, d := since.Local().Date()
		start = time.Date(y, m, d, 0, 0, 0, 0, time.Local)
	}
	n := int(now.Sub(start)/step) + 1
	if n > 400 || n < 1 {
		n = 1
	}
	a.BucketDenied = make([]float64, n)
	a.BucketPassed = make([]float64, n)
	for i := range n {
		t := start.Add(time.Duration(i) * step).Local()
		if step == time.Hour {
			a.Labels = append(a.Labels, t.Format("15:00"))
		} else {
			a.Labels = append(a.Labels, t.Format("02.01"))
		}
	}
	st.Scan(since, func(e *store.Summary) bool {
		if !f.match(e) {
			return true
		}
		a.Total++
		i := int(e.Time.Sub(start) / step)
		if e.Denied {
			a.Denied++
			if i >= 0 && i < n {
				a.BucketDenied[i]++
			}
		} else {
			a.Passed++
			if i >= 0 && i < n {
				a.BucketPassed[i]++
			}
		}
		a.IPs.add(e.SrcIP)
		a.Sites.add(e.Site)
		a.Cats.add(e.Category)
		a.Paths.add(e.Site + e.Path)
		ok, seen := isAllowed[e.SrcIP]
		if !seen {
			ok = allowed != nil && allowed(e.SrcIP)
			isAllowed[e.SrcIP] = ok
		}
		if !ok {
			a.PathsOutside.add(e.Site + e.Path)
		}
		a.Countries.add(e.Country)
		for _, r := range e.Rules {
			a.Rules.add(r)
		}
		return true
	})
	for r := range a.Rules {
		a.RuleMsg[r] = st.RuleMsg(r)
	}
	return a
}

// candidate is a rule that may be a false positive: it fires on one site,
// path and variable for many different addresses.
type candidate struct {
	Site, Rule, Var, Path, Msg string
	Count, IPs, Denied         int
	// Focused are the addresses that touched at most maxFocusPaths paths
	// in the period: visitors using a form, not scanners trying hundreds
	// of URLs.
	Focused     int
	First, Last time.Time
}

const maxFocusPaths = 3

type candKey struct{ site, rule, v, path string }

// candidates groups events by site, rule, variable and path and ranks the
// groups by how many focused addresses hit them: an attacker is one
// address or a scanner touching many paths; a broken form is many
// ordinary visitors.
func candidates(st *store.Store, f filter, minIPs int) []candidate {
	since := f.since()
	// Pass 1: how many distinct paths every address touched.
	paths := map[string]map[string]struct{}{}
	st.Scan(since, func(e *store.Summary) bool {
		if !f.match(e) {
			return true
		}
		ps := paths[e.SrcIP]
		if ps == nil {
			ps = map[string]struct{}{}
			paths[e.SrcIP] = ps
		}
		if len(ps) <= maxFocusPaths {
			ps[e.Site+e.Path] = struct{}{}
		}
		return true
	})
	groups := map[candKey]*candidate{}
	ips := map[candKey]map[string]struct{}{}
	st.Scan(since, func(e *store.Summary) bool {
		if !f.match(e) {
			return true
		}
		for i, r := range e.Rules {
			v := ""
			if i < len(e.RVars) {
				v = e.RVars[i]
			}
			k := candKey{e.Site, r, v, e.Path}
			c := groups[k]
			if c == nil {
				c = &candidate{Site: e.Site, Rule: r, Var: v, Path: e.Path, Msg: st.RuleMsg(r), First: e.Time, Last: e.Time}
				groups[k] = c
				ips[k] = map[string]struct{}{}
			}
			c.Count++
			if e.Denied {
				c.Denied++
			}
			c.First = e.Time // scanning newest first
			ips[k][e.SrcIP] = struct{}{}
		}
		return true
	})
	var out []candidate
	for k, c := range groups {
		c.IPs = len(ips[k])
		for ip := range ips[k] {
			if len(paths[ip]) <= maxFocusPaths {
				c.Focused++
			}
		}
		if c.Focused >= minIPs {
			out = append(out, *c)
		}
	}
	slices.SortFunc(out, func(a, b candidate) int {
		if a.Focused != b.Focused {
			return b.Focused - a.Focused
		}
		if a.IPs != b.IPs {
			return b.IPs - a.IPs
		}
		return b.Count - a.Count
	})
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

// Package autoban blocks addresses that keep attacking: too many denied
// requests within a window, or one request of a dangerous class; and, from
// the access logs, too many pages not found, login attempts or requests
// (see access.go). Every
// new offence of the same address blocks it for longer (a day, a week,
// then for good). In dry-run mode it only records whom it would block.
// Traps ban whoever requests a path, whether the auto-ban is on or not.
package autoban

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"wafisp/internal/auth"
	"wafisp/internal/block"
	"wafisp/internal/event"
	"wafisp/internal/policy"
)

// Settings are edited in the panel and kept in autoban.json.
type Settings struct {
	Enabled bool `json:"enabled"`
	// DryRun records decisions without blocking.
	DryRun bool `json:"dry_run"`
	// Threshold denied requests from one address within Window.
	Threshold int           `json:"threshold"`
	Window    time.Duration `json:"window"`
	// Instant classes block on a single denied request with at least
	// InstantScore.
	Instant      []string `json:"instant"`
	InstantScore int      `json:"instant_score"`
	// Durations by offence: the first offence gets Durations[0], ...; the
	// last one repeats. 0 blocks until unblocked by hand.
	Durations []time.Duration `json:"durations"`
	// Memory is how long past offences count for escalation.
	Memory   time.Duration `json:"memory"`
	Backends []string      `json:"backends"`

	// Access-log rules, on and in dry run apart from the WAF rules. A
	// limit of 0 turns that rule off.
	AccessEnabled bool          `json:"access_enabled"`
	AccessDryRun  bool          `json:"access_dry_run"`
	AccessWindow  time.Duration `json:"access_window"`
	NotFound      int           `json:"not_found"` // 404s on pages (not images, styles, scripts) within AccessWindow
	Logins        int           `json:"logins"`    // POSTs to LoginPaths within AccessWindow
	Rate          int           `json:"rate"`      // requests within one minute
	LoginPaths    []string      `json:"login_paths"`
}

func Defaults() Settings {
	return Settings{
		DryRun: true, Threshold: 20, Window: 10 * time.Minute,
		Instant: []string{"rce", "webshell", "java"}, InstantScore: 10,
		Durations: []time.Duration{24 * time.Hour, 7 * 24 * time.Hour, 0},
		Memory:    90 * 24 * time.Hour, Backends: []string{"ipset"},
		AccessDryRun: true, AccessWindow: 5 * time.Minute, NotFound: 30, Logins: 10, Rate: 600,
		LoginPaths: slices.Clone(DefaultLoginPaths),
	}
}

func (s *Settings) Validate(backends []string) error {
	if s.Threshold < 2 || s.Threshold > 10000 {
		return fmt.Errorf("the threshold must be between 2 and 10000")
	}
	if s.Window < time.Minute || s.Window > 24*time.Hour {
		return fmt.Errorf("the window must be between 1 minute and 24 hours")
	}
	if len(s.Durations) == 0 || len(s.Durations) > 5 {
		return fmt.Errorf("give 1 to 5 block durations")
	}
	for _, d := range s.Durations {
		if d < 0 || (d > 0 && d < time.Minute) {
			return fmt.Errorf("a block duration must be at least 1 minute, or 0 for permanent")
		}
	}
	if s.InstantScore < 0 {
		return fmt.Errorf("the instant score cannot be negative")
	}
	for _, c := range s.Instant {
		if event.CategoryName(c) == c {
			return fmt.Errorf("unknown class %q", c)
		}
	}
	if len(s.Backends) == 0 {
		return fmt.Errorf("choose at least one way to block")
	}
	for _, b := range s.Backends {
		if !slices.Contains(backends, b) {
			return fmt.Errorf("unknown backend %q", b)
		}
	}
	if s.Memory < 24*time.Hour {
		s.Memory = 90 * 24 * time.Hour
	}
	return validateAccess(s)
}

// Decision is one address the engine blocked or would block.
type Decision struct {
	IP       string        `json:"ip"`
	Site     string        `json:"site"`
	At       time.Time     `json:"at"`
	Offence  int           `json:"offence"` // 1 for the first
	Duration time.Duration `json:"duration"`
	Reason   string        `json:"reason"`
	DryRun   bool          `json:"dry_run"`
	// Rule is the rule that fired; Rule.Trap is set for a trap.
	Rule block.Rule `json:"rule"`
	// Result is "blocked", "would block", "skipped: ..." or an error.
	Result  string        `json:"result"`
	Samples []event.Event `json:"-"`
}

// state is what survives a restart.
type state struct {
	Settings  Settings               `json:"settings"`
	Offences  map[string][]time.Time `json:"offences"`
	Decisions []Decision             `json:"decisions"`
	TrapHits  map[int]TrapHits       `json:"trap_hits,omitempty"`
}

// TrapHits counts the requests that fell into one trap.
type TrapHits struct {
	Hits int       `json:"hits"`
	Last time.Time `json:"last"`
}

type Engine struct {
	File string
	// Traps returns the current traps; nil means none.
	Traps func() []policy.Trap

	mu     sync.Mutex
	st     state
	recent map[string][]event.Event // denied events per address within the window
	// trapSeen is when an address last fell into a trap ("id ip"): one
	// decision per address and trap an hour.
	trapSeen map[string]time.Time
	// access is what each address did lately by the access logs;
	// accessSeen is when it last got an access-log decision.
	access     map[string]*accessWin
	accessSeen map[string]time.Time
}

func Open(file string) (*Engine, error) {
	e := &Engine{File: file, recent: map[string][]event.Event{}, trapSeen: map[string]time.Time{},
		access: map[string]*accessWin{}, accessSeen: map[string]time.Time{}}
	e.st = state{Settings: Defaults(), Offences: map[string][]time.Time{}}
	b, err := os.ReadFile(file)
	if err == nil {
		if err := json.Unmarshal(b, &e.st); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if e.st.Offences == nil {
		e.st.Offences = map[string][]time.Time{}
	}
	if e.st.TrapHits == nil {
		e.st.TrapHits = map[int]TrapHits{}
	}
	return e, nil
}

func (e *Engine) save() error {
	b, err := json.MarshalIndent(e.st, "", "  ")
	if err != nil {
		return err
	}
	return auth.WriteFileAtomic(e.File, b, 0o600)
}

func (e *Engine) Settings() Settings {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.st.Settings
}

// SetSettings replaces the settings; the windows start over.
func (e *Engine) SetSettings(s Settings) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.st.Settings = s
	clear(e.recent)
	clear(e.access)
	clear(e.accessSeen)
	return e.save()
}

// Decisions returns the latest decisions, newest first.
func (e *Engine) Decisions() []Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := slices.Clone(e.st.Decisions)
	slices.Reverse(out)
	return out
}

// Offences is how many times ip was banned within the memory.
func (e *Engine) Offences(ip string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.st.Offences[ip])
}

// Process feeds one live event; it returns a decision when the address
// crossed the line. The caller applies it and reports back with Record.
func (e *Engine) Process(ev event.Event) *Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.st.Settings
	now := ev.Time
	if now.IsZero() {
		now = time.Now()
	}
	if d := e.trap(ev, now); d != nil || ev.SrcIP == "" {
		return d
	}
	if !s.Enabled || !ev.Denied {
		return nil
	}
	var reason string
	var rule block.Rule
	if slices.Contains(s.Instant, ev.Category) && ev.Score >= s.InstantScore {
		reason = fmt.Sprintf("%s (score %d, rule %s) on %s%s", event.CategoryName(ev.Category), ev.Score, ev.RuleID(), ev.Host, ev.Path())
		rule = block.Rule{Kind: "instant", Class: ev.Category, Score: s.InstantScore}
		e.recent[ev.SrcIP] = append(e.recent[ev.SrcIP], ev)
	} else {
		list := append(e.recent[ev.SrcIP], ev)
		cut := now.Add(-s.Window)
		i := 0
		for i < len(list) && list[i].Time.Before(cut) {
			i++
		}
		list = list[i:]
		e.recent[ev.SrcIP] = list
		if len(list) < s.Threshold {
			e.gc(now, s.Window)
			return nil
		}
		sites := map[string]bool{}
		for _, x := range list {
			sites[x.Site] = true
		}
		reason = fmt.Sprintf("%d denied requests in %s on %d site(s)", len(list), s.Window, len(sites))
		rule = block.Rule{Kind: "threshold", Count: s.Threshold, WindowMin: int(s.Window / time.Minute)}
	}
	samples := e.recent[ev.SrcIP]
	if len(samples) > 5 {
		samples = samples[len(samples)-5:]
	}
	delete(e.recent, ev.SrcIP)

	// Escalation: offences within the memory, this one included.
	n := e.offence(ev.SrcIP, now)
	d := s.Durations[min(n-1, len(s.Durations)-1)]
	rule.Offence = n
	return &Decision{IP: ev.SrcIP, Site: ev.Site, At: now, Offence: n, Duration: d, Reason: reason,
		DryRun: s.DryRun, Rule: rule, Samples: slices.Clone(samples)}
}

// offence is the number the next ban of ip would get within the memory.
func (e *Engine) offence(ip string, now time.Time) int {
	mem := e.st.Settings.Memory
	past := slices.DeleteFunc(slices.Clone(e.st.Offences[ip]), func(t time.Time) bool { return now.Sub(t) > mem })
	return len(past) + 1
}

// trap returns a decision when ev fell into a trap: any request, denied
// or not, whether the auto-ban is on or not.
func (e *Engine) trap(ev event.Event, now time.Time) *Decision {
	if e.Traps == nil || ev.SrcIP == "" {
		return nil
	}
	for _, t := range e.Traps() {
		if !t.Matches(ev.Site, ev.Path()) {
			continue
		}
		h := e.st.TrapHits[t.ID]
		h.Hits++
		h.Last = now
		e.st.TrapHits[t.ID] = h
		key := fmt.Sprint(t.ID, " ", ev.SrcIP)
		if last, ok := e.trapSeen[key]; ok && now.Sub(last) < time.Hour {
			return nil
		}
		e.trapSeen[key] = now
		if len(e.trapSeen) > 10000 {
			for k, at := range e.trapSeen {
				if now.Sub(at) > time.Hour {
					delete(e.trapSeen, k)
				}
			}
		}
		n := e.offence(ev.SrcIP, now)
		return &Decision{IP: ev.SrcIP, Site: ev.Site, At: now, Offence: n, Duration: t.Duration, DryRun: t.DryRun,
			Reason:  fmt.Sprintf("trap %d: %s %s%s", t.ID, ev.Method, ev.Host, ev.Path()),
			Rule:    block.Rule{Kind: "trap", Trap: t.ID, Site: t.Site, Path: t.Path, Match: t.Match, Offence: n},
			Samples: []event.Event{ev}}
	}
	return nil
}

// TrapHits returns the hit counters of the traps.
func (e *Engine) TrapHits() map[int]TrapHits {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[int]TrapHits, len(e.st.TrapHits))
	for k, v := range e.st.TrapHits {
		out[k] = v
	}
	return out
}

// Record keeps a decision and, when it blocked, counts the offence.
func (e *Engine) Record(d Decision) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if d.Result == "blocked" {
		past := slices.DeleteFunc(e.st.Offences[d.IP], func(t time.Time) bool { return d.At.Sub(t) > e.st.Settings.Memory })
		e.st.Offences[d.IP] = append(past, d.At)
	}
	e.st.Decisions = append(e.st.Decisions, d)
	if len(e.st.Decisions) > 300 {
		e.st.Decisions = slices.Clone(e.st.Decisions[len(e.st.Decisions)-300:])
	}
	return e.save()
}

// gc drops addresses whose window has passed, at most once a minute.
func (e *Engine) gc(now time.Time, window time.Duration) {
	if len(e.recent) < 10000 {
		return
	}
	for ip, list := range e.recent {
		if len(list) == 0 || now.Sub(list[len(list)-1].Time) > window {
			delete(e.recent, ip)
		}
	}
}

// Package rules turns events into alerts by filters, thresholds and cooldowns.
package rules

import (
	"crypto/rand"
	"encoding/hex"
	"path"
	"slices"
	"strings"
	"time"

	"wafisp/internal/config"
	"wafisp/internal/event"
)

// maxSamples bounds how many events an alert carries for the message.
const maxSamples = 5

type Alert struct {
	// ID identifies the alert in the history and delivery results.
	ID       string
	Rule     string
	Severity string
	Channels []string
	GroupBy  string
	GroupKey string
	Count    int
	Window   time.Duration
	First    time.Time
	Last     time.Time
	Denied   int
	Passed   int
	Hosts    []string
	Types    []string
	Samples  []event.Event
	// Note replaces the generated text: notices of the panel itself
	// (auto-bans, problems with its rules) rather than rule matches.
	Note string
}

type group struct {
	events    []event.Event
	lastAlert time.Time
}

type rule struct {
	cfg    config.Rule
	groups map[string]*group
}

type Engine struct {
	rules  []*rule
	lastGC time.Time
	// now is replaceable in tests.
	now func() time.Time
}

func New(cfg []config.Rule) *Engine {
	e := &Engine{now: time.Now}
	for _, r := range cfg {
		if !r.Disabled {
			e.rules = append(e.rules, &rule{cfg: r, groups: map[string]*group{}})
		}
	}
	return e
}

// Process feeds one event to every rule and returns the alerts it fires.
// It is not safe for concurrent use.
func (e *Engine) Process(ev event.Event) []Alert {
	if ev.Time.IsZero() {
		ev.Time = e.now()
	}
	ts := ev.Time
	var out []Alert
	for _, r := range e.rules {
		if !r.match(ev) {
			continue
		}
		key := r.key(ev)
		g := r.groups[key]
		if g == nil {
			g = &group{}
			r.groups[key] = g
		}
		g.events = append(g.events, ev)
		if r.cfg.Threshold > 1 {
			cut := ts.Add(-r.cfg.Window.D())
			i := 0
			for i < len(g.events) && eventTime(g.events[i]).Before(cut) {
				i++
			}
			g.events = g.events[i:]
		}
		if len(g.events) < r.cfg.Threshold {
			continue
		}
		if !g.lastAlert.IsZero() && ts.Sub(g.lastAlert) < r.cfg.Cooldown.D() {
			// Keep counting quietly; the window above trims the slice.
			if r.cfg.Threshold == 1 {
				g.events = g.events[:0]
			}
			continue
		}
		out = append(out, r.alert(key, g.events))
		g.lastAlert = ts
		g.events = g.events[:0]
	}
	e.gc(ts)
	return out
}

// gc drops groups that are idle for longer than their window and cooldown.
func (e *Engine) gc(now time.Time) {
	if now.Sub(e.lastGC) < time.Minute {
		return
	}
	e.lastGC = now
	for _, r := range e.rules {
		keep := max(r.cfg.Window.D(), r.cfg.Cooldown.D())
		for k, g := range r.groups {
			last := g.lastAlert
			if n := len(g.events); n > 0 {
				last = maxTime(last, eventTime(g.events[n-1]))
			}
			if now.Sub(last) > keep {
				delete(r.groups, k)
			}
		}
	}
}

func (r *rule) match(ev event.Event) bool {
	c := r.cfg
	if len(c.Sites) > 0 && !slices.Contains(c.Sites, ev.Site) {
		return false
	}
	if len(c.Categories) > 0 && !slices.Contains(c.Categories, ev.Category) {
		return false
	}
	if ev.Score < c.MinScore {
		return false
	}
	if len(c.Actions) > 0 && !slices.Contains(c.Actions, ev.ActionName()) {
		return false
	}
	if ev.Risk() < c.MinRisk {
		return false
	}
	if len(c.Hosts) > 0 {
		host := strings.ToLower(ev.Host)
		ok := false
		for _, h := range c.Hosts {
			if m, _ := path.Match(strings.ToLower(h), host); m {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (r *rule) key(ev event.Event) string {
	switch r.cfg.GroupBy {
	case "host":
		return ev.Host
	case "site":
		return ev.Site
	case "none":
		return ""
	default:
		return ev.SrcIP
	}
}

func (r *rule) alert(key string, evs []event.Event) Alert {
	a := Alert{
		ID:       newID(),
		Rule:     r.cfg.Name,
		Severity: r.cfg.Severity,
		Channels: r.cfg.Channels,
		GroupBy:  r.cfg.GroupBy,
		GroupKey: key,
		Count:    len(evs),
		Window:   r.cfg.Window.D(),
		First:    eventTime(evs[0]),
		Last:     eventTime(evs[len(evs)-1]),
	}
	for _, ev := range evs {
		if ev.Denied {
			a.Denied++
		} else {
			a.Passed++
		}
		if ev.Host != "" && !slices.Contains(a.Hosts, ev.Host) {
			a.Hosts = append(a.Hosts, ev.Host)
		}
		if !slices.Contains(a.Types, ev.Category) {
			a.Types = append(a.Types, ev.Category)
		}
	}
	// The newest events are the most useful samples.
	start := max(0, len(evs)-maxSamples)
	a.Samples = slices.Clone(evs[start:])
	return a
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func eventTime(ev event.Event) time.Time { return ev.Time }

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

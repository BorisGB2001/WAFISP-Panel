package autoban

import (
	"path/filepath"
	"testing"
	"time"

	"wafisp/internal/event"
)

var t0 = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

func ev(sec int, ip, cat string, score int, denied bool) event.Event {
	return event.Event{SrcIP: ip, Site: "shop.example", Host: "shop.example", URI: "/x", Category: cat, Score: score,
		Denied: denied, Time: t0.Add(time.Duration(sec) * time.Second)}
}

func open(t *testing.T) *Engine {
	e, err := Open(filepath.Join(t.TempDir(), "autoban.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := Defaults()
	s.Enabled, s.DryRun, s.Threshold, s.Window = true, false, 3, time.Minute
	if err := s.Validate([]string{"ipset"}); err != nil {
		t.Fatal(err)
	}
	e.SetSettings(s)
	return e
}

func TestThresholdAndEscalation(t *testing.T) {
	e := open(t)
	// Passed requests and requests outside the window do not count.
	for _, x := range []event.Event{ev(0, "203.0.113.1", "lfi", 5, true), ev(1, "203.0.113.1", "lfi", 5, false), ev(90, "203.0.113.1", "lfi", 5, true)} {
		if d := e.Process(x); d != nil {
			t.Fatalf("early decision %+v", d)
		}
	}
	e.Process(ev(91, "203.0.113.1", "lfi", 5, true))
	d := e.Process(ev(92, "203.0.113.1", "lfi", 5, true))
	if d == nil || d.Offence != 1 || d.Duration != 24*time.Hour {
		t.Fatalf("first offence %+v", d)
	}
	d.Result = "blocked"
	e.Record(*d)
	// The window starts over after a decision.
	if d := e.Process(ev(93, "203.0.113.1", "lfi", 5, true)); d != nil {
		t.Fatal("decision right after a ban")
	}
	e.Process(ev(94, "203.0.113.1", "lfi", 5, true))
	d = e.Process(ev(95, "203.0.113.1", "lfi", 5, true))
	if d == nil || d.Offence != 2 || d.Duration != 7*24*time.Hour {
		t.Fatalf("second offence %+v", d)
	}
	d.Result = "blocked"
	e.Record(*d)
	for i := 0; i < 3; i++ {
		d = e.Process(ev(100+i, "203.0.113.1", "lfi", 5, true))
	}
	if d == nil || d.Offence != 3 || d.Duration != 0 {
		t.Fatalf("third offence should be permanent: %+v", d)
	}
	// Offences survive a restart.
	e2, _ := Open(e.File)
	if e2.Offences("203.0.113.1") != 2 {
		t.Fatalf("offences after reopen: %d", e2.Offences("203.0.113.1"))
	}
}

func TestInstantAndDryRun(t *testing.T) {
	e := open(t)
	if d := e.Process(ev(0, "203.0.113.2", "rce", 5, true)); d != nil {
		t.Fatal("instant class below the score")
	}
	d := e.Process(ev(1, "203.0.113.3", "rce", 15, true))
	if d == nil || d.DryRun {
		t.Fatalf("instant ban %+v", d)
	}
	s := e.Settings()
	s.DryRun = true
	e.SetSettings(s)
	d = e.Process(ev(2, "203.0.113.4", "webshell", 20, true))
	if d == nil || !d.DryRun {
		t.Fatalf("dry run %+v", d)
	}
	d.Result = "would block"
	e.Record(*d)
	if e.Offences("203.0.113.4") != 0 {
		t.Fatal("a dry-run decision counted as an offence")
	}
	s.Enabled = false
	e.SetSettings(s)
	if d := e.Process(ev(3, "203.0.113.5", "rce", 20, true)); d != nil {
		t.Fatal("decision while off")
	}
}

func TestValidate(t *testing.T) {
	for name, s := range map[string]Settings{
		"low threshold":   {Threshold: 1, Window: time.Minute, Durations: []time.Duration{time.Hour}, Backends: []string{"ipset"}},
		"no durations":    {Threshold: 5, Window: time.Minute, Backends: []string{"ipset"}},
		"unknown backend": {Threshold: 5, Window: time.Minute, Durations: []time.Duration{time.Hour}, Backends: []string{"pf"}},
		"unknown class":   {Threshold: 5, Window: time.Minute, Durations: []time.Duration{time.Hour}, Backends: []string{"ipset"}, Instant: []string{"nope"}},
	} {
		if s.Validate([]string{"ipset"}) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

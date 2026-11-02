package rules

import (
	"testing"
	"time"

	"wafisp/internal/config"
	"wafisp/internal/event"
)

var t0 = time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC)

var cats = []string{"sqli", "xss"}

func ev(sec int, ip string, typ int, action int) event.Event {
	return event.Event{Site: "shop.example.com", SrcIP: ip, Host: "shop.example.com", Category: cats[typ],
		Denied: action == 1, Score: 5, Time: t0.Add(time.Duration(sec) * time.Second)}
}

func TestThresholdPerIP(t *testing.T) {
	e := New([]config.Rule{{
		Name: "burst", Threshold: 3, Window: config.Duration(time.Minute),
		Cooldown: config.Duration(time.Minute), GroupBy: "src_ip", Channels: []string{"tg"},
	}})
	var fired []Alert
	for _, x := range []event.Event{
		ev(0, "1.1.1.1", 0, 1), ev(1, "2.2.2.2", 0, 1), ev(2, "1.1.1.1", 1, 1),
		ev(3, "1.1.1.1", 0, 0),                                                 // third from 1.1.1.1 -> alert
		ev(4, "1.1.1.1", 0, 1), ev(5, "1.1.1.1", 0, 1), ev(6, "1.1.1.1", 0, 1), // cooldown
	} {
		fired = append(fired, e.Process(x)...)
	}
	if len(fired) != 1 {
		t.Fatalf("want 1 alert, got %d", len(fired))
	}
	a := fired[0]
	if a.GroupKey != "1.1.1.1" || a.Count != 3 || a.Denied != 2 || a.Passed != 1 || len(a.Types) != 2 {
		t.Fatalf("unexpected alert %+v", a)
	}
}

func TestWindowExpires(t *testing.T) {
	e := New([]config.Rule{{
		Name: "burst", Threshold: 2, Window: config.Duration(10 * time.Second),
		Cooldown: config.Duration(10 * time.Second), GroupBy: "src_ip",
	}})
	if n := len(e.Process(ev(0, "1.1.1.1", 0, 1))) + len(e.Process(ev(30, "1.1.1.1", 0, 1))); n != 0 {
		t.Fatalf("events 30s apart fired %d alerts", n)
	}
	if n := len(e.Process(ev(35, "1.1.1.1", 0, 1))); n != 1 {
		t.Fatalf("want alert, got %d", n)
	}
}

func TestFilters(t *testing.T) {
	e := New([]config.Rule{{
		Name: "sqli-deny", Threshold: 1, Categories: []string{"sqli"}, Actions: []string{"deny"},
		Hosts: []string{"*.example.com"}, GroupBy: "none",
	}})
	if len(e.Process(ev(0, "1.1.1.1", 1, 1))) != 0 {
		t.Fatal("xss matched an sqli rule")
	}
	if len(e.Process(ev(1, "1.1.1.1", 0, 0))) != 0 {
		t.Fatal("pass matched a deny rule")
	}
	x := ev(2, "1.1.1.1", 0, 1)
	x.Host = "other.org"
	if len(e.Process(x)) != 0 {
		t.Fatal("foreign host matched")
	}
	if len(e.Process(ev(3, "1.1.1.1", 0, 1))) != 1 {
		t.Fatal("matching event did not fire")
	}
}

func TestEveryEventWithCooldown(t *testing.T) {
	e := New([]config.Rule{{Name: "any", Threshold: 1, Cooldown: config.Duration(time.Minute), GroupBy: "src_ip"}})
	n := 0
	for i := 0; i < 5; i++ {
		n += len(e.Process(ev(i, "1.1.1.1", 0, 1)))
	}
	n += len(e.Process(ev(61, "1.1.1.1", 0, 1)))
	if n != 2 {
		t.Fatalf("want 2 alerts, got %d", n)
	}
}

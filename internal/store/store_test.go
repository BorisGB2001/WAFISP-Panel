package store

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wafisp/internal/event"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := Open(dir, 30*24*time.Hour, log)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	mk := func(id string, at time.Time) *event.Event {
		return &event.Event{ID: id, Site: "a.example", Host: "a.example", Time: at, SrcIP: "203.0.113.1",
			URI: "/x?id=1", Category: "sqli", Score: 5, Denied: true,
			Rules: []event.Match{{ID: "942100", Var: "ARGS:id", Severity: 2}, {ID: "949110", Denied: true}}}
	}
	for _, e := range []*event.Event{mk("1", yesterday), mk("2", now), mk("3", now.Add(-time.Minute))} {
		if ok, err := s.Add(e); !ok || err != nil {
			t.Fatal(ok, err)
		}
	}
	if ok, _ := s.Add(mk("2", now)); ok {
		t.Fatal("duplicate stored")
	}
	var order []string
	s.Scan(time.Time{}, func(x *Summary) bool { order = append(order, x.ID); return true })
	if len(order) != 3 || order[0] != "2" || order[1] != "3" || order[2] != "1" {
		t.Fatalf("order %v", order)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir, 30*24*time.Hour, log)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 3 {
		t.Fatalf("reloaded %d", s2.Len())
	}
	ev, err := s2.Get("1")
	if err != nil || ev.Rules[0].Var != "ARGS:id" {
		t.Fatalf("get: %v %+v", err, ev)
	}
	var sum Summary
	s2.Scan(time.Time{}, func(x *Summary) bool { sum = *x; return true })
	if len(sum.Rules) != 1 || sum.Rules[0] != "942100" || sum.Path != "/x" {
		t.Fatalf("summary %+v", sum)
	}

	// Retention drops old days from disk and memory.
	old := filepath.Join(dir, "events", now.AddDate(0, 0, -40).Format(time.DateOnly)+".jsonl")
	os.WriteFile(old, []byte(`{"id":"old"}`+"\n"), 0o600)
	s2.Maintain(now.Add(36 * time.Hour))
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("old day kept")
	}
	s2.Close()
}

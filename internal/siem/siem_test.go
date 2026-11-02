package siem

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"wafisp/internal/config"
	"wafisp/internal/event"
	"wafisp/internal/stats"
)

func sample() event.Event {
	return event.Event{ID: "e1", Site: "shop.example.com", SrcIP: "203.0.113.5", Host: "shop.example.com", DstPort: 443,
		URI: "/a?x=1|2=3\nINJECT", Category: "sqli", Denied: true, Score: 10, Status: 403,
		Rules: []event.Match{{ID: "942100", Msg: `back\slash`, Severity: 2}, {ID: "949110", Denied: true}},
		Time:  time.UnixMilli(1793354400123)}
}

func TestCEFEscaping(t *testing.T) {
	got := CEF(sample())
	if !strings.HasPrefix(got, "CEF:0|OWASP|ModSecurity CRS|4|sqli|SQL Injection|8|") {
		t.Fatalf("bad header: %s", got)
	}
	for _, want := range []string{`request=/a?x\=1|2\=3\nINJECT`, `msg=back\\slash`, "rt=1793354400123", "act=deny", "src=203.0.113.5"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}
	if strings.Contains(got, "\n") {
		t.Error("raw newline in CEF")
	}
}

func TestJSONFormat(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal([]byte(JSON(sample(), false)), &m); err != nil {
		t.Fatal(err)
	}
	if m["category_name"] != "SQL Injection" || m["action"] != "deny" || m["site"] != "shop.example.com" || m["product"] != "modsecurity" || m["rule_id"] != "942100" || m["matches"] != nil {
		t.Fatalf("unexpected %v", m)
	}
}

func TestSyslogTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 2)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			got <- line
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.SIEM{Name: "t", Network: "tcp", Address: ln.Addr().String(), Format: "cef",
		Framing: "newline", Header: "rfc5424", Facility: 16, AppName: "wafisp", Hostname: "waf1", QueueSize: 10, OnlyDenied: true}
	s, err := NewSyslog(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), stats.New())
	if err != nil {
		t.Fatal(err)
	}
	s.Start(ctx)
	pass := sample()
	pass.Denied = false
	s.Enqueue(pass) // filtered by only_denied
	s.Enqueue(sample())

	select {
	case line := <-got:
		// local0 (16) * 8 + warning (4) = 132
		if !strings.HasPrefix(line, "<132>1 2026-") || !strings.Contains(line, " waf1 wafisp - waf-event - CEF:0|") {
			t.Fatalf("bad line %q", line)
		}
		if !strings.Contains(line, "externalId=e1") {
			t.Fatalf("wrong event sent: %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no syslog message received")
	}
	select {
	case line := <-got:
		t.Fatalf("filtered event was sent: %q", line)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestNoHeaderJSON(t *testing.T) {
	cfg := config.SIEM{Name: "w", Network: "tcp", Format: "json", Framing: "newline", Header: "none"}
	s, _ := NewSyslog(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), stats.New())
	line := string(s.message(sample()))
	if !strings.HasPrefix(line, `{"@timestamp":`) || !strings.HasSuffix(line, "}\n") {
		t.Fatalf("want bare JSON line, got %q", line)
	}
}

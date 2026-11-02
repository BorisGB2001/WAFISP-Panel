package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wafisp/internal/config"
	"wafisp/internal/event"
	"wafisp/internal/rules"
)

func alert() rules.Alert {
	now := time.Now()
	ev := event.Event{ID: "e1", Site: "shop.example.com", SrcIP: "203.0.113.5", Host: "shop.example.com", URI: "/login",
		Category: "sqli", Denied: true, Country: "NL", Time: now,
		Rules: []event.Match{{ID: "942100", Msg: "SQL Injection Attack Detected via libinjection", Severity: 2}}}
	return rules.Alert{Rule: "sqli", Severity: "critical", GroupBy: "src_ip", GroupKey: "203.0.113.5",
		Count: 12, Window: 5 * time.Minute, First: now, Last: now, Denied: 12,
		Hosts: []string{"shop.example.com"}, Types: []string{"sqli"}, Samples: []event.Event{ev}}
}

func TestText(t *testing.T) {
	txt := Text(alert())
	for _, want := range []string{"[WAF shop.example.com] SQL Injection — 12 events in 5m0s", "942100", "Source: 203.0.113.5 (NL)", "Blocked: 12"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q in:\n%s", want, txt)
		}
	}
}

func TestTelegram(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botTOKEN/sendMessage" {
			t.Errorf("path %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	tg := &Telegram{cfg: config.Telegram{BotToken: "TOKEN", ChatID: "-100", ThreadID: 7, APIURL: srv.URL}, hc: srv.Client()}
	if err := tg.Send(context.Background(), alert()); err != nil {
		t.Fatal(err)
	}
	if got["chat_id"] != "-100" || got["message_thread_id"].(float64) != 7 || !strings.Contains(got["text"].(string), "sqli") {
		t.Fatalf("unexpected body %v", got)
	}
}

func TestTelegramRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"ok":false,"description":"Too Many Requests","parameters":{"retry_after":3}}`))
	}))
	defer srv.Close()
	tg := &Telegram{cfg: config.Telegram{BotToken: "T", ChatID: "1", APIURL: srv.URL}, hc: srv.Client()}
	err := tg.Send(context.Background(), alert())
	ra, ok := err.(*RetryAfterError)
	if !ok || ra.After != 3*time.Second {
		t.Fatalf("want RetryAfterError 3s, got %v", err)
	}
}

func TestWebhookSigned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m := hmac.New(sha256.New, []byte("s3cret"))
		m.Write(body)
		if r.Header.Get("X-WAFISP-Signature") != "sha256="+hex.EncodeToString(m.Sum(nil)) {
			t.Error("bad signature")
		}
		if r.Header.Get("X-Team") != "sec" {
			t.Error("custom header missing")
		}
		var p WebhookPayload
		json.Unmarshal(body, &p)
		if p.Count != 12 || len(p.Events) != 1 || p.Events[0].Action != "deny" || p.Types[0] != "SQL Injection" {
			t.Errorf("payload %+v", p)
		}
	}))
	defer srv.Close()
	w := &Webhook{cfg: config.Webhook{URL: srv.URL, Format: "json", Secret: "s3cret", Headers: map[string]string{"X-Team": "sec"}}, hc: srv.Client()}
	if err := w.Send(context.Background(), alert()); err != nil {
		t.Fatal(err)
	}
}

func TestEmailBuild(t *testing.T) {
	e := &Email{cfg: config.Email{From: "waf@example.com", To: []string{"soc@example.com"}}}
	msg := string(e.build("Тема", "текст"))
	if !strings.Contains(msg, "Subject: =?utf-8?q?") || !strings.Contains(msg, "@example.com>") {
		t.Fatalf("bad message:\n%s", msg)
	}
}

package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"wafisp/internal/config"
	"wafisp/internal/event"
	"wafisp/internal/rules"
)

type Webhook struct {
	cfg config.Webhook
	hc  *http.Client
}

// WebhookPayload is the "json" format; it is a stable contract for receivers.
type WebhookPayload struct {
	Rule     string         `json:"rule"`
	Severity string         `json:"severity"`
	Title    string         `json:"title"`
	Text     string         `json:"text"`
	GroupBy  string         `json:"group_by"`
	GroupKey string         `json:"group_key"`
	Count    int            `json:"count"`
	Denied   int            `json:"denied"`
	Passed   int            `json:"passed"`
	First    time.Time      `json:"first"`
	Last     time.Time      `json:"last"`
	Hosts    []string       `json:"hosts"`
	Types    []string       `json:"attack_types"`
	Events   []WebhookEvent `json:"events"`
}

type WebhookEvent struct {
	Site     string    `json:"site"`
	EventID  string    `json:"event_id"`
	Time     time.Time `json:"time"`
	SrcIP    string    `json:"src_ip"`
	Host     string    `json:"host"`
	URL      string    `json:"url"`
	Category string    `json:"category"`
	RuleID   string    `json:"rule_id"`
	Message  string    `json:"message"`
	Score    int       `json:"anomaly_score"`
	Action   string    `json:"action"`
	Country  string    `json:"country,omitempty"`
}

func (w *Webhook) Send(ctx context.Context, a rules.Alert) error {
	var body any
	if w.cfg.Format == "slack" {
		// Slack, Mattermost and Rocket.Chat incoming webhooks accept this.
		body = map[string]string{"text": Text(a)}
	} else {
		p := WebhookPayload{
			Rule: a.Rule, Severity: a.Severity, Title: Subject(a), Text: Text(a),
			GroupBy: a.GroupBy, GroupKey: a.GroupKey, Count: a.Count,
			Denied: a.Denied, Passed: a.Passed, First: a.First, Last: a.Last, Hosts: a.Hosts,
		}
		for _, t := range a.Types {
			p.Types = append(p.Types, event.CategoryName(t))
		}
		for _, s := range a.Samples {
			p.Events = append(p.Events, WebhookEvent{
				Site: s.Site, EventID: s.ID, Time: s.Time, SrcIP: s.SrcIP, Host: s.Host, URL: s.URI,
				Category: s.Category, RuleID: s.RuleID(), Message: s.Reason(), Score: s.Score,
				Action: s.ActionName(), Country: s.Country,
			})
		}
		body = p
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.cfg.Headers {
		req.Header.Set(k, v)
	}
	if w.cfg.Secret != "" {
		m := hmac.New(sha256.New, []byte(w.cfg.Secret))
		m.Write(b)
		req.Header.Set("X-WAFISP-Signature", "sha256="+hex.EncodeToString(m.Sum(nil)))
	}
	resp, err := w.hc.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook: HTTP %d: %.200s", resp.StatusCode, raw)
	}
	return nil
}

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"wafisp/internal/config"
	"wafisp/internal/rules"
)

// telegramLimit is the Bot API limit for one message.
const telegramLimit = 4096

type Telegram struct {
	cfg config.Telegram
	hc  *http.Client
}

func (t *Telegram) Send(ctx context.Context, a rules.Alert) error {
	text := []rune(Text(a))
	if len(text) > telegramLimit {
		text = append(text[:telegramLimit-1], '…')
	}
	body := map[string]any{
		"chat_id":                  t.cfg.ChatID,
		"text":                     string(text),
		"disable_web_page_preview": true,
	}
	if t.cfg.ThreadID != 0 {
		body["message_thread_id"] = t.cfg.ThreadID
	}
	b, _ := json.Marshal(body)
	api := strings.TrimRight(t.cfg.APIURL, "/")
	if api == "" {
		api = "https://api.telegram.org"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+"/bot"+t.cfg.BotToken+"/sendMessage", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.hc.Do(req)
	if err != nil {
		// The URL carries the bot token; never let it reach the logs.
		return fmt.Errorf("telegram: %s", strings.ReplaceAll(err.Error(), t.cfg.BotToken, "***"))
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = json.Unmarshal(raw, &r)
	if resp.StatusCode == http.StatusTooManyRequests {
		return &RetryAfterError{After: time.Duration(r.Parameters.RetryAfter) * time.Second, Err: fmt.Errorf("telegram: rate limited")}
	}
	if resp.StatusCode != http.StatusOK || !r.OK {
		return fmt.Errorf("telegram: HTTP %d: %s", resp.StatusCode, r.Description)
	}
	return nil
}

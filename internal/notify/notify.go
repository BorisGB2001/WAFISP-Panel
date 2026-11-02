package notify

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"wafisp/internal/config"
	"wafisp/internal/rules"
	"wafisp/internal/stats"
)

type Sender interface {
	Send(ctx context.Context, a rules.Alert) error
}

// RetryAfterError lets a sender ask for a specific delay, e.g. Telegram 429.
type RetryAfterError struct {
	After time.Duration
	Err   error
}

func (e *RetryAfterError) Error() string { return e.Err.Error() }

func NewSender(ch config.Channel, hc *http.Client) (Sender, error) {
	switch ch.Type {
	case "telegram":
		return &Telegram{cfg: *ch.Telegram, hc: hc}, nil
	case "email":
		return &Email{cfg: *ch.Email}, nil
	case "webhook":
		return &Webhook{cfg: *ch.Webhook, hc: hc}, nil
	}
	return nil, fmt.Errorf("unknown channel type %q", ch.Type)
}

// ResultFunc receives the final delivery result of an alert on a channel.
type ResultFunc func(alertID, channel string, err error)

// Queue sends alerts of one channel in the background with retries, so a
// slow or broken channel does not hold back the others.
type Queue struct {
	Name   string
	Sender Sender
	Log    *slog.Logger
	Stats  *stats.Registry
	// Retries is the number of attempts after the first one.
	Retries int
	Backoff time.Duration
	// OnResult, when set, is called once per alert after the last attempt.
	OnResult ResultFunc

	ch chan rules.Alert
}

func (q *Queue) Start(ctx context.Context, size int) {
	q.ch = make(chan rules.Alert, size)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case a := <-q.ch:
				q.deliver(ctx, a)
			}
		}
	}()
}

// Enqueue never blocks; a full queue drops the alert and counts it.
func (q *Queue) Enqueue(a rules.Alert) {
	select {
	case q.ch <- a:
	default:
		q.Log.Error("alert queue full, alert dropped", "channel", q.Name, "rule", a.Rule)
		q.Stats.Add(fmt.Sprintf("alerts_dropped_total{channel=%q}", q.Name), 1)
		q.result(a, fmt.Errorf("channel queue is full"))
	}
}

func (q *Queue) deliver(ctx context.Context, a rules.Alert) {
	delay := q.Backoff
	for attempt := 0; ; attempt++ {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := q.Sender.Send(sctx, a)
		cancel()
		if err == nil {
			q.Stats.Add(fmt.Sprintf("alerts_sent_total{channel=%q}", q.Name), 1)
			q.result(a, nil)
			return
		}
		if attempt >= q.Retries || ctx.Err() != nil {
			q.Log.Error("alert not delivered", "channel", q.Name, "rule", a.Rule, "err", err)
			q.Stats.Add(fmt.Sprintf("alerts_failed_total{channel=%q}", q.Name), 1)
			q.result(a, err)
			return
		}
		wait := delay
		if ra, ok := err.(*RetryAfterError); ok && ra.After > 0 {
			wait = ra.After
		}
		q.Log.Warn("alert delivery failed, retrying", "channel", q.Name, "err", err, "in", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		delay *= 2
	}
}

func (q *Queue) result(a rules.Alert, err error) {
	if q.OnResult != nil {
		q.OnResult(a.ID, q.Name, err)
	}
}

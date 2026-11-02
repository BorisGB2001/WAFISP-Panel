// Package pipeline wires collectors, the rule engine, channels and SIEM targets.
package pipeline

import (
	"context"
	"log/slog"
	"sync"

	"wafisp/internal/config"
	"wafisp/internal/event"
	"wafisp/internal/rules"
	"wafisp/internal/siem"
)

type AlertSink interface {
	Enqueue(rules.Alert)
}

// Recorder keeps fired alerts, e.g. history.History.
type Recorder interface {
	Add(rules.Alert)
}

type Pipeline struct {
	Engine   *rules.Engine
	Channels map[string]AlertSink
	SIEM     []*siem.Syslog
	History  Recorder
	Log      *slog.Logger
	// DryRun logs alerts instead of sending them.
	DryRun bool

	once   sync.Once
	reload chan []config.Rule
}

func (p *Pipeline) init() {
	p.once.Do(func() { p.reload = make(chan []config.Rule, 1) })
}

// SetRules replaces the rule set. The engine is swapped by the Run
// goroutine, so in-flight thresholds and cooldowns start over.
func (p *Pipeline) SetRules(rs []config.Rule) {
	p.init()
	select {
	case <-p.reload: // drop a pending update that was not applied yet
	default:
	}
	p.reload <- rs
}

// Run consumes events until ctx ends. It is the only goroutine that touches
// the rule engine, which therefore needs no locking.
func (p *Pipeline) Run(ctx context.Context, events <-chan event.Event) {
	p.init()
	for {
		select {
		case <-ctx.Done():
			return
		case rs := <-p.reload:
			p.Engine = rules.New(rs)
			p.Log.Info("rules reloaded", "rules", len(rs))
		case ev := <-events:
			p.handle(ev)
		}
	}
}

func (p *Pipeline) handle(ev event.Event) {
	if !p.DryRun {
		for _, s := range p.SIEM {
			s.Enqueue(ev)
		}
	}
	for _, a := range p.Engine.Process(ev) {
		p.Log.Info("alert", "rule", a.Rule, "group", a.GroupKey, "count", a.Count, "channels", a.Channels)
		if p.DryRun {
			continue
		}
		if p.History != nil {
			p.History.Add(a)
		}
		for _, name := range a.Channels {
			if ch, ok := p.Channels[name]; ok {
				ch.Enqueue(a)
			}
		}
	}
}

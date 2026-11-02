package web

import (
	"sync"
	"time"
)

// Health is the result of the periodic self-check: problems with the
// panel's rules that an update of ISPmanager or nginx may cause.
type Health struct {
	mu       sync.Mutex
	problems []string
	at       time.Time
}

func (h *Health) Set(p []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.problems, h.at = p, time.Now()
}

func (h *Health) Problems() []string {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.problems
}

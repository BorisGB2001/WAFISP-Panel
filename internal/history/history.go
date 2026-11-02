// Package history keeps fired alerts and their delivery results.
package history

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"

	"wafisp/internal/event"
	"wafisp/internal/notify"
	"wafisp/internal/rules"
)

type Entry struct {
	ID       string            `json:"id"`
	Time     time.Time         `json:"time"`
	Rule     string            `json:"rule"`
	Severity string            `json:"severity"`
	Title    string            `json:"title"`
	Text     string            `json:"text"`
	GroupKey string            `json:"group_key"`
	Count    int               `json:"count"`
	Denied   int               `json:"denied"`
	Passed   int               `json:"passed"`
	Hosts    []string          `json:"hosts"`
	Types    []string          `json:"types"`
	Delivery map[string]string `json:"delivery"` // channel -> "queued" | "ok" | error text
}

// History is an in-memory ring of recent alerts mirrored to a JSON lines
// file. Delivery updates are appended as new lines for the same id; the
// newest line wins when the file is read back.
type History struct {
	path string
	keep int
	mu   sync.Mutex
	list []*Entry
	byID map[string]*Entry
}

func Open(path string, keep int) (*History, error) {
	h := &History{path: path, keep: keep, byID: map[string]*Entry{}}
	lines := 0
	f, err := os.Open(path)
	if err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			lines++
			var e Entry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				h.put(&e)
			}
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// Delivery updates and trimmed entries make the file grow; rewrite it
	// with what is kept once it is much larger than needed.
	if lines > 3*keep {
		var buf []byte
		for _, e := range h.list {
			b, _ := json.Marshal(e)
			buf = append(append(buf, b...), '\n')
		}
		if err := os.WriteFile(path+".tmp", buf, 0o600); err == nil {
			os.Rename(path+".tmp", path)
		}
	}
	return h, nil
}

func (h *History) put(e *Entry) {
	if old, ok := h.byID[e.ID]; ok {
		*old = *e
		return
	}
	h.list = append(h.list, e)
	h.byID[e.ID] = e
	if len(h.list) > h.keep {
		delete(h.byID, h.list[0].ID)
		h.list = h.list[1:]
	}
}

// Add records a fired alert with every channel queued.
func (h *History) Add(a rules.Alert) {
	e := &Entry{
		ID: a.ID, Time: time.Now(), Rule: a.Rule, Severity: a.Severity,
		Title: notify.Subject(a), Text: notify.Text(a), GroupKey: a.GroupKey,
		Count: a.Count, Denied: a.Denied, Passed: a.Passed, Hosts: a.Hosts,
		Delivery: map[string]string{},
	}
	for _, t := range a.Types {
		e.Types = append(e.Types, event.CategoryName(t))
	}
	for _, c := range a.Channels {
		e.Delivery[c] = "queued"
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.put(e)
	h.appendLocked(e)
}

// Delivered records the result of one channel; it matches notify.ResultFunc.
func (h *History) Delivered(id, channel string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.byID[id]
	if e == nil {
		return
	}
	if err != nil {
		e.Delivery[channel] = err.Error()
	} else {
		e.Delivery[channel] = "ok"
	}
	h.appendLocked(e)
}

func (h *History) appendLocked(e *Entry) {
	b, _ := json.Marshal(e)
	f, err := os.OpenFile(h.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	f.Write(append(b, '\n'))
	f.Close()
}

// Recent returns copies of the newest entries first.
func (h *History) Recent(n int) []Entry {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Entry, 0, min(n, len(h.list)))
	for i := len(h.list) - 1; i >= 0 && len(out) < n; i-- {
		e := *h.list[i]
		e.Delivery = make(map[string]string, len(h.list[i].Delivery))
		for k, v := range h.list[i].Delivery {
			e.Delivery[k] = v
		}
		out = append(out, e)
	}
	return out
}

// Since counts alerts fired after t.
func (h *History) Since(t time.Time) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, e := range h.list {
		if e.Time.After(t) {
			n++
		}
	}
	return n
}

// Package stats keeps counters for /healthz and /metrics.
package stats

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

type Instance struct {
	LastPoll   time.Time `json:"last_poll"`
	LastOK     time.Time `json:"last_ok"`
	LastError  string    `json:"last_error,omitempty"`
	Cursor     int64     `json:"cursor"`
	Events     int64     `json:"events"`
	Skipped    int64     `json:"skipped_pages"`
	PollErrors int64     `json:"poll_errors"`
}

type Registry struct {
	mu        sync.Mutex
	started   time.Time
	instances map[string]*Instance
	counters  map[string]int64
}

func New() *Registry {
	return &Registry{started: time.Now(), instances: map[string]*Instance{}, counters: map[string]int64{}}
}

// Instance updates the stats of one instance under the lock.
func (r *Registry) Instance(id string, f func(*Instance)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	in := r.instances[id]
	if in == nil {
		in = &Instance{}
		r.instances[id] = in
	}
	f(in)
}

// Add increments a named counter such as "alerts_sent{channel=tg}".
func (r *Registry) Add(name string, n int64) {
	r.mu.Lock()
	r.counters[name] += n
	r.mu.Unlock()
}

// Healthy reports whether every instance was polled successfully within maxAge.
func (r *Registry) Healthy(maxAge time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, in := range r.instances {
		if time.Since(in.LastOK) > maxAge {
			return false
		}
	}
	return true
}

func (r *Registry) WriteJSON(w io.Writer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return json.NewEncoder(w).Encode(map[string]any{
		"started":   r.started,
		"instances": r.instances,
		"counters":  r.counters,
	})
}

// WritePrometheus writes the counters in the Prometheus text format.
func (r *Registry) WritePrometheus(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.instances))
	for id := range r.instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		in := r.instances[id]
		fmt.Fprintf(w, "wafisp_events_total{instance=%q} %d\n", id, in.Events)
		fmt.Fprintf(w, "wafisp_poll_errors_total{instance=%q} %d\n", id, in.PollErrors)
		fmt.Fprintf(w, "wafisp_last_ok_timestamp_seconds{instance=%q} %d\n", id, in.LastOK.Unix())
		fmt.Fprintf(w, "wafpanel_cursor{instance=%q} %d\n", id, in.Cursor)
	}
	names := make([]string, 0, len(r.counters))
	for n := range r.counters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "wafpanel_%s %d\n", n, r.counters[n])
	}
}

// Snapshot returns copies of the instance stats and counters.
func (r *Registry) Snapshot() (map[string]Instance, map[string]int64, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	in := make(map[string]Instance, len(r.instances))
	for k, v := range r.instances {
		in[k] = *v
	}
	c := make(map[string]int64, len(r.counters))
	for k, v := range r.counters {
		c[k] = v
	}
	return in, c, r.started
}

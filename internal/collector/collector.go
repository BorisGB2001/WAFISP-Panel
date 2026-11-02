// Package collector follows the ModSecurity audit logs of every site,
// like tail -f, and hands complete entries on as events.
package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"wafisp/internal/auth"
	"wafisp/internal/event"
	"wafisp/internal/modsec"
)

// Cursor is how far a log has been read: up to the end of the last
// complete entry. The file is identified by its inode.
type Cursor struct {
	Ino uint64 `json:"ino"`
	Off int64  `json:"off"`
}

// FileStat is the state of one log for the panel's health view.
type FileStat struct {
	Site     string
	Path     string
	Size     int64
	Off      int64
	Events   int64
	LastSeen time.Time // time of the newest event read
	Err      string
}

// Sink receives each event. live is false for events read on the first
// start (the backlog already on disk), which should not raise alerts.
type Sink func(ev *event.Event, live bool)

type Collector struct {
	// Glob of the audit logs, e.g. /var/www/httpd-logs/*.audit.log; the
	// site is the file name without the suffix.
	Glob     string
	Suffix   string
	State    string // cursors, JSON
	Interval time.Duration
	Log      *slog.Logger
	Sink     Sink
	// Flush makes what Sink wrote durable before the cursors move on.
	Flush func() error
	// OnPoll is called after every pass, for the health check.
	OnPoll func()

	mu      sync.Mutex
	cursors map[string]Cursor
	stats   map[string]*FileStat
}

// maxRead bounds one pass over a file; a backlog is read over several ticks.
const maxRead = 64 << 20

func (c *Collector) Run(ctx context.Context) {
	c.load()
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		c.Poll()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (c *Collector) load() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cursors = map[string]Cursor{}
	c.stats = map[string]*FileStat{}
	if b, err := os.ReadFile(c.State); err == nil {
		json.Unmarshal(b, &c.cursors)
	}
}

// Poll reads what was appended to every log since the last call.
func (c *Collector) Poll() {
	if c.cursors == nil {
		c.load()
	}
	files, err := filepath.Glob(c.Glob)
	if err != nil {
		c.Log.Error("collector: bad glob", "glob", c.Glob, "err", err)
		return
	}
	sort.Strings(files)
	if c.OnPoll != nil {
		defer c.OnPoll()
	}
	changed := false
	for _, f := range files {
		if c.follow(f) {
			changed = true
		}
	}
	if !changed {
		return
	}
	if c.Flush != nil {
		if err := c.Flush(); err != nil {
			c.Log.Error("collector: flush before saving cursors", "err", err)
			return
		}
	}
	c.save()
}

func (c *Collector) site(path string) string {
	return strings.TrimSuffix(filepath.Base(path), c.Suffix)
}

func (c *Collector) follow(path string) bool {
	site := c.site(path)
	c.mu.Lock()
	st := c.stats[path]
	if st == nil {
		st = &FileStat{Site: site, Path: path}
		c.stats[path] = st
	}
	cur, known := c.cursors[path]
	c.mu.Unlock()

	fi, err := os.Stat(path)
	if err != nil {
		c.setErr(st, err)
		return false
	}
	ino := inode(fi)
	if known && (cur.Ino != ino || fi.Size() < cur.Off) {
		// Replaced, or truncated in place by logrotate's copytruncate.
		cur = Cursor{Ino: ino}
	}
	cur.Ino = ino
	if fi.Size() == cur.Off {
		c.mu.Lock()
		st.Size, st.Off, st.Err = fi.Size(), cur.Off, ""
		c.mu.Unlock()
		if !known {
			c.mu.Lock()
			c.cursors[path] = cur
			c.mu.Unlock()
			return true
		}
		return false
	}

	var newest time.Time
	n, events, err := read(path, cur.Off, site, func(ev *event.Event) {
		if ev.Time.After(newest) {
			newest = ev.Time
		}
		c.Sink(ev, known)
	})
	cur.Off += n
	c.mu.Lock()
	c.cursors[path] = cur
	st.Size, st.Off, st.Events = fi.Size(), cur.Off, st.Events+int64(events)
	if newest.After(st.LastSeen) {
		st.LastSeen = newest
	}
	st.Err = ""
	if err != nil {
		st.Err = err.Error()
	}
	c.mu.Unlock()
	return true
}

func (c *Collector) setErr(st *FileStat, err error) {
	c.mu.Lock()
	st.Err = err.Error()
	c.mu.Unlock()
}

// read parses entries from off and returns how many bytes form complete
// entries: an entry still being written is read again next time.
func read(path string, off int64, site string, fn func(*event.Event)) (int64, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return 0, 0, err
	}
	r := bufio.NewReaderSize(f, 256<<10)
	p := &modsec.Parser{Site: site}
	var pos, done int64
	events := 0
	for pos < maxRead {
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return done, events, err
		}
		pos += int64(len(line))
		if ev := p.Feed(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")); ev != nil {
			fn(ev)
			events++
			done = pos
		}
	}
	if pos >= maxRead && done == 0 {
		// One entry larger than maxRead: skip it rather than stall.
		done = pos
	}
	return done, events, nil
}

func (c *Collector) save() {
	c.mu.Lock()
	b, err := json.MarshalIndent(c.cursors, "", "  ")
	c.mu.Unlock()
	if err == nil {
		err = auth.WriteFileAtomic(c.State, b, 0o600)
	}
	if err != nil {
		c.Log.Error("collector: save cursors", "err", err)
	}
}

// Files is the state of every log for the panel.
func (c *Collector) Files() []FileStat {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]FileStat, 0, len(c.stats))
	for _, st := range c.stats {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Site < out[j].Site })
	return out
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

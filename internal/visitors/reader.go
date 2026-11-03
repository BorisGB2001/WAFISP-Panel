package visitors

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"wafisp/internal/ua"
)

// Request is one line of an access log.
type Request struct {
	Time    time.Time
	IP      string
	Method  string
	Path    string // without the query
	Status  int
	Referer string
	Agent   string
}

// combined is nginx's "combined" format, which ISPmanager uses:
// ip - user [time] "request" status bytes "referer" "agent"
var combined = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) \S+ "([^"]*)" "([^"]*)"`)

// ParseLine reads one access log line.
func ParseLine(line string) (Request, bool) {
	m := combined.FindStringSubmatch(line)
	if m == nil {
		return Request{}, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
	if err != nil {
		return Request{}, false
	}
	r := Request{Time: t, IP: m[1], Referer: m[5], Agent: m[6]}
	r.Status, _ = strconv.Atoi(m[4])
	if f := strings.Fields(m[3]); len(f) >= 2 {
		r.Method, r.Path = f[0], f[1]
		if i := strings.IndexAny(r.Path, "?#"); i >= 0 {
			r.Path = r.Path[:i]
		}
		if len(r.Path) > 200 {
			r.Path = r.Path[:200]
		}
	}
	return r, true
}

var assetExt = map[string]bool{".css": true, ".js": true, ".mjs": true, ".map": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".webp": true, ".avif": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".otf": true, ".mp4": true, ".webm": true, ".mp3": true, ".json": true, ".xml": true, ".txt": true}

// isPage tells a page from an asset or an API call.
func isPage(r Request) bool {
	if r.Method != "GET" || r.Path == "" || r.Status >= 300 && r.Status != 304 {
		return false
	}
	return !assetExt[strings.ToLower(path.Ext(r.Path))]
}

// count adds one request to a.
func count(a *Agg, site string, r Request) {
	a.Requests++
	if r.Status > 0 {
		a.Status.add(strconv.Itoa(r.Status), false)
	}
	if r.Status == 404 && r.Path != "" {
		a.NotFound.add(r.Path, true)
	}
	c := ua.Parse(r.Agent)
	a.Kind.add(c.Kind, false)
	switch c.Kind {
	case ua.Bot:
		a.Bot.add(c.Name, false)
		return
	case ua.Script:
		a.Script.add(c.Name, false)
		return
	case ua.Empty:
		return
	}
	if !isPage(r) {
		return
	}
	a.Views++
	a.OS.add(c.OS, false)
	a.Browser.add(c.Browser, false)
	a.Device.add(c.Device, false)
	a.Page.add(r.Path, true)
	src := ua.RefererSource(r.Referer, site)
	a.Source.add(src.Kind, false)
	switch src.Kind {
	case ua.Search:
		a.Search.add(src.Name, false)
	case ua.Social:
		a.Social.add(src.Name, false)
	case ua.Other:
		a.Referrer.add(src.Domain, true)
	}
}

// cursor is how far a log was read.
type cursor struct {
	Ino uint64 `json:"ino"`
	Off int64  `json:"off"`
}

// Reader follows the access logs: every Every it reads what was appended,
// counts it into Store, writes Store and then its cursors, so a restart
// neither loses nor (beyond a crash between the two) recounts lines. A
// rotated or truncated log is read from its start.
type Reader struct {
	Glob      string
	Suffix    string // the site is the file name without it
	StateFile string
	Store     *Store
	Every     time.Duration
	Log       *slog.Logger

	mu      sync.Mutex
	cursors map[string]cursor
	files   map[string]FileStat
}

// FileStat is the state of one access log for the panel.
type FileStat struct {
	Site     string
	Size     int64
	Lines    int64
	LastSeen time.Time
	Err      string
}

// Run reads until ctx ends.
func (r *Reader) Run(ctx context.Context) {
	r.load()
	var expired time.Time
	for {
		r.Poll()
		if time.Since(expired) > 24*time.Hour {
			r.Store.Expire(time.Now())
			expired = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.Every):
		}
	}
}

func (r *Reader) load() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cursors, r.files = map[string]cursor{}, map[string]FileStat{}
	if b, err := os.ReadFile(r.StateFile); err == nil {
		json.Unmarshal(b, &r.cursors)
	}
}

// Poll reads every log once.
func (r *Reader) Poll() {
	if r.cursors == nil {
		r.load()
	}
	paths, _ := filepath.Glob(r.Glob)
	changed := false
	for _, p := range paths {
		site := strings.TrimSuffix(filepath.Base(p), r.Suffix)
		if r.readFile(p, site) {
			changed = true
		}
	}
	if !changed {
		return
	}
	if err := r.Store.Flush(); err != nil {
		if r.Log != nil {
			r.Log.Error("visitors: write summaries", "err", err)
		}
		return // keep the cursors: the lines are read again next time
	}
	r.mu.Lock()
	b, _ := json.MarshalIndent(r.cursors, "", "  ")
	r.mu.Unlock()
	tmp := r.StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		os.Rename(tmp, r.StateFile)
	}
}

// readFile reads what was appended to one log; it reports whether
// anything was counted.
func (r *Reader) readFile(p, site string) bool {
	r.mu.Lock()
	cur, known := r.cursors[p]
	st := r.files[p]
	r.mu.Unlock()
	st.Site = site
	defer func() { r.mu.Lock(); r.files[p] = st; r.mu.Unlock() }()

	fi, err := os.Stat(p)
	if err != nil {
		st.Err = err.Error()
		return false
	}
	st.Size, st.Err = fi.Size(), ""
	ino := inode(fi)
	if known && (cur.Ino != ino || fi.Size() < cur.Off) {
		cur = cursor{Ino: ino} // rotated or truncated
	}
	cur.Ino = ino
	if fi.Size() == cur.Off {
		r.mu.Lock()
		r.cursors[p] = cur
		r.mu.Unlock()
		return false
	}
	f, err := os.Open(p)
	if err != nil {
		st.Err = err.Error()
		return false
	}
	defer f.Close()
	if _, err := f.Seek(cur.Off, io.SeekStart); err != nil {
		st.Err = err.Error()
		return false
	}
	br := bufio.NewReaderSize(f, 64<<10)
	n := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			// A line without its newline is still being written: leave it.
			if !errors.Is(err, io.EOF) {
				st.Err = err.Error()
			}
			break
		}
		cur.Off += int64(len(line))
		if req, ok := ParseLine(line); ok {
			r.Store.Add(site, req)
			n++
			if req.Time.After(st.LastSeen) {
				st.LastSeen = req.Time
			}
		}
	}
	st.Lines += int64(n)
	r.mu.Lock()
	r.cursors[p] = cur
	r.mu.Unlock()
	return n > 0
}

// Files is the state of every log, for the panel.
func (r *Reader) Files() []FileStat {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]FileStat, 0, len(r.files))
	for _, f := range r.files {
		out = append(out, f)
	}
	return out
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

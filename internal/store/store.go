// Package store keeps WAF events on disk, one JSON line per event in a
// file per day, and a compact summary of every event in memory for the
// attack log, statistics and the dashboard.
//
// The day being written is plain events/YYYY-MM-DD.jsonl; earlier days are
// gzipped. A detail view reads the full event back from its day file.
package store

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"wafisp/internal/event"
	"wafisp/internal/ua"
)

// Summary is what the store keeps of an event in memory.
type Summary struct {
	ID       string
	Site     string
	Host     string
	Time     time.Time
	SrcIP    string
	Method   string
	Path     string
	Status   int
	Denied   bool
	Score    int
	Category string
	Rules    []string
	// Top is the rule that tells most about the event (event.Top).
	Top string
	// RVars is the variable each rule of Rules matched ("" when none).
	RVars   []string
	Reason  string
	Country string
	// Vars are the variables the attack rules matched (ARGS:q, ...).
	Vars []string
	// Client is what sent the request, from its User-Agent: kind and label
	// ("bot", "Googlebot"; "script", "curl"; "browser", "Chrome · Windows").
	ClientKind, Client string
}

const maxPath = 300

type Store struct {
	Dir       string
	Retention time.Duration
	Log       *slog.Logger

	mu     sync.RWMutex
	events []Summary // oldest first
	ids    map[string]struct{}
	intern map[string]string
	msgs   map[string]string // rule id -> message

	day string
	f   *os.File
	w   *bufio.Writer
}

// Open loads the summaries of the retention period.
func Open(dir string, retention time.Duration, log *slog.Logger) (*Store, error) {
	s := &Store{Dir: filepath.Join(dir, "events"), Retention: retention, Log: log,
		ids: map[string]struct{}{}, intern: map[string]string{}, msgs: map[string]string{}}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	days, err := s.days()
	if err != nil {
		return nil, err
	}
	cut := time.Now().Add(-retention).Format(time.DateOnly)
	for _, d := range days {
		if d.date < cut {
			continue
		}
		err := readDay(d.path, func(ev *event.Event) bool {
			s.add(ev)
			return true
		})
		if err != nil {
			log.Warn("store: day file damaged, read what was readable", "file", d.path, "err", err)
		}
	}
	slices.SortStableFunc(s.events, func(a, b Summary) int { return a.Time.Compare(b.Time) })
	return s, nil
}

type dayFile struct{ date, path string }

func (s *Store) days() ([]dayFile, error) {
	es, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []dayFile
	for _, e := range es {
		n := e.Name()
		date, ok := strings.CutSuffix(n, ".jsonl")
		if !ok {
			date, ok = strings.CutSuffix(n, ".jsonl.gz")
		}
		if ok && len(date) == 10 {
			out = append(out, dayFile{date, filepath.Join(s.Dir, n)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

func (s *Store) str(v string) string {
	if x, ok := s.intern[v]; ok {
		return x
	}
	if len(s.intern) > 500_000 {
		clear(s.intern)
	}
	s.intern[v] = v
	return v
}

// add keeps the summary; it reports false for an event already stored.
func (s *Store) add(ev *event.Event) bool {
	if _, ok := s.ids[ev.ID]; ok {
		return false
	}
	s.ids[ev.ID] = struct{}{}
	p := ev.Path()
	if len(p) > maxPath {
		p = p[:maxPath]
	}
	sum := Summary{
		ID: ev.ID, Site: s.str(ev.Site), Host: s.str(ev.Host), Time: ev.Time, SrcIP: s.str(ev.SrcIP),
		Method: s.str(ev.Method), Path: p, Status: ev.Status, Denied: ev.Denied, Score: ev.Score,
		Category: s.str(ev.Category), Reason: s.str(ev.Reason()), Country: s.str(ev.Country),
		Top: s.str(ev.RuleID()),
	}
	c := ua.Parse(ev.Header("User-Agent"))
	sum.ClientKind, sum.Client = c.Kind, s.str(c.Label())
	for _, m := range ev.Rules {
		if event.Evaluation(m.ID) {
			continue
		}
		sum.Rules = append(sum.Rules, s.str(m.ID))
		sum.RVars = append(sum.RVars, s.str(m.Var))
		if _, ok := s.msgs[m.ID]; !ok && m.Msg != "" {
			s.msgs[m.ID] = s.str(m.Msg)
		}
		if m.Var != "" && !slices.Contains(sum.Vars, m.Var) && len(sum.Vars) < 8 {
			sum.Vars = append(sum.Vars, s.str(m.Var))
		}
	}
	s.events = append(s.events, sum)
	return true
}

// Add writes ev to its day file and keeps its summary. It reports false
// when the event was stored before (a re-read after a crash).
func (s *Store) Add(ev *event.Event) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ids[ev.ID]; ok {
		return false, nil
	}
	if err := s.write(ev); err != nil {
		return false, err
	}
	s.add(ev)
	// Events of several files arrive slightly out of order.
	if n := len(s.events); n > 1 && s.events[n-1].Time.Before(s.events[n-2].Time) {
		i := sort.Search(n-1, func(i int) bool { return s.events[i].Time.After(s.events[n-1].Time) })
		last := s.events[n-1]
		copy(s.events[i+1:], s.events[i:n-1])
		s.events[i] = last
	}
	return true, nil
}

func (s *Store) write(ev *event.Event) error {
	day := ev.Time.Local().Format(time.DateOnly)
	if day < s.day {
		// A late event of a day already closed: append to that file only
		// while it is still plain.
		return s.appendTo(day, ev)
	}
	if day != s.day || s.f == nil {
		if err := s.rotate(day); err != nil {
			return err
		}
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	s.w.Write(b)
	s.w.WriteByte('\n')
	return nil
}

func (s *Store) appendTo(day string, ev *event.Event) error {
	path := filepath.Join(s.Dir, day+".jsonl")
	if _, err := os.Stat(path); err != nil {
		return s.writeHere(ev) // the day is compressed: keep it in today's file
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(ev)
	_, err = f.Write(append(b, '\n'))
	return err
}

func (s *Store) writeHere(ev *event.Event) error {
	b, _ := json.Marshal(ev)
	s.w.Write(b)
	return s.w.WriteByte('\n')
}

// rotate opens the file of day, closing and compressing the previous one.
func (s *Store) rotate(day string) error {
	prev := s.day
	if s.f != nil {
		s.w.Flush()
		s.f.Close()
		s.f = nil
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, day+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	s.f, s.w, s.day = f, bufio.NewWriterSize(f, 64<<10), day
	if prev != "" && prev != day {
		go s.compress(filepath.Join(s.Dir, prev+".jsonl"))
	}
	return nil
}

// Flush writes buffered events to disk.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return nil
	}
	if err := s.w.Flush(); err != nil {
		return err
	}
	return s.f.Sync()
}

func (s *Store) Close() error {
	err := s.Flush()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		s.f.Close()
		s.f = nil
	}
	return err
}

func (s *Store) compress(path string) {
	if err := gzipFile(path); err != nil && s.Log != nil {
		s.Log.Warn("store: compress failed", "file", path, "err", err)
	}
}

func gzipFile(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := path + ".gz.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := zw.Close(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path+".gz"); err != nil {
		return err
	}
	return os.Remove(path)
}

// Maintain compresses closed days left plain and deletes days past the
// retention, then drops their summaries.
func (s *Store) Maintain(now time.Time) {
	days, err := s.days()
	if err != nil {
		return
	}
	s.mu.RLock()
	today := s.day
	s.mu.RUnlock()
	cut := now.Add(-s.Retention).Format(time.DateOnly)
	for _, d := range days {
		switch {
		case d.date < cut:
			os.Remove(d.path)
		case strings.HasSuffix(d.path, ".jsonl") && d.date != today && d.date < now.Format(time.DateOnly):
			s.compress(d.path)
		}
	}
	limit := now.Add(-s.Retention)
	s.mu.Lock()
	i := sort.Search(len(s.events), func(i int) bool { return !s.events[i].Time.Before(limit) })
	for _, e := range s.events[:i] {
		delete(s.ids, e.ID)
	}
	s.events = slices.Clone(s.events[i:])
	s.mu.Unlock()
}

func readDay(path string, fn func(*event.Event) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var ev event.Event
		if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.ID == "" {
			continue
		}
		if !fn(&ev) {
			return nil
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return err
	}
	return nil
}

// Get reads the full event back from disk.
func (s *Store) Get(id string) (*event.Event, error) {
	s.mu.RLock()
	var at time.Time
	found := false
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].ID == id {
			at, found = s.events[i].Time, true
			break
		}
	}
	s.mu.RUnlock()
	if !found {
		return nil, fmt.Errorf("event %s not found", id)
	}
	if err := s.Flush(); err != nil {
		return nil, err
	}
	day := at.Local().Format(time.DateOnly)
	// The event may sit in a later file (late events go to the open day).
	days, _ := s.days()
	for _, d := range days {
		if d.date < day {
			continue
		}
		var out *event.Event
		readDay(d.path, func(ev *event.Event) bool {
			if ev.ID == id {
				out = ev
				return false
			}
			return true
		})
		if out != nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("event %s not found on disk", id)
}

// Scan calls fn for summaries from since on, newest first, until fn
// returns false.
func (s *Store) Scan(since time.Time, fn func(*Summary) bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.events) - 1; i >= 0; i-- {
		e := &s.events[i]
		if e.Time.Before(since) {
			return
		}
		if !fn(e) {
			return
		}
	}
}

// RuleMsg is the message of a rule as it was last logged.
func (s *Store) RuleMsg(id string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.msgs[id]
}

// Len is the number of events in memory.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// Oldest is the time of the oldest event in memory.
func (s *Store) Oldest() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.events) == 0 {
		return time.Time{}
	}
	return s.events[0].Time
}

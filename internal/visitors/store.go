// Package visitors reads the sites' nginx access logs and keeps hourly
// summaries of all traffic, not only attacks: response codes, clients,
// devices, bots and where visits came from. Every request is counted, then
// forgotten; only the counts stay, so the logs may be rotated and deleted
// (ISPmanager does that) without losing the statistics.
package visitors

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Counts is a counter by key.
type Counts map[string]int

// maxKeys caps the long-tailed counters (paths, referrers) per site and
// hour; the rest is counted under OtherKey.
const (
	maxKeys  = 100
	OtherKey = "(other)"
)

func (c Counts) add(k string, capped bool) {
	if k == "" {
		return
	}
	if _, ok := c[k]; !ok && capped && len(c) >= maxKeys {
		k = OtherKey
	}
	c[k]++
}

func (c Counts) merge(o Counts) {
	for k, v := range o {
		c[k] += v
	}
}

// Agg is the traffic of one site in one hour (or a sum of them).
type Agg struct {
	Requests int    `json:"n"`
	Views    int    `json:"v"` // page views by browsers (no assets, no bots)
	Status   Counts `json:"status,omitempty"`
	Kind     Counts `json:"kind,omitempty"` // browser | bot | script | empty
	Bot      Counts `json:"bot,omitempty"`
	Script   Counts `json:"script,omitempty"`
	OS       Counts `json:"os,omitempty"` // page views
	Browser  Counts `json:"browser,omitempty"`
	Device   Counts `json:"device,omitempty"`
	Source   Counts `json:"source,omitempty"` // page views: direct | internal | search | social | other
	Search   Counts `json:"search,omitempty"`
	Social   Counts `json:"social,omitempty"`
	Referrer Counts `json:"referrer,omitempty"` // other sites
	NotFound Counts `json:"notfound,omitempty"` // paths answered 404
	Page     Counts `json:"page,omitempty"`     // page views by path
}

func newAgg() *Agg {
	return &Agg{Status: Counts{}, Kind: Counts{}, Bot: Counts{}, Script: Counts{}, OS: Counts{}, Browser: Counts{}, Device: Counts{},
		Source: Counts{}, Search: Counts{}, Social: Counts{}, Referrer: Counts{}, NotFound: Counts{}, Page: Counts{}}
}

func (a *Agg) fill() {
	for _, c := range []*Counts{&a.Status, &a.Kind, &a.Bot, &a.Script, &a.OS, &a.Browser, &a.Device, &a.Source, &a.Search, &a.Social, &a.Referrer, &a.NotFound, &a.Page} {
		if *c == nil {
			*c = Counts{}
		}
	}
}

func (a *Agg) merge(o *Agg) {
	a.Requests += o.Requests
	a.Views += o.Views
	a.Status.merge(o.Status)
	a.Kind.merge(o.Kind)
	a.Bot.merge(o.Bot)
	a.Script.merge(o.Script)
	a.OS.merge(o.OS)
	a.Browser.merge(o.Browser)
	a.Device.merge(o.Device)
	a.Source.merge(o.Source)
	a.Search.merge(o.Search)
	a.Social.merge(o.Social)
	a.Referrer.merge(o.Referrer)
	a.NotFound.merge(o.NotFound)
	a.Page.merge(o.Page)
}

// day is one day: site -> 24 hours.
type day map[string]*[24]*Agg

// Store keeps the summaries in <Dir>/YYYY-MM-DD.json.gz, one file a day.
// Days being written stay in memory; past days are read on demand and a
// few are cached.
type Store struct {
	Dir       string
	Retention time.Duration

	mu    sync.Mutex
	days  map[string]day // loaded days
	dirty map[string]bool
	used  map[string]time.Time // last use of a loaded day, to evict
}

// OpenStore prepares the directory and drops days past the retention.
func OpenStore(dir string, retention time.Duration) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir, Retention: retention, days: map[string]day{}, dirty: map[string]bool{}, used: map[string]time.Time{}}
	s.Expire(time.Now())
	return s, nil
}

func (s *Store) path(date string) string { return filepath.Join(s.Dir, date+".json.gz") }

// get returns the loaded day, reading it from disk the first time.
// Callers hold mu.
func (s *Store) get(date string) day {
	s.used[date] = time.Now()
	if d, ok := s.days[date]; ok {
		return d
	}
	d := day{}
	if f, err := os.Open(s.path(date)); err == nil {
		if zr, err := gzip.NewReader(f); err == nil {
			var raw map[string][24]*Agg
			if json.NewDecoder(zr).Decode(&raw) == nil {
				for site, hours := range raw {
					h := hours
					for _, a := range h {
						if a != nil {
							a.fill()
						}
					}
					d[site] = &h
				}
			}
		}
		f.Close()
	}
	s.days[date] = d
	return d
}

// Add counts one request of site.
func (s *Store) Add(site string, r Request) {
	t := r.Time.Local()
	date := t.Format(time.DateOnly)
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.get(date)
	hours := d[site]
	if hours == nil {
		hours = &[24]*Agg{}
		d[site] = hours
	}
	a := hours[t.Hour()]
	if a == nil {
		a = newAgg()
		hours[t.Hour()] = a
	}
	count(a, site, r)
	s.dirty[date] = true
}

// Flush writes the changed days and lets go of the days not used lately.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for date := range s.dirty {
		if err := s.write(date, s.days[date]); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(s.dirty, date)
	}
	today := time.Now().Format(time.DateOnly)
	for date, at := range s.used {
		if date != today && !s.dirty[date] && time.Since(at) > 10*time.Minute {
			delete(s.days, date)
			delete(s.used, date)
		}
	}
	return errors.Join(errs...)
}

func (s *Store) write(date string, d day) error {
	tmp := s.path(date) + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(f)
	err = json.NewEncoder(zw).Encode(d)
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.path(date))
}

// Expire removes the day files older than the retention.
func (s *Store) Expire(now time.Time) {
	cut := now.Add(-s.Retention).Format(time.DateOnly)
	ents, _ := os.ReadDir(s.Dir)
	for _, e := range ents {
		if date, ok := strings.CutSuffix(e.Name(), ".json.gz"); ok && date < cut {
			os.Remove(filepath.Join(s.Dir, e.Name()))
		}
	}
}

// Oldest is the first day with data, zero when none.
func (s *Store) Oldest() time.Time {
	ents, _ := os.ReadDir(s.Dir)
	var dates []string
	for _, e := range ents {
		if date, ok := strings.CutSuffix(e.Name(), ".json.gz"); ok {
			dates = append(dates, date)
		}
	}
	s.mu.Lock()
	for date := range s.days {
		dates = append(dates, date)
	}
	s.mu.Unlock()
	if len(dates) == 0 {
		return time.Time{}
	}
	t, _ := time.ParseInLocation(time.DateOnly, slices.Min(dates), time.Local)
	return t
}

// Report is the traffic of a period.
type Report struct {
	Total  *Agg
	Sites  Counts // requests by site
	Labels []string
	Series []float64 // requests per hour (up to 2 days) or per day
	Views  []float64 // page views, same buckets
}

// Report sums the hours from from to now for one site ("" for all).
func (s *Store) Report(from, now time.Time, site string) Report {
	from = from.Local().Truncate(time.Hour)
	if oldest := s.Oldest(); from.Before(oldest) {
		from = oldest
	}
	hourly := now.Sub(from) <= 48*time.Hour
	rep := Report{Total: newAgg(), Sites: Counts{}}
	idx := map[string]int{}
	s.mu.Lock()
	defer s.mu.Unlock()
	for d := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.Local); !d.After(now); d = d.AddDate(0, 0, 1) {
		date := d.Format(time.DateOnly)
		if !hourly {
			idx[date] = len(rep.Labels)
			rep.Labels = append(rep.Labels, d.Format("02.01"))
			rep.Series, rep.Views = append(rep.Series, 0), append(rep.Views, 0)
		}
		for h := range 24 {
			at := d.Add(time.Duration(h) * time.Hour)
			if at.Before(from) || at.After(now) {
				continue
			}
			if hourly {
				idx[at.Format("2006-01-02 15")] = len(rep.Labels)
				rep.Labels = append(rep.Labels, at.Format("15:00"))
				rep.Series, rep.Views = append(rep.Series, 0), append(rep.Views, 0)
			}
		}
		dd := s.get(date)
		for name, hours := range dd {
			if site != "" && name != site {
				continue
			}
			for h, a := range hours {
				at := d.Add(time.Duration(h) * time.Hour)
				if a == nil || at.Before(from) || at.After(now) {
					continue
				}
				rep.Total.merge(a)
				rep.Sites[name] += a.Requests
				i := idx[date]
				if hourly {
					i = idx[at.Format("2006-01-02 15")]
				}
				rep.Series[i] += float64(a.Requests)
				rep.Views[i] += float64(a.Views)
			}
		}
	}
	return rep
}

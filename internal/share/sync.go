package share

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"wafisp/internal/auth"
	"wafisp/internal/block"
)

// Syncer publishes this server's blocks and applies the peers'.
type Syncer struct {
	Name   string
	Key    ed25519.PrivateKey
	Peers  map[string]ed25519.PublicKey
	Store  Store
	Blocks *block.Manager
	// Allowed reports whether ip is on this server's allow list.
	Allowed  func(ip string) bool
	Backends []string
	// Apply blocks the peers' addresses; without it the syncer only
	// counts what it would do.
	Apply bool
	// StateFile keeps what was applied, what was unblocked here by hand
	// and the newest list seen of every peer.
	StateFile string
	Log       *slog.Logger
	// Audit records what the syncer changed.
	Audit func(action, detail string)
	Now   func() time.Time

	mu        sync.Mutex
	st        syncState
	loaded    bool
	published []Item
	pubAt     time.Time
	self      Status
	peers     map[string]Status
}

// Status is how the exchange with one server went.
type Status struct {
	Server  string
	Checked time.Time // last read or write
	ListAt  time.Time // when that server made its list
	Items   int       // blocks in its list
	Applied int       // of them blocked here (peers only)
	Would   int       // would be blocked here in dry run
	Skipped map[string]int
	Err     string
}

type syncState struct {
	// Applied: peer -> ip -> the At of the peer's block applied here.
	Applied map[string]map[string]time.Time `json:"applied"`
	// Terms: peer -> ip -> the peer's expiry when last applied, so a term
	// changed here by hand stands until the peer changes its own.
	Terms map[string]map[string]time.Time `json:"terms"`
	// Dismissed: peer -> ip -> the At of a block that was unblocked here
	// by hand; it is not applied again until the peer blocks anew.
	Dismissed map[string]map[string]time.Time `json:"dismissed"`
	// Seen: peer -> the newest list accepted, so an old copy is refused.
	Seen map[string]time.Time `json:"seen"`
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Syncer) load() {
	if s.loaded {
		return
	}
	s.loaded = true
	if b, err := os.ReadFile(s.StateFile); err == nil {
		json.Unmarshal(b, &s.st)
	}
	if s.st.Applied == nil {
		s.st.Applied = map[string]map[string]time.Time{}
	}
	if s.st.Terms == nil {
		s.st.Terms = map[string]map[string]time.Time{}
	}
	if s.st.Dismissed == nil {
		s.st.Dismissed = map[string]map[string]time.Time{}
	}
	if s.st.Seen == nil {
		s.st.Seen = map[string]time.Time{}
	}
	s.peers = map[string]Status{}
}

func (s *Syncer) save() {
	b, _ := json.MarshalIndent(s.st, "", "  ")
	if err := auth.WriteFileAtomic(s.StateFile, b, 0o600); err != nil && s.Log != nil {
		s.Log.Error("share: save state", "err", err)
	}
}

// Run exchanges every interval until ctx ends.
func (s *Syncer) Run(ctx context.Context, every time.Duration) {
	s.dropUnknownPeers(ctx)
	for {
		s.Once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// Once publishes this server's list and pulls every peer's.
func (s *Syncer) Once(ctx context.Context) {
	s.publish(ctx)
	names := make([]string, 0, len(s.Peers))
	for n := range s.Peers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s.pull(ctx, n)
	}
}

// Own is what this server publishes: its own blocks, not the peers'.
func (s *Syncer) Own() []Item {
	now := s.now()
	var out []Item
	for _, e := range s.Blocks.Entries() {
		if e.Peer != "" || (!e.Expires.IsZero() && !e.Expires.After(now)) {
			continue
		}
		out = append(out, Item{IP: e.IP, At: e.At.UTC(), Expires: e.Expires.UTC(), Reason: e.Reason, By: e.By, Via: e.Via, Site: e.Site})
	}
	slices.SortFunc(out, func(a, b Item) int { return strings.Compare(a.IP, b.IP) })
	if len(out) > MaxItems {
		out = out[:MaxItems]
	}
	return out
}

// publish writes the list when it changed, and every hour anyway so the
// peers see this server is alive.
func (s *Syncer) publish(ctx context.Context) {
	items := s.Own()
	s.mu.Lock()
	fresh := s.now().Sub(s.pubAt) < time.Hour
	unchanged := same(items, s.published) && fresh
	s.mu.Unlock()
	if unchanged {
		return
	}
	at := s.now().UTC()
	data, err := Seal(s.Key, List{Server: s.Name, At: at, Items: items})
	if err == nil {
		err = s.Store.Put(ctx, s.Name, data)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.self = Status{Server: s.Name, Checked: s.now(), ListAt: s.self.ListAt, Items: s.self.Items}
	if err != nil {
		s.self.Err = err.Error()
		if s.Log != nil {
			s.Log.Error("share: publish", "err", err)
		}
		return
	}
	s.published, s.pubAt = items, s.now()
	s.self.ListAt, s.self.Items = at, len(items)
}

// pull reads one peer's list and puts this server in line with it.
func (s *Syncer) pull(ctx context.Context, peer string) {
	st := Status{Server: peer, Checked: s.now(), Skipped: map[string]int{}}
	defer func() {
		s.mu.Lock()
		if st.Err != "" && st.Err != ErrNotFound.Error() && s.Log != nil && s.peers[peer].Err != st.Err {
			s.Log.Error("share: pull", "peer", peer, "err", st.Err)
		}
		s.peers[peer] = st
		s.mu.Unlock()
	}()
	s.mu.Lock()
	s.load()
	s.mu.Unlock()
	data, err := s.Store.Get(ctx, peer)
	if err != nil {
		st.Err = err.Error()
		return
	}
	l, err := Unseal(data, peer, s.Peers[peer])
	if err != nil {
		st.Err = err.Error()
		return
	}
	s.mu.Lock()
	seen := s.st.Seen[peer]
	s.mu.Unlock()
	if l.At.Before(seen) {
		st.Err = fmt.Sprintf("an older list (%s) than the one already applied (%s): refused", l.At.Format(time.RFC3339), seen.Format(time.RFC3339))
		return
	}
	st.ListAt, st.Items = l.At, len(l.Items)
	s.reconcile(ctx, peer, l, &st)
}

func (s *Syncer) reconcile(ctx context.Context, peer string, l List, st *Status) {
	now := s.now()
	local := map[string]block.Entry{}
	for _, e := range s.Blocks.Entries() {
		local[e.IP] = e
	}
	s.mu.Lock()
	applied := s.st.Applied[peer]
	terms := s.st.Terms[peer]
	dismissed := s.st.Dismissed[peer]
	s.mu.Unlock()
	if applied == nil {
		applied = map[string]time.Time{}
	}
	if dismissed == nil {
		dismissed = map[string]time.Time{}
	}
	want := map[string]Item{}
	var add []block.Entry
	var notes []string
	for _, it := range l.Items {
		if !it.Expires.IsZero() && !it.Expires.After(now) {
			continue
		}
		ip, err := s.Blocks.Normalize(it.IP, "")
		if err != nil {
			st.Skipped["protected"]++
			continue
		}
		if s.Allowed != nil && s.Allowed(ip) {
			st.Skipped["allow list"]++
			continue
		}
		if at, ok := dismissed[ip]; ok && at.Equal(it.At) {
			st.Skipped["unblocked here"]++
			continue
		}
		delete(dismissed, ip) // blocked anew there: it applies again
		want[ip] = it
		if e, ok := local[ip]; ok {
			if e.Peer != peer {
				st.Skipped["blocked here already"]++
				delete(want, ip)
				continue
			}
			st.Applied++
			if last, ok := terms[ip]; ok && !last.Equal(it.Expires) && !e.Expires.Equal(it.Expires) && s.Apply {
				if err := s.Blocks.SetExpiry(ip, it.Expires); err == nil {
					notes = append(notes, fmt.Sprintf("%s: new term", ip))
				}
			}
			continue
		}
		if e, ok := s.Blocks.Lookup(ip); ok && e.IP != ip {
			st.Skipped["blocked here already"]++
			delete(want, ip)
			continue
		}
		if at, ok := applied[ip]; ok && at.Equal(it.At) {
			// It was applied and is gone, though still blocked there:
			// unblocked here by hand. Leave it so.
			dismissed[ip] = it.At
			delete(want, ip)
			st.Skipped["unblocked here"]++
			notes = append(notes, fmt.Sprintf("%s unblocked here by hand: not applied again", ip))
			continue
		}
		if !s.Apply {
			st.Would++
			delete(want, ip)
			continue
		}
		reason := fmt.Sprintf("from %s: %s", peer, it.Reason)
		add = append(add, block.Entry{IP: ip, Backends: s.Backends, By: "share", Via: "share", Peer: peer, Reason: reason,
			At: now, Expires: it.Expires, Site: it.Site})
	}
	if len(add) > 0 {
		n, err := s.Blocks.BlockMany(ctx, add)
		if err != nil {
			st.Err = "blocking: " + err.Error()
			for _, e := range add {
				delete(want, e.IP)
			}
		} else {
			st.Applied += n
			ips := make([]string, 0, len(add))
			for _, e := range add {
				ips = append(ips, e.IP)
			}
			s.audit("block.share", fmt.Sprintf("%d from %s: %s", n, peer, short(ips)))
		}
	}
	// Lifted, expired or allowed there, or taken off the list: unblock here.
	removed, err := s.Blocks.UnblockMany(ctx, func(e block.Entry) bool {
		_, keep := want[e.IP]
		return e.Peer == peer && !keep
	})
	if err != nil && st.Err == "" {
		st.Err = "unblocking: " + err.Error()
	}
	if len(removed) > 0 {
		ips := make([]string, 0, len(removed))
		for _, e := range removed {
			ips = append(ips, e.IP)
		}
		s.audit("unblock.share", fmt.Sprintf("%d lifted on %s: %s", len(removed), peer, short(ips)))
	}
	for _, n := range notes {
		s.audit("share", peer+": "+n)
	}
	next, nextTerms := map[string]time.Time{}, map[string]time.Time{}
	for ip, it := range want {
		next[ip], nextTerms[ip] = it.At, it.Expires
	}
	for ip := range dismissed {
		if _, ok := wantAny(l, ip); !ok {
			delete(dismissed, ip)
		}
	}
	s.mu.Lock()
	s.st.Applied[peer], s.st.Terms[peer], s.st.Dismissed[peer], s.st.Seen[peer] = next, nextTerms, dismissed, l.At
	s.save()
	s.mu.Unlock()
}

// wantAny finds ip in a list.
func wantAny(l List, ip string) (Item, bool) {
	for _, it := range l.Items {
		if it.IP == ip {
			return it, true
		}
	}
	return Item{}, false
}

func short(ips []string) string {
	if len(ips) > 10 {
		return strings.Join(ips[:10], ", ") + fmt.Sprintf(" and %d more", len(ips)-10)
	}
	return strings.Join(ips, ", ")
}

func (s *Syncer) audit(action, detail string) {
	if s.Audit != nil {
		s.Audit(action, detail)
	}
}

// dropUnknownPeers lifts the blocks of servers no longer trusted.
func (s *Syncer) dropUnknownPeers(ctx context.Context) {
	removed, err := s.Blocks.UnblockMany(ctx, func(e block.Entry) bool {
		_, ok := s.Peers[e.Peer]
		return e.Peer != "" && !ok
	})
	if err != nil && s.Log != nil {
		s.Log.Error("share: lift blocks of removed peers", "err", err)
	}
	if len(removed) > 0 {
		s.audit("unblock.share", fmt.Sprintf("%d blocks of servers no longer trusted lifted", len(removed)))
	}
}

// Statuses returns this server's status first, then the peers' by name.
func (s *Syncer) Statuses() (Status, []Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.load()
	var out []Status
	for n := range s.Peers {
		p, ok := s.peers[n]
		if !ok {
			p = Status{Server: n}
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Status) int { return strings.Compare(a.Server, b.Server) })
	return s.self, out
}

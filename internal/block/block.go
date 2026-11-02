// Package block blocks source addresses. An address can be blocked by
// several backends at once:
//
//	ipset    a set of the panel's own, dropped by one iptables rule before
//	         ISPmanager's chains; instant and cheap, for the web ports only
//	modsec   the deny list of the panel's ModSecurity rules: answers 403 and
//	         lands in the site's audit log; every change reloads nginx
//	ispmgr   a deny rule in ISPmanager's firewall, visible in its panel
//
// The panel keeps who blocked what, why and until when in blocks.json and
// puts the backends back in line with it (after a reboot, or when
// ISPmanager rewrote its firewall).
package block

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"wafisp/internal/auth"
	"wafisp/internal/i18n"
)

// Backend is one way of blocking.
type Backend interface {
	Name() string
	// Ensure prepares what the backend needs (set, iptables rule).
	Ensure(ctx context.Context) error
	// Sync makes the backend block exactly ips.
	Sync(ctx context.Context, ips []string) error
	// List returns what the backend blocks now, for the status view.
	List(ctx context.Context) ([]string, error)
}

type Entry struct {
	IP       string    `json:"ip"`
	Backends []string  `json:"backends"`
	By       string    `json:"by"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
	Expires  time.Time `json:"expires,omitzero"`
	// Site is where the attack came from, if blocked from an event.
	Site string `json:"site,omitempty"`
}

type Manager struct {
	File     string
	Backends []Backend
	// Protected addresses can never be blocked: the host, the office,
	// the VPN.
	Protected []netip.Prefix
	Log       *slog.Logger

	mu      sync.Mutex
	entries []Entry
	loaded  bool
	errs    map[string]string // backend -> last sync error
}

func (m *Manager) load() {
	if m.loaded {
		return
	}
	m.loaded = true
	if b, err := os.ReadFile(m.File); err == nil {
		json.Unmarshal(b, &m.entries)
	}
}

func (m *Manager) save() error {
	b, err := json.MarshalIndent(m.entries, "", "  ")
	if err != nil {
		return err
	}
	return auth.WriteFileAtomic(m.File, b, 0o600)
}

func (m *Manager) Backend(name string) Backend {
	for _, b := range m.Backends {
		if b.Name() == name {
			return b
		}
	}
	return nil
}

// Names lists the configured backends.
func (m *Manager) Names() []string {
	var out []string
	for _, b := range m.Backends {
		out = append(out, b.Name())
	}
	return out
}

// Normalize parses an IP or CIDR and refuses what must not be blocked.
func (m *Manager) Normalize(s, requester string) (string, error) {
	return normalize(strings.TrimSpace(s), requester, m.Protected)
}

func normalize(s, requester string, protected []netip.Prefix) (string, error) {
	var p netip.Prefix
	if a, err := netip.ParseAddr(s); err == nil {
		p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
	} else if p, err = netip.ParsePrefix(s); err != nil {
		return "", i18n.Errorf("%q is neither an IP address nor a subnet", s)
	}
	p = p.Masked()
	a := p.Addr()
	switch {
	case a.Is4() && p.Bits() < 16, a.Is6() && p.Bits() < 48:
		return "", i18n.Errorf("The subnet is too wide: at most /16 for IPv4 and /48 for IPv6")
	case a.IsLoopback(), a.IsUnspecified(), a.IsMulticast(), a.IsPrivate(), a.IsLinkLocalUnicast():
		return "", i18n.Errorf("This address cannot be blocked")
	}
	if r, err := netip.ParseAddr(requester); err == nil && p.Contains(r.Unmap()) {
		return "", i18n.Errorf("The subnet contains your own address — you would lose access")
	}
	for _, x := range protected {
		if p.Overlaps(x) {
			return "", i18n.Errorf("The subnet overlaps the protected address %s", x)
		}
	}
	if p.IsSingleIP() {
		return a.String(), nil
	}
	return p.String(), nil
}

// Entries returns the blocks, newest first.
func (m *Manager) Entries() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	out := slices.Clone(m.entries)
	slices.SortFunc(out, func(a, b Entry) int { return b.At.Compare(a.At) })
	return out
}

// Lookup returns the block of ip, if any.
func (m *Manager) Lookup(ip string) (Entry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	for _, e := range m.entries {
		if e.IP == ip {
			return e, true
		}
		if p, err := netip.ParsePrefix(e.IP); err == nil {
			if a, err := netip.ParseAddr(ip); err == nil && p.Contains(a) {
				return e, true
			}
		}
	}
	return Entry{}, false
}

// Errors returns the last sync error of every backend.
func (m *Manager) Errors() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for k, v := range m.errs {
		out[k] = v
	}
	return out
}

// Block adds or replaces the block of e.IP and syncs the backends.
func (m *Manager) Block(ctx context.Context, e Entry) error {
	if len(e.Backends) == 0 {
		return i18n.Errorf("Choose at least one way to block")
	}
	for _, b := range e.Backends {
		if m.Backend(b) == nil {
			return fmt.Errorf("unknown backend %q", b)
		}
	}
	m.mu.Lock()
	m.load()
	prev := slices.Clone(m.entries)
	affected := slices.Clone(e.Backends)
	for _, x := range m.entries {
		if x.IP == e.IP {
			affected = append(affected, x.Backends...)
		}
	}
	m.entries = slices.DeleteFunc(m.entries, func(x Entry) bool { return x.IP == e.IP })
	m.entries = append(m.entries, e)
	m.mu.Unlock()
	if err := m.sync(ctx, affected); err != nil {
		m.mu.Lock()
		m.entries = prev
		m.mu.Unlock()
		m.sync(ctx, affected)
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.save()
}

// Unblock removes ip from every backend.
func (m *Manager) Unblock(ctx context.Context, ip string) error {
	m.mu.Lock()
	m.load()
	var affected []string
	for _, x := range m.entries {
		if x.IP == ip {
			affected = append(affected, x.Backends...)
		}
	}
	n := len(m.entries)
	m.entries = slices.DeleteFunc(m.entries, func(x Entry) bool { return x.IP == ip })
	removed := len(m.entries) != n
	m.mu.Unlock()
	if !removed {
		affected = m.Names() // not ours: make sure no backend keeps it
	}
	err := m.sync(ctx, affected)
	if removed {
		m.mu.Lock()
		if serr := m.save(); serr != nil && err == nil {
			err = serr
		}
		m.mu.Unlock()
	}
	return err
}

// Sync puts every backend in line with the entries. Errors of one backend
// do not stop the others.
func (m *Manager) Sync(ctx context.Context) error { return m.sync(ctx, nil) }

// sync is Sync limited to the named backends; nil means all.
func (m *Manager) sync(ctx context.Context, only []string) error {
	m.mu.Lock()
	m.load()
	want := map[string][]string{}
	for _, e := range m.entries {
		for _, b := range e.Backends {
			want[b] = append(want[b], e.IP)
		}
	}
	m.mu.Unlock()
	var errs []error
	m.mu.Lock()
	res := map[string]string{}
	for k, v := range m.errs {
		res[k] = v
	}
	m.mu.Unlock()
	for _, b := range m.Backends {
		if only != nil && !slices.Contains(only, b.Name()) {
			continue
		}
		delete(res, b.Name())
		err := b.Ensure(ctx)
		if err == nil {
			err = b.Sync(ctx, want[b.Name()])
		}
		if err != nil {
			res[b.Name()] = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", b.Name(), err))
		}
	}
	m.mu.Lock()
	m.errs = res
	m.mu.Unlock()
	return errors.Join(errs...)
}

// Expired returns addresses whose block time is over.
func (m *Manager) Expired(now time.Time) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	var out []string
	for _, e := range m.entries {
		if !e.Expires.IsZero() && now.After(e.Expires) {
			out = append(out, e.IP)
		}
	}
	return out
}

// Run unblocks expired addresses and re-syncs the backends every minute
// until ctx ends; onExpire is called for every address it removed.
func (m *Manager) Run(ctx context.Context, onExpire func(ip string, err error)) {
	if err := m.Sync(ctx); err != nil {
		m.Log.Warn("block: initial sync", "err", err)
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, ip := range m.Expired(time.Now()) {
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			err := m.Unblock(cctx, ip)
			cancel()
			onExpire(ip, err)
		}
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		if err := m.Sync(cctx); err != nil {
			m.Log.Warn("block: sync", "err", err)
		}
		cancel()
	}
}

// NormalizeAllow parses an address or subnet for the allow list: the
// WAF does not inspect its requests, so it may be narrow but not wide.
func (m *Manager) NormalizeAllow(s string) (string, error) {
	var p netip.Prefix
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
	} else if p, err = netip.ParsePrefix(s); err != nil {
		return "", i18n.Errorf("%q is neither an IP address nor a subnet", s)
	}
	p = p.Masked()
	if a := p.Addr(); (a.Is4() && p.Bits() < 24) || (a.Is6() && p.Bits() < 56) || a.IsUnspecified() {
		return "", i18n.Errorf("The subnet is too wide for the allow list: at most /24 for IPv4 and /56 for IPv6")
	}
	if p.IsSingleIP() {
		return p.Addr().String(), nil
	}
	return p.String(), nil
}

// SetExpiry changes until when ip stays blocked; zero means until
// unblocked by hand. The backends keep the address, so nothing is synced.
func (m *Manager) SetExpiry(ip string, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	i := slices.IndexFunc(m.entries, func(e Entry) bool { return e.IP == ip })
	if i < 0 {
		return i18n.Errorf("%s is not blocked by the panel", ip)
	}
	m.entries[i].Expires = expires
	return m.save()
}

// Blocked reports, for each of ips, whether it is blocked (directly or
// inside a blocked subnet).
func (m *Manager) Blocked(ips []string) map[string]bool {
	out := map[string]bool{}
	for _, ip := range ips {
		if _, ok := m.Lookup(ip); ok {
			out[ip] = true
		}
	}
	return out
}

// BlockMany blocks many addresses with one sync per backend, so that a
// mass ban through the modsec backend reloads nginx once, not per address.
// Addresses already blocked keep their entry. On a sync error nothing is
// kept.
func (m *Manager) BlockMany(ctx context.Context, es []Entry) (int, error) {
	var affected []string
	for _, e := range es {
		if len(e.Backends) == 0 {
			return 0, i18n.Errorf("Choose at least one way to block")
		}
		for _, b := range e.Backends {
			if m.Backend(b) == nil {
				return 0, fmt.Errorf("unknown backend %q", b)
			}
			if !slices.Contains(affected, b) {
				affected = append(affected, b)
			}
		}
	}
	m.mu.Lock()
	m.load()
	prev := slices.Clone(m.entries)
	added := 0
	for _, e := range es {
		if slices.ContainsFunc(m.entries, func(x Entry) bool { return x.IP == e.IP }) {
			continue
		}
		m.entries = append(m.entries, e)
		added++
	}
	m.mu.Unlock()
	if added == 0 {
		return 0, nil
	}
	if err := m.sync(ctx, affected); err != nil {
		m.mu.Lock()
		m.entries = prev
		m.mu.Unlock()
		m.sync(ctx, affected)
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return added, m.save()
}

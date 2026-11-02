package policy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"wafisp/internal/auth"
)

// Runner runs a command; tests replace it.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

func Exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Manager owns policy.json and the rule files nginx loads.
type Manager struct {
	File string // policy.json
	Dir  string // where before.conf, after.conf, allow.txt and deny.txt go
	// Test and Reload are the nginx commands, e.g. ["nginx","-t"] and
	// ["systemctl","reload","nginx"]. An empty Reload only writes files.
	Test   []string
	Reload []string
	// MinAvailMB postpones a reload while the host has less memory
	// available: every reload starts a new set of nginx workers that load
	// all the rules again.
	MinAvailMB int
	Run        Runner
	Log        *slog.Logger

	mu    sync.Mutex
	state State
	// applyMu serialises writing the files, testing and reloading.
	applyMu sync.Mutex
	// pending is set when a change waits for a reload.
	pending   bool
	lastError string
	lastApply time.Time
}

func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := os.ReadFile(m.File)
	if errors.Is(err, os.ErrNotExist) {
		m.state = State{NextID: 1}
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &m.state); err != nil {
		return fmt.Errorf("%s: %w", m.File, err)
	}
	if m.state.NextID == 0 {
		m.state.NextID = 1
	}
	return nil
}

// State returns a copy of the policy.
func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := json.Marshal(m.state)
	var s State
	json.Unmarshal(b, &s)
	return s
}

// Status is how the last apply went.
func (m *Manager) Status() (pending bool, lastErr string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending, m.lastError, m.lastApply
}

// Update changes the policy with fn, saves it and applies it to nginx.
// When nginx refuses the new files the change is undone and the error
// returned.
func (m *Manager) Update(ctx context.Context, fn func(*State) error) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()

	m.mu.Lock()
	prev := m.state
	b, _ := json.Marshal(prev)
	var next State
	json.Unmarshal(b, &next)
	if err := fn(&next); err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()

	if err := m.apply(ctx, &next); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = next
	return m.save()
}

func (m *Manager) save() error {
	b, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	return auth.WriteFileAtomic(m.File, b, 0o600)
}

// Apply writes the current policy again, e.g. on start or when a reload
// was postponed.
func (m *Manager) Apply(ctx context.Context) error {
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	s := m.State()
	return m.apply(ctx, &s)
}

func (m *Manager) files(s *State) map[string]string {
	before, after := s.Files(m.Dir)
	return map[string]string{
		"before.conf": before,
		"after.conf":  after,
		"allow.txt":   AddrList(addrIPs(s.Allow)),
		"deny.txt":    AddrList(s.Deny),
	}
}

func addrIPs(as []Addr) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.IP)
	}
	return out
}

// apply writes the files, tests the nginx config and reloads it. Unchanged
// files cause no reload.
func (m *Manager) apply(ctx context.Context, s *State) error {
	if err := os.MkdirAll(m.Dir, 0o755); err != nil {
		return err
	}
	want := m.files(s)
	old := map[string][]byte{}
	changed := false
	for name, content := range want {
		b, err := os.ReadFile(filepath.Join(m.Dir, name))
		if err == nil {
			old[name] = b
		}
		if err != nil || !bytes.Equal(b, []byte(content)) {
			changed = true
		}
	}
	if !changed && !m.isPending() {
		return nil
	}
	for name, content := range want {
		if err := auth.WriteFileAtomic(filepath.Join(m.Dir, name), []byte(content), 0o644); err != nil {
			m.restore(old)
			return err
		}
	}
	if len(m.Test) > 0 {
		tctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		out, err := m.Run(tctx, m.Test[0], m.Test[1:]...)
		cancel()
		if err != nil {
			m.restore(old)
			msg := lastLines(string(out), 6)
			m.setResult(false, "nginx -t: "+msg)
			return fmt.Errorf("nginx refused the change, nothing was applied: %s", msg)
		}
	}
	return m.reload(ctx)
}

func (m *Manager) isPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending
}

func (m *Manager) setResult(pending bool, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending, m.lastError = pending, errMsg
	if errMsg == "" && !pending {
		m.lastApply = time.Now()
	}
}

func (m *Manager) reload(ctx context.Context) error {
	if len(m.Reload) == 0 {
		m.setResult(false, "")
		return nil
	}
	if m.MinAvailMB > 0 {
		if avail, err := memAvailableMB(); err == nil && avail < m.MinAvailMB {
			m.setResult(true, fmt.Sprintf("reload postponed: %d MB available, %d MB needed", avail, m.MinAvailMB))
			m.Log.Warn("policy: nginx reload postponed, low memory", "available_mb", avail)
			return nil
		}
	}
	rctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if out, err := m.Run(rctx, m.Reload[0], m.Reload[1:]...); err != nil {
		// The files passed nginx -t and stay; the reload is retried every
		// minute and the panel shows the error meanwhile.
		msg := lastLines(string(out), 4)
		m.setResult(true, fmt.Sprintf("reload: %v %s", err, msg))
		m.Log.Error("policy: nginx reload failed", "err", err, "out", msg)
		return nil
	}
	m.setResult(false, "")
	m.Log.Info("policy applied, nginx reloaded")
	return nil
}

// RetryPending reloads nginx when an earlier reload was postponed.
func (m *Manager) RetryPending(ctx context.Context) {
	if !m.isPending() {
		return
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if err := m.reload(ctx); err != nil {
		m.Log.Warn("policy: retry reload", "err", err)
	}
}

func (m *Manager) restore(old map[string][]byte) {
	for _, name := range []string{"before.conf", "after.conf", "allow.txt", "deny.txt"} {
		p := filepath.Join(m.Dir, name)
		if b, ok := old[name]; ok {
			auth.WriteFileAtomic(p, b, 0o644)
		} else {
			os.Remove(p)
		}
	}
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func memAvailableMB() (int, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "MemAvailable:"); ok {
			kb, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")))
			return kb / 1024, err
		}
	}
	return 0, errors.New("no MemAvailable in /proc/meminfo")
}

// AddExclusion stores x with a new id.
func (s *State) AddExclusion(x Exclusion) (Exclusion, error) {
	x.ID = s.NextID
	if err := x.Validate(); err != nil {
		return x, err
	}
	s.NextID++
	s.Exclusions = append(s.Exclusions, x)
	return x, nil
}

func (s *State) Exclusion(id int) *Exclusion {
	i := slices.IndexFunc(s.Exclusions, func(x Exclusion) bool { return x.ID == id })
	if i < 0 {
		return nil
	}
	return &s.Exclusions[i]
}

func (s *State) DeleteExclusion(id int) bool {
	n := len(s.Exclusions)
	s.Exclusions = slices.DeleteFunc(s.Exclusions, func(x Exclusion) bool { return x.ID == id })
	return len(s.Exclusions) != n
}

// SetMode overrides the engine of a site; an empty engine removes it.
func (s *State) SetMode(m Mode) {
	s.Modes = slices.DeleteFunc(s.Modes, func(x Mode) bool { return x.Site == m.Site })
	if m.Engine != "" {
		s.Modes = append(s.Modes, m)
		slices.SortFunc(s.Modes, func(a, b Mode) int { return strings.Compare(a.Site, b.Site) })
	}
}

func (s State) ModeOf(site string) string {
	for _, m := range s.Modes {
		if m.Site == site {
			return m.Engine
		}
	}
	return ""
}

// ExpireAllow drops allowed addresses whose time is over and returns them.
func (s *State) ExpireAllow(now time.Time) []string {
	var gone []string
	s.Allow = slices.DeleteFunc(s.Allow, func(a Addr) bool {
		if !a.Expires.IsZero() && now.After(a.Expires) {
			gone = append(gone, a.IP)
			return true
		}
		return false
	})
	return gone
}

// CheckInclude reads the nginx file that should load the panel's rules
// around CRS and returns what is wrong with it; nil means all is well.
// The panel never edits that file: an update of ISPmanager or nginx may
// rewrite it, and fixing it is a decision for a person.
func (m *Manager) CheckInclude(file string) []string {
	var problems []string
	b, err := os.ReadFile(file)
	if err != nil {
		problems = append(problems, fmt.Sprintf("%s: %v", file, err))
	}
	before, after := filepath.Join(m.Dir, "before.conf"), filepath.Join(m.Dir, "after.conf")
	pos := map[string]int{}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) != 2 || f[0] != "modsecurity_rules_file" {
			continue
		}
		n++
		p := strings.TrimSuffix(f[1], ";")
		switch {
		case p == before:
			pos["before"] = n
		case p == after:
			pos["after"] = n
		case pos["crs"] == 0:
			pos["crs"] = n
		}
	}
	if err == nil && pos["before"] == 0 {
		problems = append(problems, fmt.Sprintf("%s no longer loads %s: the allow and deny lists, site modes and site exclusions do not apply", file, before))
	}
	if err == nil && pos["after"] == 0 {
		problems = append(problems, fmt.Sprintf("%s no longer loads %s: exclusions for every site do not apply", file, after))
	}
	if err == nil && pos["crs"] == 0 {
		problems = append(problems, fmt.Sprintf("%s loads no CRS rules file", file))
	} else if (pos["before"] != 0 && pos["before"] > pos["crs"]) || (pos["after"] != 0 && pos["after"] < pos["crs"]) {
		problems = append(problems, fmt.Sprintf("%s loads the panel's rules in the wrong order around CRS", file))
	}
	for _, name := range []string{"before.conf", "after.conf", "allow.txt", "deny.txt"} {
		if _, err := os.Stat(filepath.Join(m.Dir, name)); err != nil {
			problems = append(problems, fmt.Sprintf("%s is missing; the panel writes it again", filepath.Join(m.Dir, name)))
		}
	}
	return problems
}

// AddTrap stores t with a new id.
func (s *State) AddTrap(t Trap) (Trap, error) {
	t.ID = 1
	for _, x := range s.Traps {
		t.ID = max(t.ID, x.ID+1)
	}
	if err := t.Validate(); err != nil {
		return t, err
	}
	for _, x := range s.Traps {
		if x.Site == t.Site && strings.EqualFold(x.Path, t.Path) {
			return t, fmt.Errorf("trap %d already covers this path", x.ID)
		}
	}
	s.Traps = append(s.Traps, t)
	return t, nil
}

func (s *State) Trap(id int) *Trap {
	i := slices.IndexFunc(s.Traps, func(x Trap) bool { return x.ID == id })
	if i < 0 {
		return nil
	}
	return &s.Traps[i]
}

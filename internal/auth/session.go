package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"
)

// Sessions are stateless cookies signed with a key kept in the data dir.
// A session carries the user's Version, so changing a password or role
// logs out every other session of that user.
type Sessions struct {
	key []byte
	ttl time.Duration
}

type Session struct {
	User    string `json:"u"`
	Version int    `json:"v"`
	Expires int64  `json:"e"`
	// Nonce makes every session, and therefore its CSRF token, unique.
	Nonce string `json:"n"`
}

func OpenSessions(keyFile string, ttl time.Duration) (*Sessions, error) {
	key, err := os.ReadFile(keyFile)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		rand.Read(key)
		err = WriteFileAtomic(keyFile, key, 0o600)
	}
	if err != nil {
		return nil, err
	}
	if len(key) < 32 {
		return nil, errors.New("session key is too short")
	}
	return &Sessions{key: key, ttl: ttl}, nil
}

func (s *Sessions) TTL() time.Duration { return s.ttl }

func (s *Sessions) New(u User) (string, Session) {
	n := make([]byte, 12)
	rand.Read(n)
	sess := Session{User: u.Name, Version: u.Version, Expires: time.Now().Add(s.ttl).Unix(), Nonce: base64.RawURLEncoding.EncodeToString(n)}
	b, _ := json.Marshal(sess)
	p := base64.RawURLEncoding.EncodeToString(b)
	return p + "." + s.sign("session", p), sess
}

func (s *Sessions) Parse(cookie string) (Session, bool) {
	p, sig, ok := strings.Cut(cookie, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.sign("session", p))) {
		return Session{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return Session{}, false
	}
	var sess Session
	if json.Unmarshal(b, &sess) != nil || time.Now().Unix() > sess.Expires {
		return Session{}, false
	}
	return sess, true
}

// CSRF is the per-session token every form posts back.
func (s *Sessions) CSRF(sess Session) string {
	return s.sign("csrf", sess.User+"|"+sess.Nonce)
}

func (s *Sessions) sign(purpose, v string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(purpose + ":" + v))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Throttle locks a login key (IP or user) after too many failures.
type Throttle struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	failures map[string][]time.Time
}

func NewThrottle(max int, window time.Duration) *Throttle {
	return &Throttle{max: max, window: window, failures: map[string][]time.Time{}}
}

func (t *Throttle) Blocked(keys ...string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		if len(t.recent(k)) >= t.max {
			return true
		}
	}
	return false
}

func (t *Throttle) Fail(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		t.failures[k] = append(t.recent(k), time.Now())
	}
}

func (t *Throttle) Reset(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		delete(t.failures, k)
	}
}

func (t *Throttle) recent(k string) []time.Time {
	cut := time.Now().Add(-t.window)
	fs := t.failures[k]
	i := 0
	for i < len(fs) && fs[i].Before(cut) {
		i++
	}
	fs = fs[i:]
	if len(fs) == 0 {
		delete(t.failures, k)
	}
	return fs
}

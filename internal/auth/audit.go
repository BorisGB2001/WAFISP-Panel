package auth

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AuditEntry is one action in the panel.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	IP     string    `json:"ip"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
}

// Audit appends entries to a JSON lines file and keeps the newest in memory.
type Audit struct {
	path   string
	mu     sync.Mutex
	recent []AuditEntry
	keep   int
}

func OpenAudit(path string, keep int) (*Audit, error) {
	a := &Audit{path: path, keep: keep}
	f, err := os.Open(path)
	if err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var e AuditEntry
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				a.push(e)
			}
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return a, nil
}

func (a *Audit) push(e AuditEntry) {
	a.recent = append(a.recent, e)
	if len(a.recent) > a.keep {
		a.recent = a.recent[len(a.recent)-a.keep:]
	}
}

func (a *Audit) Log(user, ip, action, detail string) error {
	e := AuditEntry{Time: time.Now(), User: user, IP: ip, Action: action, Detail: detail}
	b, _ := json.Marshal(e)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.push(e)
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// Recent returns the newest entries first.
func (a *Audit) Recent() []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEntry, len(a.recent))
	for i, e := range a.recent {
		out[len(a.recent)-1-i] = e
	}
	return out
}

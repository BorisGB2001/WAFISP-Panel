// Package event is one ModSecurity audit log entry as the panel sees it.
package event

import (
	"strings"
	"time"
)

// Match is one rule that matched the request.
type Match struct {
	ID       string   `json:"id"`
	Msg      string   `json:"msg,omitempty"`
	Data     string   `json:"data,omitempty"`
	Var      string   `json:"var,omitempty"` // e.g. ARGS:q, REQUEST_FILENAME
	Severity int      `json:"severity,omitempty"`
	Phase    int      `json:"phase,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	File     string   `json:"file,omitempty"`
	// Denied is set on the rule that blocked the request.
	Denied bool `json:"denied,omitempty"`
}

type Header struct {
	Name  string `json:"n"`
	Value string `json:"v"`
}

// Event is one entry of a site's audit log.
type Event struct {
	ID      string    `json:"id"` // ModSecurity unique_id
	Site    string    `json:"site"`
	Time    time.Time `json:"time"`
	SrcIP   string    `json:"src_ip"`
	SrcPort int       `json:"src_port,omitempty"`
	DstIP   string    `json:"dst_ip,omitempty"`
	DstPort int       `json:"dst_port,omitempty"`

	Method    string   `json:"method"`
	URI       string   `json:"uri"`
	Proto     string   `json:"proto,omitempty"`
	Host      string   `json:"host"`
	UserAgent string   `json:"ua,omitempty"`
	Referer   string   `json:"referer,omitempty"`
	Headers   []Header `json:"headers,omitempty"`
	Body      string   `json:"body,omitempty"` // request body, truncated

	Status int `json:"status"`
	// Denied is set when ModSecurity intervened; a request that only
	// scored (DetectionOnly, or below the threshold) passed.
	Denied bool `json:"denied"`
	// Score is the inbound anomaly score CRS compared to its threshold.
	Score int `json:"score"`
	// Category of the strongest attack rule, see Categories.
	Category string  `json:"category"`
	Rules    []Match `json:"rules,omitempty"`

	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
}

func (e Event) ActionName() string {
	if e.Denied {
		return "deny"
	}
	return "pass"
}

// Risk is 1 (low), 2 (medium) or 3 (high), from the anomaly score.
func (e Event) Risk() int {
	switch {
	case e.Score >= 15:
		return 3
	case e.Score >= 5:
		return 2
	default:
		return 1
	}
}

// Top is the attack rule that tells most about the request: the one with
// the highest severity, the first one on a tie. Evaluation rules (949,
// 959, 980) never are.
func (e Event) Top() *Match {
	var top *Match
	for i := range e.Rules {
		m := &e.Rules[i]
		if Evaluation(m.ID) {
			continue
		}
		if top == nil || (m.Severity != 0 && (top.Severity == 0 || m.Severity < top.Severity)) {
			top = m
		}
	}
	return top
}

// RuleID and Reason describe the event in one line.
func (e Event) RuleID() string {
	if m := e.Top(); m != nil {
		return m.ID
	}
	return ""
}

func (e Event) Reason() string {
	if m := e.Top(); m != nil {
		return m.Msg
	}
	for _, m := range e.Rules {
		if m.Denied {
			return m.Msg
		}
	}
	return ""
}

// RuleIDs lists the attack rules, without the evaluation ones.
func (e Event) RuleIDs() []string {
	var out []string
	for _, m := range e.Rules {
		if !Evaluation(m.ID) {
			out = append(out, m.ID)
		}
	}
	return out
}

// Path is the URI without the query string.
func (e Event) Path() string {
	if i := strings.IndexByte(e.URI, '?'); i >= 0 {
		return e.URI[:i]
	}
	return e.URI
}

// Evaluation reports CRS rules that sum up scores rather than detect.
func Evaluation(id string) bool {
	return strings.HasPrefix(id, "949") || strings.HasPrefix(id, "959") || strings.HasPrefix(id, "980") ||
		strings.HasPrefix(id, "901") || strings.HasPrefix(id, "905")
}

// Header is the first request header with that name, case-insensitively.
func (e Event) Header(name string) string {
	for _, h := range e.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

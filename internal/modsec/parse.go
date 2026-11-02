// Package modsec reads the native (Serial) audit log of ModSecurity v3.
//
// An entry is a run of sections, each opened by a boundary line
// "---<8 chars>---<letter>--" and closed by section Z:
//
//	A  [02/Jan/2026:07:10:12 +0300] <unique_id> <src ip> <src port> <dst ip> <dst port>
//	B  request line and headers
//	C  request body
//	E  response body (ignored)
//	F  response status line and headers
//	H  one "ModSecurity: ..." line per matched rule
//	Z  end of entry
package modsec

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"wafisp/internal/event"
)

// MaxBody bounds how much of a request body an event keeps.
const MaxBody = 4096

var boundary = regexp.MustCompile(`^---([A-Za-z0-9]{8})---([A-Z])--$`)

// Parser assembles entries from lines. It is not safe for concurrent use.
type Parser struct {
	Site string

	id      string
	section byte
	ev      *event.Event
	body    strings.Builder
	sawLine bool // the first line of section B/F is the request/status line
}

// Feed takes one line without its newline and returns the event when the
// line closes an entry. Lines outside an entry are ignored, so a reader
// that starts in the middle of a file resynchronises on the next entry.
func (p *Parser) Feed(line string) *event.Event {
	if m := boundary.FindStringSubmatch(line); m != nil {
		return p.open(m[1], m[2][0])
	}
	if p.ev == nil {
		return nil
	}
	if !utf8.ValidString(line) {
		line = strings.ToValidUTF8(line, "�")
	}
	switch p.section {
	case 'A':
		p.parseA(line)
	case 'B':
		p.parseB(line)
	case 'C':
		if p.body.Len() < MaxBody {
			if p.body.Len() > 0 {
				p.body.WriteByte('\n')
			}
			p.body.WriteString(line)
		}
	case 'F':
		if !p.sawLine {
			p.sawLine = true
			if f := strings.Fields(line); len(f) >= 2 {
				p.ev.Status, _ = strconv.Atoi(f[1])
			}
		}
	case 'H':
		p.parseH(line)
	}
	return nil
}

func (p *Parser) open(id string, sec byte) *event.Event {
	if sec == 'A' || p.ev == nil || id != p.id {
		// A new entry; an unfinished previous one is dropped.
		p.ev = &event.Event{Site: p.Site}
		p.id = id
		p.body.Reset()
		if sec != 'A' {
			p.ev = nil // joined mid-entry: wait for the next A
			return nil
		}
	}
	p.section, p.sawLine = sec, false
	if sec != 'Z' {
		return nil
	}
	ev := p.ev
	p.ev = nil
	if ev.ID == "" {
		return nil
	}
	ev.Body = truncate(p.body.String(), MaxBody)
	finish(ev)
	return ev
}

// [02/Nov/2026:07:10:12 +0300] 179359261256.944934 198.51.100.7 49160 10.0.0.5 443
func (p *Parser) parseA(line string) {
	end := strings.IndexByte(line, ']')
	if !strings.HasPrefix(line, "[") || end < 0 {
		return
	}
	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", line[1:end]); err == nil {
		p.ev.Time = t
	}
	f := strings.Fields(line[end+1:])
	if len(f) >= 5 {
		p.ev.ID, p.ev.SrcIP, p.ev.DstIP = f[0], f[1], f[3]
		p.ev.SrcPort, _ = strconv.Atoi(f[2])
		p.ev.DstPort, _ = strconv.Atoi(f[4])
	}
}

func (p *Parser) parseB(line string) {
	if line == "" {
		return
	}
	if !p.sawLine {
		p.sawLine = true
		f := strings.Fields(line)
		if len(f) >= 2 {
			p.ev.Method, p.ev.URI = f[0], f[1]
		}
		if len(f) >= 3 {
			p.ev.Proto = f[len(f)-1]
		}
		return
	}
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		return
	}
	name, value = strings.TrimSpace(name), strings.TrimSpace(value)
	if len(p.ev.Headers) < 64 {
		p.ev.Headers = append(p.ev.Headers, event.Header{Name: name, Value: truncate(value, 2048)})
	}
	switch strings.ToLower(name) {
	case "host":
		p.ev.Host = stripPort(value)
	case "user-agent":
		p.ev.UserAgent = truncate(value, 512)
	case "referer":
		p.ev.Referer = truncate(value, 512)
	}
}

var (
	tagRe   = regexp.MustCompile(`\[(\w+) "((?:[^"\\]|\\.)*)"\]`)
	varRe   = regexp.MustCompile("against variable `([^']*)'")
	valueRe = regexp.MustCompile("\\(Value: `((?:[^']|'[^ ])*)' \\)")
	phaseRe = regexp.MustCompile(`\(phase (\d)\)`)
)

func (p *Parser) parseH(line string) {
	if !strings.HasPrefix(line, "ModSecurity: ") {
		return
	}
	m := event.Match{Denied: strings.HasPrefix(line, "ModSecurity: Access denied")}
	if v := varRe.FindStringSubmatch(line); v != nil {
		m.Var = v[1]
	}
	if v := phaseRe.FindStringSubmatch(line); v != nil {
		m.Phase, _ = strconv.Atoi(v[1])
	}
	// Tags start after the operator part, whose regex may hold brackets.
	rest := line
	if i := strings.Index(line, " [file \""); i >= 0 {
		rest = line[i:]
	}
	for _, t := range tagRe.FindAllStringSubmatch(rest, -1) {
		v := strings.ReplaceAll(strings.ReplaceAll(t[2], `\"`, `"`), `\x22`, `"`)
		switch t[1] {
		case "id":
			m.ID = v
		case "msg":
			m.Msg = v
		case "data":
			m.Data = truncate(v, 1024)
		case "severity":
			m.Severity, _ = strconv.Atoi(v)
		case "tag":
			m.Tags = append(m.Tags, v)
		case "file":
			m.File = v
		}
	}
	if m.ID == "" {
		return
	}
	// 949xxx compares the inbound score with the threshold (959 is outbound).
	if strings.HasPrefix(m.ID, "949") {
		if v := valueRe.FindStringSubmatch(line); v != nil {
			if n, err := strconv.Atoi(v[1]); err == nil {
				p.ev.Score = max(p.ev.Score, n)
			}
		}
	}
	p.ev.Rules = append(p.ev.Rules, m)
}

// finish fills what depends on the whole entry.
func finish(ev *event.Event) {
	for _, m := range ev.Rules {
		if m.Denied {
			ev.Denied = true
		}
	}
	if ev.Score == 0 {
		// No evaluation rule matched (DetectionOnly below the threshold,
		// or a rule that blocks by itself): add up CRS severities.
		for _, m := range ev.Rules {
			if !event.Evaluation(m.ID) {
				ev.Score += severityScore(m.Severity)
			}
		}
	}
	if ev.Host == "" {
		ev.Host = ev.Site
	}
	ev.Classify()
}

// severityScore is CRS's default score for a severity.
func severityScore(s int) int {
	switch s {
	case 2: // CRITICAL
		return 5
	case 3: // ERROR
		return 4
	case 4: // WARNING
		return 3
	case 5: // NOTICE
		return 2
	}
	return 0
}

func stripPort(h string) string {
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[:i], ":") {
		return strings.ToLower(h[:i])
	}
	return strings.ToLower(h)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}

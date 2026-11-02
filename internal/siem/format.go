// Package siem forwards every WAF event to a SIEM over syslog.
package siem

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"wafisp/internal/event"
)

// CEF formats an event in ArcSight Common Event Format (rev. 25).
func CEF(ev event.Event) string {
	sev := 5
	if ev.Denied {
		sev = 8
	}
	var ext []string
	add := func(k, v string) {
		if v != "" {
			ext = append(ext, k+"="+cefExt(v))
		}
	}
	add("rt", strconv.FormatInt(ev.Time.UnixMilli(), 10))
	add("src", ev.SrcIP)
	add("dhost", ev.Host)
	if ev.DstPort != 0 {
		add("dpt", strconv.Itoa(ev.DstPort))
	}
	add("request", ev.URI)
	add("requestMethod", ev.Method)
	add("requestClientApplication", ev.UserAgent)
	add("act", ev.ActionName())
	add("cat", ev.Category)
	add("externalId", ev.ID)
	add("deviceExternalId", ev.Site)
	add("msg", ev.Reason())
	add("cs1Label", "rules")
	add("cs1", strings.Join(ev.RuleIDs(), ","))
	add("cs2Label", "ruleId")
	add("cs2", ev.RuleID())
	add("cs4Label", "country")
	add("cs4", ev.Country)
	add("cn1Label", "anomalyScore")
	add("cn1", strconv.Itoa(ev.Score))
	add("cn2Label", "status")
	add("cn2", strconv.Itoa(ev.Status))

	return fmt.Sprintf("CEF:0|OWASP|ModSecurity CRS|4|%s|%s|%d|%s",
		cefHeader(ev.Category), cefHeader(event.CategoryName(ev.Category)), sev, strings.Join(ext, " "))
}

var (
	cefHeaderEsc = strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\n", " ", "\r", " ")
	cefExtEsc    = strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`)
)

func cefHeader(s string) string { return cefHeaderEsc.Replace(s) }
func cefExt(s string) string    { return cefExtEsc.Replace(s) }

// JSONEvent is the "json" SIEM format.
type JSONEvent struct {
	Time time.Time `json:"@timestamp"`
	// Product marks the event for SIEM rules, e.g. a Wazuh field match.
	Product      string        `json:"product"`
	Site         string        `json:"site"`
	EventID      string        `json:"event_id"`
	SrcIP        string        `json:"src_ip"`
	Host         string        `json:"host"`
	DstPort      int           `json:"dst_port,omitempty"`
	URL          string        `json:"url"`
	Method       string        `json:"method,omitempty"`
	UserAgent    string        `json:"user_agent,omitempty"`
	Status       int           `json:"status"`
	Action       string        `json:"action"`
	Category     string        `json:"category"`
	CategoryName string        `json:"category_name"`
	Score        int           `json:"anomaly_score"`
	RiskLevel    int           `json:"risk_level"`
	RuleID       string        `json:"rule_id,omitempty"`
	Rules        []string      `json:"rules,omitempty"`
	Message      string        `json:"message,omitempty"`
	Country      string        `json:"country,omitempty"`
	Matches      []event.Match `json:"matches,omitempty"`
}

// JSON formats an event; withRaw adds every matched rule with its data.
func JSON(ev event.Event, withRaw bool) string {
	var matches []event.Match
	if withRaw {
		matches = ev.Rules
	}
	b, _ := json.Marshal(JSONEvent{
		Time: ev.Time, Product: "modsecurity", Site: ev.Site, EventID: ev.ID, SrcIP: ev.SrcIP,
		Host: ev.Host, DstPort: ev.DstPort, URL: ev.URI, Method: ev.Method, UserAgent: ev.UserAgent,
		Status: ev.Status, Action: ev.ActionName(), Category: ev.Category,
		CategoryName: event.CategoryName(ev.Category), Score: ev.Score, RiskLevel: ev.Risk(),
		RuleID: ev.RuleID(), Rules: ev.RuleIDs(), Message: ev.Reason(), Country: ev.Country, Matches: matches,
	})
	return string(b)
}

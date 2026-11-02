package event

import "strings"

// Categories are the attack classes the panel groups events by, in the
// order they are shown. Codes are stable: alert rules and SIEM use them.
var Categories = []struct{ Code, Name string }{
	{"sqli", "SQL Injection"},
	{"xss", "XSS"},
	{"rce", "Command Injection"},
	{"php", "PHP Injection"},
	{"lfi", "Path Traversal / LFI"},
	{"rfi", "Remote File Inclusion"},
	{"java", "Java / Deserialization"},
	{"generic", "Code Injection"},
	{"session", "Session Fixation"},
	{"scanner", "Scanner"},
	{"protocol", "Protocol Violation"},
	{"method", "Method Not Allowed"},
	{"multipart", "Multipart Attack"},
	{"leakage", "Data Leakage"},
	{"webshell", "Web Shell"},
	{"panel", "Panel Deny List"},
	{"trap", "Path Trap"},
	{"custom", "Custom Rule"},
	{"other", "Other"},
}

// CategoryName is the English name of a category code.
func CategoryName(code string) string {
	for _, c := range Categories {
		if c.Code == code {
			return c.Name
		}
	}
	return code
}

// byPrefix maps the CRS rule id range (one rule file each) to a category.
var byPrefix = []struct{ prefix, code string }{
	{"942", "sqli"}, {"941", "xss"}, {"932", "rce"}, {"933", "php"}, {"930", "lfi"},
	{"931", "rfi"}, {"944", "java"}, {"934", "generic"}, {"943", "session"},
	{"913", "scanner"}, {"920", "protocol"}, {"921", "protocol"}, {"911", "method"},
	{"922", "multipart"}, {"955", "webshell"}, {"950", "leakage"}, {"951", "leakage"},
	{"952", "leakage"}, {"953", "leakage"}, {"954", "leakage"}, {"956", "leakage"},
}

// PanelRuleBase is the first id of the rules the panel writes.
const PanelRuleBase = 7710000

// RuleCategory classifies one rule id.
func RuleCategory(id string) string {
	if len(id) == 6 {
		for _, p := range byPrefix {
			if strings.HasPrefix(id, p.prefix) {
				return p.code
			}
		}
	}
	if strings.HasPrefix(id, "771") && len(id) == 7 {
		return "panel"
	}
	if strings.HasPrefix(id, "772") && len(id) == 7 {
		return "trap"
	}
	if len(id) != 6 || id[0] != '9' {
		return "custom"
	}
	return "other"
}

// Classify sets the category of e from its strongest rule.
func (e *Event) Classify() {
	if m := e.Top(); m != nil {
		e.Category = RuleCategory(m.ID)
		return
	}
	for _, m := range e.Rules {
		if m.Denied {
			e.Category = RuleCategory(m.ID)
			return
		}
	}
	e.Category = "other"
}

// scanRules fire almost only on scanners: a numeric or missing Host, a
// scanner User-Agent, requests for .env, .git and the like. The analysis
// page marks them so they are not mistaken for false positives.
var scanRules = map[string]bool{
	"920350": true, "920280": true, "913100": true, "913101": true, "913102": true,
	"913110": true, "913120": true, "930130": true, "920440": true,
}

func ScanRule(id string) bool { return scanRules[id] }

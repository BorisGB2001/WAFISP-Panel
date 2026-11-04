package web

import (
	"strings"
	"testing"
)

func TestCountryFunc(t *testing.T) {
	cc := countryFunc(nil, "ru") // no geo database
	if got := string(cc("192.168.1.10")); !strings.Contains(got, ">LAN<") || !strings.Contains(got, "Частная сеть") {
		t.Errorf("private address: %q", got)
	}
	if got := string(cc("192.168.0.0/16")); !strings.Contains(got, ">LAN<") {
		t.Errorf("private subnet: %q", got)
	}
	if got := cc("203.0.113.7"); got != "" {
		t.Errorf("public address without a database: %q, want nothing", got)
	}
	if got := cc("not an address"); got != "" {
		t.Errorf("garbage: %q", got)
	}
}

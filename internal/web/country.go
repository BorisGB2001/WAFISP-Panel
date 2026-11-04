package web

import (
	"html/template"
	"strings"

	"wafisp/internal/geo"
	"wafisp/internal/i18n"
)

// countryFunc is the "cc" template function: the two-letter country code
// shown after an address in tables, e.g. "DE" with the country name as a
// tooltip. Private addresses show "LAN", addresses the database cannot
// place show "—"; without a geo database public addresses show nothing.
// The code starts with a no-break space so it never wraps away from the
// address; templates write it right after the address: {{.IP}}{{cc .IP}}.
func countryFunc(g *geo.Geo, lang string) func(ip string) template.HTML {
	return func(ip string) template.HTML {
		if i := strings.IndexByte(ip, '/'); i >= 0 { // a subnet: its first address
			ip = ip[:i]
		}
		p := g.Lookup(ip)
		switch p.Country {
		case geo.Unknown, "":
			if g == nil {
				return ""
			}
			return template.HTML(`&nbsp;<small class="cc" title="` + template.HTMLEscapeString(i18n.T(lang, "Country unknown")) + `">—</small>`)
		case geo.Private:
			return template.HTML(`&nbsp;<small class="cc" title="` + template.HTMLEscapeString(i18n.T(lang, "Private network")) + `">LAN</small>`)
		}
		title := p.Name
		if p.City != "" {
			title += ", " + p.City
		}
		return template.HTML(`&nbsp;<small class="cc" title="` + template.HTMLEscapeString(title) + `">` +
			template.HTMLEscapeString(p.Country) + `</small>`)
	}
}

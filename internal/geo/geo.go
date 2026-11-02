package geo

import (
	"net/netip"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Place is where an address is, as far as the database knows.
type Place struct {
	Country string // ISO code, or one of the pseudo codes below
	Name    string // country name in English
	City    string
}

// Pseudo countries for addresses a geo database cannot place.
const (
	Private = "private"
	Unknown = "unknown"
)

// Geo looks up addresses in a MaxMind-format City or Country database,
// e.g. the GeoLite2-Country.mmdb ISPmanager keeps in /usr/share/GeoIP.
type Geo struct {
	db    *maxminddb.Reader
	mu    sync.Mutex
	cache map[netip.Addr]Place
}

// OpenGeo opens the database; a nil *Geo places public addresses as unknown.
func OpenGeo(path string) (*Geo, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &Geo{db: db, cache: map[netip.Addr]Place{}}, nil
}

func (g *Geo) Close() {
	if g != nil && g.db != nil {
		g.db.Close()
	}
}

type mmRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
}

func (g *Geo) Lookup(ip string) Place {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return Place{Country: Unknown}
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || isCGNAT(a) {
		return Place{Country: Private}
	}
	if g == nil || g.db == nil {
		return Place{Country: Unknown}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if p, ok := g.cache[a]; ok {
		return p
	}
	var rec mmRecord
	p := Place{Country: Unknown}
	if err := g.db.Lookup(a).Decode(&rec); err == nil && rec.Country.ISOCode != "" {
		p = Place{Country: rec.Country.ISOCode, Name: rec.Country.Names["en"], City: rec.City.Names["en"]}
	}
	if len(g.cache) > 200_000 {
		clear(g.cache)
	}
	g.cache[a] = p
	return p
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isCGNAT(a netip.Addr) bool { return cgnat.Contains(a) }

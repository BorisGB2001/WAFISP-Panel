package block

import (
	"context"
	"net/netip"
)

// Cloudflare are Cloudflare's networks (https://www.cloudflare.com/ips/).
// A site behind Cloudflare sees its edge servers as the clients unless
// nginx restores the real address, so blocking one of them cuts off every
// visitor that comes through it. The panel never blocks them unless
// block.block_cloudflare is set.
var Cloudflare = prefixes(
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// IsCloudflare tells whether ip (an address or subnet) is Cloudflare's.
func IsCloudflare(ip string) bool {
	p, ok := prefixOf(ip)
	if !ok {
		return false
	}
	for _, c := range Cloudflare {
		if c.Overlaps(p) {
			return true
		}
	}
	return false
}

func prefixOf(s string) (netip.Prefix, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	return p.Masked(), err == nil
}

// LiftProtected unblocks the entries that overlap a protected address, e.g.
// Cloudflare's, blocked before they were protected.
func (m *Manager) LiftProtected(ctx context.Context) ([]Entry, error) {
	return m.UnblockMany(ctx, func(e Entry) bool {
		p, ok := prefixOf(e.IP)
		if !ok {
			return false
		}
		for _, x := range m.Protected {
			if x.Overlaps(p) {
				return true
			}
		}
		return false
	})
}

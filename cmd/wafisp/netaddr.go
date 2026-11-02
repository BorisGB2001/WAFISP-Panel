package main

import (
	"net"
	"net/netip"
)

// netInterfaceAddrs lists the host's own addresses.
func netInterfaceAddrs() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if x, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, x.Unmap())
			}
		}
	}
	return out, nil
}

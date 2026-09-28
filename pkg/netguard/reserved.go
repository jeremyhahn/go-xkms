// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package netguard

import "net/netip"

// reservedPrefixes are the special-purpose ranges (RFC 6890 and its IANA
// registries) ReservedAddr treats as reserved in addition to the netip
// classifications it checks directly: loopback, private (RFC 1918 and
// RFC 4193), link-local, multicast and unspecified.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network" (RFC 791)
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space, CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments (RFC 6890)
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1 (RFC 5737)
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2 (RFC 5737)
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3 (RFC 5737)
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and limited broadcast (RFC 1112, RFC 919)
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 well-known prefix (RFC 6052)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64 (RFC 8215)
	netip.MustParsePrefix("100::/64"),        // discard-only (RFC 6666)
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments, incl. Teredo (RFC 2928)
	netip.MustParsePrefix("2001:db8::/32"),   // documentation (RFC 3849)
	netip.MustParsePrefix("2002::/16"),       // 6to4, which embeds an arbitrary IPv4 address (RFC 3056)
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local (RFC 3879)
}

// ReservedAddr reports whether addr is in a reserved or special-purpose
// range: loopback, private (RFC 1918, RFC 4193), link-local (which holds
// the 169.254.169.254 cloud metadata address), multicast, unspecified, or
// one of the special-purpose ranges in reservedPrefixes (CGNAT, the
// TEST-NETs, benchmarking, NAT64, 6to4, documentation and the rest). An
// IPv4-mapped IPv6 address is classified by the IPv4 address it carries, so
// ::ffff:127.0.0.1 is loopback.
//
// It is the one reserved-address classification in go-xkms: every dialer
// that points at an attacker-chosen destination -- the ACME
// challenge-validation client and the CA's AIA/CRL fetch client -- refuses
// exactly the addresses this reports, so an address one caller treats as
// reserved is reserved for the other too.
func ReservedAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, prefix := range reservedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

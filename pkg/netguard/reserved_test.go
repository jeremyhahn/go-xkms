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

import (
	"net/netip"
	"testing"
)

// TestReservedAddr_RefusesReservedRanges covers every range the merged
// policy refuses: the base netip classifications, the special-purpose
// prefixes (CGNAT, the TEST-NETs, benchmarking, IETF protocol
// assignments, NAT64, 6to4, documentation, deprecated site-local, "this
// network"), and IPv4-mapped IPv6 forms of each.
func TestReservedAddr_RefusesReservedRanges(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{
		"127.0.0.1",
		"::1",
		"10.1.2.3",
		"172.16.0.1",
		"192.168.0.1",
		"169.254.169.254", // link-local cloud metadata
		"fd00:ec2::254",   // AWS IPv6 metadata (ULA)
		"fe80::1",
		"0.0.0.0",
		"::",
		"224.0.0.1",
		"255.255.255.255",
		"100.64.0.1", // CGNAT shared space, Alibaba metadata
		"100.100.100.200",
		"192.0.0.192",      // IETF protocol assignments
		"198.18.0.1",       // benchmarking
		"192.0.2.1",        // TEST-NET-1
		"198.51.100.1",     // TEST-NET-2
		"203.0.113.1",      // TEST-NET-3
		"2001:db8::1",      // documentation
		"fec0::1",          // deprecated site-local
		"::ffff:127.0.0.1", // IPv4-mapped loopback
		"::ffff:10.0.0.1",  // IPv4-mapped private
		"64:ff9b::a00:1",   // NAT64 of 10.0.0.1
		"2002:a00:1::1",    // 6to4 of 10.0.0.1
	} {
		if !ReservedAddr(netip.MustParseAddr(addr)) {
			t.Errorf("ReservedAddr(%s) = false, want true", addr)
		}
	}
}

// TestReservedAddr_AllowsPublicAddresses proves a public unicast address,
// in either family and in IPv4-mapped IPv6 form, is not refused.
func TestReservedAddr_AllowsPublicAddresses(t *testing.T) {
	t.Parallel()
	for _, addr := range []string{
		"8.8.8.8",
		"1.1.1.1",
		"2001:4860::8888",
		"2606:4700:4700::1111",
		"::ffff:8.8.8.8",
	} {
		if ReservedAddr(netip.MustParseAddr(addr)) {
			t.Errorf("ReservedAddr(%s) = true, want false", addr)
		}
	}
}

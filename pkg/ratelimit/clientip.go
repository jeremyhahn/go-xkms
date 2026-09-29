// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package ratelimit

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// InvalidTrustedProxyError reports a trusted-proxy entry that is neither an
// IP address nor a CIDR prefix.
type InvalidTrustedProxyError struct {
	// Entry is the rejected configuration value.
	Entry string
}

// Error describes the rejected entry.
func (e *InvalidTrustedProxyError) Error() string {
	return "ratelimit: trusted proxy " + `"` + e.Entry + `"` + " is not an IP address or CIDR prefix"
}

// TrustedProxies is the set of peer addresses permitted to name the client
// in the X-Forwarded-For and X-Real-IP request headers. A request from any
// other peer is identified by its transport address alone, so a client
// cannot choose its own rate-limit bucket by sending a forwarding header.
//
// The nil *TrustedProxies trusts no proxy, which is the secure default.
type TrustedProxies struct {
	prefixes []netip.Prefix
}

// ParseTrustedProxies builds a TrustedProxies from IP addresses ("10.0.0.1")
// and CIDR prefixes ("10.0.0.0/8"). An empty list yields nil: no proxy is
// trusted. The first malformed entry fails the whole list with
// *InvalidTrustedProxyError, so a typo never silently drops a proxy.
func ParseTrustedProxies(entries []string) (*TrustedProxies, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if prefix, err := netip.ParsePrefix(trimmed); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(trimmed)
		if err != nil {
			return nil, &InvalidTrustedProxyError{Entry: entry}
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return &TrustedProxies{prefixes: prefixes}, nil
}

// Contains reports whether addr is a trusted proxy. It is false for every
// address on the nil *TrustedProxies.
func (t *TrustedProxies) Contains(addr netip.Addr) bool {
	if t == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range t.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ClientIP returns the address of the client that sent r.
//
// The transport peer is r.RemoteAddr with its port removed, so every
// connection from one host resolves to the same identity. Only when that peer
// is a trusted proxy are the forwarding headers consulted:
//
//  1. X-Forwarded-For is walked from the right — the entry the trusted proxy
//     itself appended — skipping further trusted proxies; the first untrusted
//     address is the client. Entries to its left were supplied by the client
//     and are never believed, so prepending forged hops cannot select a
//     bucket.
//  2. Otherwise X-Real-IP, when it holds a valid address.
//  3. Otherwise the peer address.
//
// A header value that does not parse as an IP address is ignored, so the
// returned identity is always an IP address (or the raw RemoteAddr when that
// carries none, as on a Unix socket) and its length is bounded.
func (t *TrustedProxies) ClientIP(r *http.Request) string {
	peer := remoteHost(r.RemoteAddr)
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil || !t.Contains(peerAddr) {
		return peer
	}

	if client, ok := t.forwardedClient(r.Header.Values("X-Forwarded-For")); ok {
		return client
	}
	if realIP, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return realIP.Unmap().String()
	}
	return peer
}

// forwardedClient walks the X-Forwarded-For hops right to left and returns the
// first address that is not a trusted proxy. ok is false when the header is
// absent, malformed, or names only trusted proxies.
func (t *TrustedProxies) forwardedClient(values []string) (string, bool) {
	hops := strings.Split(strings.Join(values, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		addr, err := netip.ParseAddr(hop)
		if err != nil {
			return "", false
		}
		addr = addr.Unmap()
		if !t.Contains(addr) {
			return addr.String(), true
		}
	}
	return "", false
}

// remoteHost strips the port from a transport address ("192.0.2.1:443",
// "[2001:db8::1]:443"). An address without a port is returned unchanged,
// minus any IPv6 brackets.
func remoteHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return strings.Trim(addr, "[]")
}

// ipv6RateLimitPrefixBits is the prefix length RateLimitKey masks an IPv6
// client address to. Residential and mobile ISPs commonly delegate a /64 (or
// shorter) to a single subscriber, so keying a bucket on the full address
// lets that subscriber evade a limiter by cycling through addresses within
// their own delegation; /64 is the smallest block IPv6 SLAAC assumes, so it
// is the coarsest prefix that still cannot span two unrelated subscribers.
const ipv6RateLimitPrefixBits = 64

// RateLimitKey folds a client address returned by ClientIP into the identity
// a rate limiter should bucket on. IPv4 addresses are returned unchanged: one
// bucket per address. IPv6 addresses are masked to their /64
// (ipv6RateLimitPrefixBits) so a client cannot escape a limiter by rotating
// through addresses an ISP delegates it within the same /64. A value that is
// not a valid IP address — a JWS key ID standing in for the client, or the
// raw RemoteAddr from a listener with no notion of ports — is returned
// unchanged, so callers can pass any ClientIP/ClientID result through this
// function unconditionally.
//
// RateLimitKey is for rate-limit bucketing only. Audit records keep the
// address ClientIP resolved at full precision; nothing here should feed an
// audit trail.
func RateLimitKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(ipv6RateLimitPrefixBits)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}

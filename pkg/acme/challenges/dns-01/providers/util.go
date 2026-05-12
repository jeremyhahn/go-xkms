// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package providers

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/miekg/dns"
)

// Default DNS settings
const (
	DefaultDNSTimeout  = 10 * time.Second
	DefaultDNSPort     = "53"
	DefaultTTL         = 120
	PropagationTimeout = 120 * time.Second
	PropagationPoll    = 4 * time.Second
)

// Default recursive nameservers used for DNS lookups
var DefaultNameservers = []string{
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// zoneCacheEntry represents a cached zone lookup result
type zoneCacheEntry struct {
	zone       string
	expiryTime time.Time
}

// zoneCache caches zone lookups to avoid repeated DNS queries
var (
	zoneCacheMu sync.RWMutex
	zoneCache   = make(map[string]zoneCacheEntry)
)

// ToFQDN converts a domain name to a fully qualified domain name by appending a trailing dot.
func ToFQDN(name string) string {
	if name == "" || strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// UnFQDN removes the trailing dot from a fully qualified domain name.
func UnFQDN(name string) string {
	return strings.TrimSuffix(name, ".")
}

// FindZoneByFQDN determines the zone apex for the given FQDN by recursing up the
// domain labels until a SOA record is found. Results are cached based on the TTL.
func FindZoneByFQDN(ctx context.Context, fqdn string, nameservers []string) (string, error) {
	if len(nameservers) == 0 {
		nameservers = DefaultNameservers
	}

	// Check cache first
	zoneCacheMu.RLock()
	entry, exists := zoneCache[fqdn]
	zoneCacheMu.RUnlock()

	if exists && time.Now().Before(entry.expiryTime) {
		return entry.zone, nil
	}

	// Remove expired entry if exists
	if exists {
		zoneCacheMu.Lock()
		delete(zoneCache, fqdn)
		zoneCacheMu.Unlock()
	}

	labelIndexes := dns.Split(fqdn)

	// Climb up the domain tree looking for the SOA record
	for _, index := range labelIndexes {
		domain := fqdn[index:]

		in, err := DNSQuery(ctx, domain, dns.TypeSOA, nameservers, true)
		if err != nil {
			return "", err
		}

		// NXDOMAIN means we need to climb higher
		if in.Rcode == dns.RcodeNameError {
			continue
		}

		// Any non-success response other than NXDOMAIN is an error
		if in.Rcode != dns.RcodeSuccess {
			return "", caerrors.DNSError("dns query for %s returned rcode %s", domain, dns.RcodeToString[in.Rcode])
		}

		// Skip if CNAME (SOA cannot exist at CNAME)
		if containsCNAME(in) {
			continue
		}

		// Look for SOA in answer
		for _, ans := range in.Answer {
			if soa, ok := ans.(*dns.SOA); ok {
				zone := soa.Hdr.Name

				// Cache the result
				zoneCacheMu.Lock()
				zoneCache[fqdn] = zoneCacheEntry{
					zone:       zone,
					expiryTime: time.Now().Add(time.Duration(soa.Hdr.Ttl) * time.Second),
				}
				zoneCacheMu.Unlock()

				return zone, nil
			}
		}
	}

	return "", caerrors.DNSError("could not find SOA record for %s", fqdn)
}

// DNSQuery performs a DNS query against the specified nameservers.
// It tries UDP first, then falls back to TCP on truncation or timeout.
func DNSQuery(ctx context.Context, fqdn string, rtype uint16, nameservers []string, recursive bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, rtype)
	m.SetEdns0(4096, false)
	m.RecursionDesired = recursive

	udpClient := &dns.Client{Net: "udp", Timeout: DefaultDNSTimeout}
	tcpClient := &dns.Client{Net: "tcp", Timeout: DefaultDNSTimeout}

	var lastErr error
	for _, ns := range nameservers {
		// Ensure nameserver has port
		if _, _, err := net.SplitHostPort(ns); err != nil {
			ns = net.JoinHostPort(ns, DefaultDNSPort)
		}

		// Try UDP first
		in, _, err := udpClient.ExchangeContext(ctx, m, ns)
		if err == nil && !in.Truncated {
			return in, nil
		}

		// Fall back to TCP on truncation or UDP error
		if in != nil && in.Truncated || err != nil {
			in, _, err = tcpClient.ExchangeContext(ctx, m, ns)
			if err == nil {
				return in, nil
			}
		}

		lastErr = err
	}

	if lastErr != nil {
		return nil, caerrors.DNSError("dns query for %s failed: %v", fqdn, lastErr)
	}
	return nil, caerrors.DNSError("dns query for %s failed: no nameservers responded", fqdn)
}

// containsCNAME checks if the DNS message contains a CNAME record.
func containsCNAME(msg *dns.Msg) bool {
	for _, ans := range msg.Answer {
		if _, ok := ans.(*dns.CNAME); ok {
			return true
		}
	}
	return false
}

// FollowCNAMEs follows CNAME records and returns the final target.
// Returns an error if a loop is detected.
func FollowCNAMEs(ctx context.Context, fqdn string, nameservers []string, visited ...string) (string, error) {
	if len(nameservers) == 0 {
		nameservers = DefaultNameservers
	}

	r, err := DNSQuery(ctx, fqdn, dns.TypeCNAME, nameservers, true)
	if err != nil {
		return "", err
	}

	if r.Rcode != dns.RcodeSuccess {
		return fqdn, nil
	}

	for _, rr := range r.Answer {
		cn, ok := rr.(*dns.CNAME)
		if !ok || cn.Hdr.Name != fqdn {
			continue
		}

		// Check for loops
		for _, v := range visited {
			if cn.Target == v {
				return "", caerrors.DNSError("CNAME loop detected: %s -> %s", fqdn, cn.Target)
			}
		}

		return FollowCNAMEs(ctx, cn.Target, nameservers, append(visited, fqdn)...)
	}

	return fqdn, nil
}

// FindBestMatch finds the longest matching zone from a list of zones for the given FQDN.
func FindBestMatch(fqdn string, zones ...string) (string, error) {
	var best string
	var bestLen int

	for _, zone := range zones {
		if strings.HasSuffix(fqdn, zone) && len(zone) > bestLen {
			best = zone
			bestLen = len(zone)
		}
	}

	if best == "" {
		return "", caerrors.DNSError("no matching zone found for %s", fqdn)
	}

	return best, nil
}

// WaitFor polls the given function until it returns true or times out.
// It respects context cancellation and the provided timeout, whichever comes first.
func WaitFor(timeout, interval time.Duration, f func() (bool, error)) error {
	return WaitForCtx(context.Background(), timeout, interval, f)
}

// WaitForCtx polls the given function until it returns true, times out, or the context is cancelled.
// It respects both the context deadline/cancellation and the provided timeout.
func WaitForCtx(ctx context.Context, timeout, interval time.Duration, f func() (bool, error)) error {
	// Create a timeout context that will cancel after the specified timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastErr error

	// Check immediately before starting the ticker loop
	done, err := f()
	if done {
		return nil
	}
	if err != nil {
		lastErr = err
	}

	for {
		select {
		case <-timeoutCtx.Done():
			// Context was cancelled or timed out
			if lastErr != nil {
				return caerrors.ChallengeTimeoutError("timeout waiting for condition: %v", lastErr)
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrPropagationTimeout
		case <-ticker.C:
			done, err := f()
			if done {
				return nil
			}
			if err != nil {
				lastErr = err
			}
		}
	}
}

// GetNameserversFromConfig gets nameservers from system configuration or returns defaults.
func GetNameserversFromConfig(configPath string) []string {
	if configPath == "" {
		configPath = "/etc/resolv.conf"
	}

	config, err := dns.ClientConfigFromFile(configPath)
	if err != nil || len(config.Servers) == 0 {
		return DefaultNameservers
	}

	servers := make([]string, 0, len(config.Servers))
	for _, server := range config.Servers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			servers = append(servers, net.JoinHostPort(server, DefaultDNSPort))
		} else {
			servers = append(servers, server)
		}
	}

	return servers
}

// ClearZoneCache clears the zone lookup cache. Useful for testing.
func ClearZoneCache() {
	zoneCacheMu.Lock()
	defer zoneCacheMu.Unlock()
	zoneCache = make(map[string]zoneCacheEntry)
}

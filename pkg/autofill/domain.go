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

package autofill

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ExtractDomain extracts the effective registrable domain from a URL.
// For multi-level subdomains like "login.okta.com", it returns "okta.com".
// For simple two-part domains like "github.com", it returns as-is.
// For IP addresses, it returns the IP address unchanged.
// Returns an empty string for empty or invalid input.
func ExtractDomain(rawURL string) string {
	hostname := ExtractHostname(rawURL)
	if hostname == "" {
		return ""
	}

	// If it's an IP address, return as-is.
	if net.ParseIP(hostname) != nil {
		return hostname
	}

	// Strip www. prefix before computing the registrable domain.
	hostname = stripWWW(hostname)

	// Split into labels and return the registrable (last two) parts.
	labels := strings.Split(hostname, ".")
	if len(labels) <= 2 {
		return hostname
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// ExtractHostname extracts the lowercase hostname from a URL, stripping
// any port, path, query, or fragment. IPv6 bracket notation is removed.
// Returns an empty string for empty or invalid input.
func ExtractHostname(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	rawURL = ensureScheme(rawURL)

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return ""
	}

	hostname := parsed.Hostname() // strips port and IPv6 brackets
	hostname = strings.ToLower(hostname)

	return hostname
}

// MatchesDomain reports whether candidateURL belongs to targetDomain.
// The match is case-insensitive and www-agnostic. A candidate hostname
// matches if it equals the target domain or is a proper subdomain of it
// (i.e., ends with "."+targetDomain). This prevents "evil-github.com"
// from matching "github.com".
// Returns false for empty inputs.
func MatchesDomain(candidateURL, targetDomain string) bool {
	if candidateURL == "" || targetDomain == "" {
		return false
	}

	hostname := ExtractHostname(candidateURL)
	if hostname == "" {
		return false
	}

	hostname = stripWWW(hostname)
	targetDomain = strings.ToLower(targetDomain)

	if hostname == targetDomain {
		return true
	}

	// Subdomain match: the hostname must end with ".targetDomain" to
	// ensure a dot boundary. This prevents "evil-github.com" from
	// matching "github.com".
	return strings.HasSuffix(hostname, "."+targetDomain)
}

// MatchesBaseDomain reports whether two hostnames share the same registrable
// domain (eTLD+1). For example, "us-east-2.signin.aws.amazon.com" and
// "855983325396.signin.aws.amazon.com" both have eTLD+1 "amazon.com" and
// would match. Returns false if either hostname is empty or is an IP address.
func MatchesBaseDomain(candidateURL, storedURL string) bool {
	candidateHost := ExtractHostname(candidateURL)
	storedHost := ExtractHostname(storedURL)

	if candidateHost == "" || storedHost == "" {
		return false
	}

	candidateHost = stripWWW(candidateHost)
	storedHost = stripWWW(storedHost)

	// IP addresses have no registrable domain; compare literally.
	if net.ParseIP(candidateHost) != nil || net.ParseIP(storedHost) != nil {
		return false
	}

	candidateBase, err := publicsuffix.EffectiveTLDPlusOne(candidateHost)
	if err != nil {
		return false
	}

	storedBase, err := publicsuffix.EffectiveTLDPlusOne(storedHost)
	if err != nil {
		return false
	}

	return candidateBase == storedBase
}

// MatchesPattern reports whether a hostname matches a glob pattern.
// Only leading wildcard patterns are supported: "*.example.com" matches
// "foo.example.com" and "a.b.example.com" but not "example.com" itself.
// A pattern without a wildcard is treated as an exact hostname match.
// Both the hostname and pattern are compared case-insensitively.
func MatchesPattern(hostname, pattern string) bool {
	if hostname == "" || pattern == "" {
		return false
	}

	hostname = strings.ToLower(stripWWW(hostname))
	pattern = strings.ToLower(strings.TrimSpace(pattern))

	// Leading wildcard: "*.example.com"
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		// The hostname must end with the suffix and be strictly longer
		// (i.e., "example.com" alone does not match "*.example.com").
		return strings.HasSuffix(hostname, suffix) && len(hostname) > len(suffix)
	}

	// No wildcard: exact match.
	return hostname == stripWWW(pattern)
}

// MatchesEntry reports whether a page domain matches a stored password entry.
// It checks in order:
//  1. Standard domain match (exact hostname or subdomain of stored URL)
//  2. Custom match patterns (if entry has MatchPatterns)
//  3. Base domain fallback (eTLD+1 comparison between page and stored URL)
//
// Returns true if any strategy matches.
func MatchesEntry(pageDomain string, entryURL string, matchPatterns []string) bool {
	if pageDomain == "" {
		return false
	}

	// Strategy 1: standard domain match against the stored URL's hostname.
	if entryURL != "" {
		storedHost := ExtractHostname(entryURL)
		storedHost = stripWWW(storedHost)
		if storedHost != "" && MatchesDomain(pageDomain, storedHost) {
			return true
		}
	}

	// Strategy 2: custom glob patterns.
	if len(matchPatterns) > 0 {
		pageHost := ExtractHostname(pageDomain)
		if pageHost == "" {
			pageHost = strings.ToLower(pageDomain)
		}
		for _, pat := range matchPatterns {
			if MatchesPattern(pageHost, pat) {
				return true
			}
		}
	}

	// Strategy 3: eTLD+1 base domain fallback.
	if entryURL != "" {
		if MatchesBaseDomain(pageDomain, entryURL) {
			return true
		}
	}

	return false
}

// NormalizeURL strips the scheme, port, path, query, and fragment from
// a URL and returns the lowercase hostname. This is functionally
// identical to ExtractHostname but is provided as a distinct named
// function for semantic clarity in call sites that deal with URL
// normalization rather than hostname extraction.
func NormalizeURL(rawURL string) string {
	return ExtractHostname(rawURL)
}

// ensureScheme prepends "https://" if rawURL has no scheme so that
// net/url.Parse produces a meaningful Host field.
func ensureScheme(rawURL string) string {
	if !strings.Contains(rawURL, "://") {
		return "https://" + rawURL
	}
	return rawURL
}

// stripWWW removes a leading "www." prefix from a hostname.
func stripWWW(hostname string) string {
	return strings.TrimPrefix(hostname, "www.")
}

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
	"testing"
)

// --- ExtractDomain ----------------------------------------------------------

func TestExtractDomain_ValidURLs(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "simple two-part domain",
			input:  "https://github.com",
			expect: "github.com",
		},
		{
			name:   "subdomain stripped to registrable",
			input:  "https://login.okta.com/app/sso",
			expect: "okta.com",
		},
		{
			name:   "www stripped",
			input:  "https://www.github.com",
			expect: "github.com",
		},
		{
			name:   "deep subdomain stripped",
			input:  "https://a.b.c.example.com/path",
			expect: "example.com",
		},
		{
			name:   "login subdomain",
			input:  "https://login.github.com",
			expect: "github.com",
		},
		{
			name:   "port stripped",
			input:  "https://example.com:8443/path",
			expect: "example.com",
		},
		{
			name:   "no scheme",
			input:  "github.com",
			expect: "github.com",
		},
		{
			name:   "no scheme with subdomain",
			input:  "login.okta.com",
			expect: "okta.com",
		},
		{
			name:   "ipv4 address",
			input:  "https://192.168.1.1:8080",
			expect: "192.168.1.1",
		},
		{
			name:   "ipv6 address",
			input:  "https://[::1]",
			expect: "::1",
		},
		{
			name:   "uppercase normalized",
			input:  "https://LOGIN.GITHUB.COM",
			expect: "github.com",
		},
		{
			name:   "query and fragment stripped",
			input:  "https://app.example.com/path?q=1#frag",
			expect: "example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractDomain(tc.input)
			if got != tc.expect {
				t.Errorf("ExtractDomain(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

func TestExtractDomain_InvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "empty string",
			input:  "",
			expect: "",
		},
		{
			name:   "scheme only",
			input:  "https://",
			expect: "",
		},
		{
			name:   "just colon slash slash",
			input:  "://",
			expect: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractDomain(tc.input)
			if got != tc.expect {
				t.Errorf("ExtractDomain(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

// --- ExtractHostname --------------------------------------------------------

func TestExtractHostname_ValidURLs(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "simple URL",
			input:  "https://github.com",
			expect: "github.com",
		},
		{
			name:   "with path",
			input:  "https://login.okta.com/app/sso",
			expect: "login.okta.com",
		},
		{
			name:   "with port",
			input:  "https://example.com:8443/path",
			expect: "example.com",
		},
		{
			name:   "no scheme",
			input:  "github.com",
			expect: "github.com",
		},
		{
			name:   "no scheme with subdomain",
			input:  "login.okta.com",
			expect: "login.okta.com",
		},
		{
			name:   "ipv4",
			input:  "https://192.168.1.1:8080",
			expect: "192.168.1.1",
		},
		{
			name:   "ipv6 brackets stripped",
			input:  "https://[::1]",
			expect: "::1",
		},
		{
			name:   "uppercase lowered",
			input:  "https://GITHUB.COM",
			expect: "github.com",
		},
		{
			name:   "www preserved in hostname",
			input:  "https://www.github.com",
			expect: "www.github.com",
		},
		{
			name:   "query and fragment stripped",
			input:  "https://example.com/page?q=1#section",
			expect: "example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractHostname(tc.input)
			if got != tc.expect {
				t.Errorf("ExtractHostname(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

func TestExtractHostname_InvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "empty string",
			input:  "",
			expect: "",
		},
		{
			name:   "scheme only",
			input:  "https://",
			expect: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractHostname(tc.input)
			if got != tc.expect {
				t.Errorf("ExtractHostname(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

// --- MatchesDomain ----------------------------------------------------------

func TestMatchesDomain_ValidMatches(t *testing.T) {
	tests := []struct {
		name         string
		candidateURL string
		targetDomain string
		expect       bool
	}{
		{
			name:         "exact match",
			candidateURL: "https://github.com",
			targetDomain: "github.com",
			expect:       true,
		},
		{
			name:         "subdomain match",
			candidateURL: "https://login.github.com",
			targetDomain: "github.com",
			expect:       true,
		},
		{
			name:         "www match",
			candidateURL: "https://www.github.com",
			targetDomain: "github.com",
			expect:       true,
		},
		{
			name:         "deep subdomain match",
			candidateURL: "https://a.b.c.github.com",
			targetDomain: "github.com",
			expect:       true,
		},
		{
			name:         "case insensitive candidate",
			candidateURL: "https://GITHUB.COM",
			targetDomain: "github.com",
			expect:       true,
		},
		{
			name:         "case insensitive target",
			candidateURL: "https://github.com",
			targetDomain: "GITHUB.COM",
			expect:       true,
		},
		{
			name:         "no scheme candidate",
			candidateURL: "login.github.com",
			targetDomain: "github.com",
			expect:       true,
		},
		{
			name:         "with port and path",
			candidateURL: "https://github.com:443/org/repo",
			targetDomain: "github.com",
			expect:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesDomain(tc.candidateURL, tc.targetDomain)
			if got != tc.expect {
				t.Errorf("MatchesDomain(%q, %q) = %v, want %v",
					tc.candidateURL, tc.targetDomain, got, tc.expect)
			}
		})
	}
}

func TestMatchesDomain_Rejections(t *testing.T) {
	tests := []struct {
		name         string
		candidateURL string
		targetDomain string
		expect       bool
	}{
		{
			name:         "evil subdomain rejected",
			candidateURL: "https://evil-github.com",
			targetDomain: "github.com",
			expect:       false,
		},
		{
			name:         "different domain",
			candidateURL: "https://gitlab.com",
			targetDomain: "github.com",
			expect:       false,
		},
		{
			name:         "partial suffix mismatch",
			candidateURL: "https://notgithub.com",
			targetDomain: "github.com",
			expect:       false,
		},
		{
			name:         "empty candidate",
			candidateURL: "",
			targetDomain: "github.com",
			expect:       false,
		},
		{
			name:         "empty target",
			candidateURL: "https://github.com",
			targetDomain: "",
			expect:       false,
		},
		{
			name:         "both empty",
			candidateURL: "",
			targetDomain: "",
			expect:       false,
		},
		{
			name:         "evil with deep subdomain",
			candidateURL: "https://login.evil-github.com",
			targetDomain: "github.com",
			expect:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesDomain(tc.candidateURL, tc.targetDomain)
			if got != tc.expect {
				t.Errorf("MatchesDomain(%q, %q) = %v, want %v",
					tc.candidateURL, tc.targetDomain, got, tc.expect)
			}
		})
	}
}

// --- NormalizeURL -----------------------------------------------------------

func TestNormalizeURL_ValidURLs(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "full URL stripped to hostname",
			input:  "https://example.com:8443/path?q=1#frag",
			expect: "example.com",
		},
		{
			name:   "http scheme stripped",
			input:  "http://www.example.com/page",
			expect: "www.example.com",
		},
		{
			name:   "no scheme handled",
			input:  "example.com",
			expect: "example.com",
		},
		{
			name:   "uppercase lowered",
			input:  "HTTPS://EXAMPLE.COM",
			expect: "example.com",
		},
		{
			name:   "ipv4 preserved",
			input:  "https://10.0.0.1:9090/api",
			expect: "10.0.0.1",
		},
		{
			name:   "ipv6 brackets stripped",
			input:  "https://[fe80::1]:443/",
			expect: "fe80::1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeURL(tc.input)
			if got != tc.expect {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

func TestNormalizeURL_InvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "empty string",
			input:  "",
			expect: "",
		},
		{
			name:   "scheme only",
			input:  "https://",
			expect: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeURL(tc.input)
			if got != tc.expect {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tc.input, got, tc.expect)
			}
		})
	}
}

// --- MatchesBaseDomain ------------------------------------------------------

func TestMatchesBaseDomain_ValidMatches(t *testing.T) {
	tests := []struct {
		name         string
		candidateURL string
		storedURL    string
	}{
		{
			name:         "AWS sibling subdomains",
			candidateURL: "us-east-2.signin.aws.amazon.com",
			storedURL:    "https://855983325396.signin.aws.amazon.com/console",
		},
		{
			name:         "same domain both bare",
			candidateURL: "github.com",
			storedURL:    "github.com",
		},
		{
			name:         "subdomain vs bare",
			candidateURL: "login.github.com",
			storedURL:    "https://github.com",
		},
		{
			name:         "deep subdomain vs different subdomain",
			candidateURL: "https://a.b.c.example.com",
			storedURL:    "https://x.y.example.com",
		},
		{
			name:         "www stripped on candidate",
			candidateURL: "https://www.example.com",
			storedURL:    "https://app.example.com",
		},
		{
			name:         "www stripped on stored",
			candidateURL: "https://app.example.com",
			storedURL:    "https://www.example.com",
		},
		{
			name:         "case insensitive",
			candidateURL: "https://LOGIN.GITHUB.COM",
			storedURL:    "https://api.github.com",
		},
		{
			name:         "co.uk ccTLD",
			candidateURL: "https://login.example.co.uk",
			storedURL:    "https://app.example.co.uk",
		},
		{
			name:         "com.au ccTLD",
			candidateURL: "https://mail.example.com.au",
			storedURL:    "https://www.example.com.au",
		},
		{
			name:         "google subdomains",
			candidateURL: "https://accounts.google.com",
			storedURL:    "https://mail.google.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesBaseDomain(tc.candidateURL, tc.storedURL)
			if !got {
				t.Errorf("MatchesBaseDomain(%q, %q) = false, want true",
					tc.candidateURL, tc.storedURL)
			}
		})
	}
}

func TestMatchesBaseDomain_Rejections(t *testing.T) {
	tests := []struct {
		name         string
		candidateURL string
		storedURL    string
	}{
		{
			name:         "different base domains",
			candidateURL: "https://login.github.com",
			storedURL:    "https://login.gitlab.com",
		},
		{
			name:         "different co.uk domains",
			candidateURL: "https://app.foo.co.uk",
			storedURL:    "https://app.bar.co.uk",
		},
		{
			name:         "IP candidate",
			candidateURL: "https://192.168.1.1",
			storedURL:    "https://example.com",
		},
		{
			name:         "IP stored",
			candidateURL: "https://example.com",
			storedURL:    "https://10.0.0.1",
		},
		{
			name:         "both IPs",
			candidateURL: "https://192.168.1.1",
			storedURL:    "https://192.168.1.1",
		},
		{
			name:         "empty candidate",
			candidateURL: "",
			storedURL:    "https://example.com",
		},
		{
			name:         "empty stored",
			candidateURL: "https://example.com",
			storedURL:    "",
		},
		{
			name:         "both empty",
			candidateURL: "",
			storedURL:    "",
		},
		{
			name:         "evil suffix attack",
			candidateURL: "https://evil-amazon.com",
			storedURL:    "https://signin.aws.amazon.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesBaseDomain(tc.candidateURL, tc.storedURL)
			if got {
				t.Errorf("MatchesBaseDomain(%q, %q) = true, want false",
					tc.candidateURL, tc.storedURL)
			}
		})
	}
}

// --- MatchesPattern ---------------------------------------------------------

func TestMatchesPattern_ValidMatches(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		pattern  string
	}{
		{
			name:     "wildcard matches subdomain",
			hostname: "foo.example.com",
			pattern:  "*.example.com",
		},
		{
			name:     "wildcard matches deep subdomain",
			hostname: "a.b.c.example.com",
			pattern:  "*.example.com",
		},
		{
			name:     "wildcard with AWS signin",
			hostname: "855983325396.signin.aws.amazon.com",
			pattern:  "*.signin.aws.amazon.com",
		},
		{
			name:     "wildcard with different AWS account",
			hostname: "us-east-2.signin.aws.amazon.com",
			pattern:  "*.signin.aws.amazon.com",
		},
		{
			name:     "exact match without wildcard",
			hostname: "example.com",
			pattern:  "example.com",
		},
		{
			name:     "exact match case insensitive",
			hostname: "EXAMPLE.COM",
			pattern:  "example.com",
		},
		{
			name:     "wildcard case insensitive",
			hostname: "FOO.EXAMPLE.COM",
			pattern:  "*.example.com",
		},
		{
			name:     "exact with www stripped",
			hostname: "www.example.com",
			pattern:  "example.com",
		},
		{
			name:     "pattern with whitespace trimmed",
			hostname: "foo.example.com",
			pattern:  "  *.example.com  ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesPattern(tc.hostname, tc.pattern)
			if !got {
				t.Errorf("MatchesPattern(%q, %q) = false, want true",
					tc.hostname, tc.pattern)
			}
		})
	}
}

func TestMatchesPattern_Rejections(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		pattern  string
	}{
		{
			name:     "bare domain does not match wildcard",
			hostname: "example.com",
			pattern:  "*.example.com",
		},
		{
			name:     "different domain",
			hostname: "foo.other.com",
			pattern:  "*.example.com",
		},
		{
			name:     "evil suffix attack on wildcard",
			hostname: "evil-example.com",
			pattern:  "*.example.com",
		},
		{
			name:     "exact mismatch",
			hostname: "other.com",
			pattern:  "example.com",
		},
		{
			name:     "empty hostname",
			hostname: "",
			pattern:  "*.example.com",
		},
		{
			name:     "empty pattern",
			hostname: "foo.example.com",
			pattern:  "",
		},
		{
			name:     "both empty",
			hostname: "",
			pattern:  "",
		},
		{
			name:     "partial domain suffix attack",
			hostname: "notexample.com",
			pattern:  "*.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesPattern(tc.hostname, tc.pattern)
			if got {
				t.Errorf("MatchesPattern(%q, %q) = true, want false",
					tc.hostname, tc.pattern)
			}
		})
	}
}

// --- MatchesEntry -----------------------------------------------------------

func TestMatchesEntry_CombinedStrategies(t *testing.T) {
	tests := []struct {
		name          string
		pageDomain    string
		entryURL      string
		matchPatterns []string
		expect        bool
	}{
		// Strategy 1: standard domain match
		{
			name:       "exact domain match via standard",
			pageDomain: "https://github.com",
			entryURL:   "https://github.com/settings",
			expect:     true,
		},
		{
			name:       "subdomain match via standard",
			pageDomain: "login.github.com",
			entryURL:   "https://github.com",
			expect:     true,
		},
		{
			name:       "www match via standard",
			pageDomain: "https://www.github.com",
			entryURL:   "https://github.com",
			expect:     true,
		},

		// Strategy 2: custom patterns
		{
			name:          "wildcard pattern match",
			pageDomain:    "us-east-2.signin.aws.amazon.com",
			entryURL:      "",
			matchPatterns: []string{"*.signin.aws.amazon.com"},
			expect:        true,
		},
		{
			name:          "multiple patterns first matches",
			pageDomain:    "app.example.com",
			entryURL:      "",
			matchPatterns: []string{"*.example.com", "*.other.com"},
			expect:        true,
		},
		{
			name:          "multiple patterns second matches",
			pageDomain:    "app.other.com",
			entryURL:      "",
			matchPatterns: []string{"*.example.com", "*.other.com"},
			expect:        true,
		},
		{
			name:          "pattern with entry URL that does not standard-match",
			pageDomain:    "us-east-2.signin.aws.amazon.com",
			entryURL:      "https://855983325396.signin.aws.amazon.com/console",
			matchPatterns: []string{"*.signin.aws.amazon.com"},
			expect:        true,
		},

		// Strategy 3: base domain fallback
		{
			name:       "AWS sibling subdomains via base domain",
			pageDomain: "us-east-2.signin.aws.amazon.com",
			entryURL:   "https://855983325396.signin.aws.amazon.com/console",
			expect:     true,
		},
		{
			name:       "different subdomains same base domain",
			pageDomain: "https://accounts.google.com",
			entryURL:   "https://mail.google.com",
			expect:     true,
		},
		{
			name:       "co.uk base domain match",
			pageDomain: "login.example.co.uk",
			entryURL:   "https://app.example.co.uk",
			expect:     true,
		},

		// No match
		{
			name:       "completely different domains",
			pageDomain: "https://github.com",
			entryURL:   "https://gitlab.com",
			expect:     false,
		},
		{
			name:          "no match with patterns",
			pageDomain:    "https://evil.com",
			entryURL:      "https://github.com",
			matchPatterns: []string{"*.example.com"},
			expect:        false,
		},
		{
			name:       "empty page domain",
			pageDomain: "",
			entryURL:   "https://github.com",
			expect:     false,
		},
		{
			name:       "empty entry URL and no patterns",
			pageDomain: "github.com",
			entryURL:   "",
			expect:     false,
		},
		{
			name:       "evil suffix attack",
			pageDomain: "https://evil-github.com",
			entryURL:   "https://github.com",
			expect:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchesEntry(tc.pageDomain, tc.entryURL, tc.matchPatterns)
			if got != tc.expect {
				t.Errorf("MatchesEntry(%q, %q, %v) = %v, want %v",
					tc.pageDomain, tc.entryURL, tc.matchPatterns, got, tc.expect)
			}
		})
	}
}

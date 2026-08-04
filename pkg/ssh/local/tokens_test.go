// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package local

import "testing"

func TestExpandTokens(t *testing.T) {
	cases := []struct {
		name       string
		pattern    string
		homeDir    string
		targetHost string
		remoteUser string
		port       int
		want       string
	}{
		{
			name:    "empty pattern",
			pattern: "",
			want:    "",
		},
		{
			name:    "leading tilde slash",
			pattern: "~/.ssh/id_ed25519",
			homeDir: "/home/alice",
			want:    "/home/alice/.ssh/id_ed25519",
		},
		{
			name:    "tilde only in the middle is literal",
			pattern: "foo~/bar",
			homeDir: "/home/alice",
			want:    "foo~/bar",
		},
		{
			name:    "percent d expands to home",
			pattern: "%d/.ssh/id_rsa",
			homeDir: "/home/bob",
			want:    "/home/bob/.ssh/id_rsa",
		},
		{
			name:       "percent h expands to target host",
			pattern:    "/keys/%h",
			targetHost: "example.com",
			want:       "/keys/example.com",
		},
		{
			name:       "percent r expands to remote user",
			pattern:    "/keys/%r",
			remoteUser: "alice",
			want:       "/keys/alice",
		},
		{
			name:    "percent p expands to port",
			pattern: "/keys/%p",
			port:    2222,
			want:    "/keys/2222",
		},
		{
			name:    "percent percent expands to a literal percent",
			pattern: "100%%done",
			want:    "100%done",
		},
		{
			name:    "unknown token left verbatim",
			pattern: "%L-unused",
			want:    "%L-unused",
		},
		{
			name:       "combination of every non-tilde token in one pattern",
			pattern:    "prefix-%d-%h-%r-%p-%%-tail",
			homeDir:    "/home/carol",
			targetHost: "host.example.com",
			remoteUser: "carol",
			port:       22,
			want:       "prefix-/home/carol-host.example.com-carol-22-%-tail",
		},
		{
			name:       "leading tilde slash combined with a following percent token",
			pattern:    "~/%h",
			homeDir:    "/home/carol",
			targetHost: "host.example.com",
			want:       "/home/carol/host.example.com",
		},
		{
			name:    "trailing percent with nothing after it is left as-is",
			pattern: "path-ends-with-%",
			want:    "path-ends-with-%",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expandTokens(tc.pattern, tc.homeDir, tc.targetHost, tc.remoteUser, tc.port)
			if got != tc.want {
				t.Errorf("expandTokens(%q) = %q, want %q", tc.pattern, got, tc.want)
			}
		})
	}
}

// TestExpandTokens_DoubledPercentDoesNotReenableSubstitution proves the
// single-pass invariant: a literal "%" produced by "%%" must not be
// re-scanned as the start of a new token, even when the following
// character would otherwise form a valid one.
func TestExpandTokens_DoubledPercentDoesNotReenableSubstitution(t *testing.T) {
	got := expandTokens("%%h", "", "example.com", "", 0)
	if got != "%h" {
		t.Errorf("expandTokens(%%%%h) = %q, want literal %%h (not re-expanded to target host)", got)
	}
}

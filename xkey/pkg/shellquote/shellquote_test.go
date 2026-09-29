// Copyright (c) 2025-2026 Jeremy Hahn
// Copyright (c) 2025-2026 Automate The Things, LLC
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

package shellquote

import "testing"

// TestSingleQuote verifies that values containing POSIX sh metacharacters —
// "$", backticks, a literal single quote, and whitespace — are rendered as
// exact literal text once substituted into a single-quoted shell string.
// Go's fmt "%q" verb, which this package replaces at every call site that
// interpolates a value into a generated shell script, does not have this
// property: it escapes for a Go string literal, not a POSIX shell one, and
// leaves "$" and backticks untouched.
func TestSingleQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain path",
			input: "/usr/local/bin/xkey",
			want:  "'/usr/local/bin/xkey'",
		},
		{
			name:  "dollar sign is not expanded",
			input: "$HOME/bin",
			want:  "'$HOME/bin'",
		},
		{
			name:  "backticks are not command-substituted",
			input: "a`id`b",
			want:  "'a`id`b'",
		},
		{
			name:  "embedded space",
			input: "path with spaces/xkey",
			want:  "'path with spaces/xkey'",
		},
		{
			name:  "single quote is escaped",
			input: "it's",
			want:  `'it'\''s'`,
		},
		{
			name:  "empty string",
			input: "",
			want:  "''",
		},
		{
			name:  "mixed metacharacters",
			input: `$HOME/it's ` + "`whoami`",
			want:  `'$HOME/it'\''s ` + "`whoami`'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SingleQuote(tt.input); got != tt.want {
				t.Errorf("SingleQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

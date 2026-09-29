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

// Package shellquote renders values for safe interpolation into generated
// POSIX shell scripts.
//
// Go's fmt "%q" verb escapes a string for a Go string literal, not a POSIX
// shell one: it leaves "$" and backtick untouched, so a value containing
// either is still subject to shell expansion when substituted inside a
// double-quoted sh string. Values that end up in a generated script —
// filesystem paths derived from a user's home directory, extension IDs,
// installed binary paths — are not attacker-controlled in the usual sense,
// but they are still outside this program's control, so they are quoted the
// same way any other untrusted string would be.
package shellquote

import "strings"

// SingleQuote returns s wrapped in single quotes, safe for interpolation
// into a POSIX shell script. Inside single quotes, sh performs no expansion
// at all: not "$", not backticks, not "\". So the only character that needs
// escaping is the single quote itself, which is done by closing the quoted
// string, emitting a backslash-escaped literal quote, and reopening it.
func SingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

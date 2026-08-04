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

import (
	"strconv"
	"strings"
)

// expandTokens expands the ssh_config(5) tokens ssh(1) recognizes in
// IdentityFile and IdentityAgent values:
//
//   - A leading "~/" is replaced with homeDir.
//   - "%d" expands to homeDir.
//   - "%h" expands to targetHost.
//   - "%r" expands to remoteUser.
//   - "%p" expands to the decimal port.
//   - "%%" expands to a literal "%".
//   - Any other "%x" sequence is left verbatim (ssh(1) supports additional
//     tokens — %L, %l, %n, %C, etc. — that this package has no value for;
//     rather than guess, we leave them untouched for the caller to
//     interpret or reject).
//
// The whole pattern is expanded in a single left-to-right pass over the
// original bytes, so substituted content (which may itself contain "%" or
// "~") is never re-scanned for further tokens — "%%h" therefore expands to
// the literal string "%h", not to targetHost.
func expandTokens(pattern, homeDir, targetHost, remoteUser string, port int) string {
	if pattern == "" {
		return pattern
	}

	s := pattern
	var b strings.Builder
	b.Grow(len(pattern))

	if strings.HasPrefix(s, "~/") {
		b.WriteString(homeDir)
		b.WriteByte('/')
		s = s[2:]
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		switch s[i+1] {
		case '%':
			b.WriteByte('%')
		case 'd':
			b.WriteString(homeDir)
		case 'h':
			b.WriteString(targetHost)
		case 'r':
			b.WriteString(remoteUser)
		case 'p':
			b.WriteString(strconv.Itoa(port))
		default:
			// Unknown token: preserve both characters verbatim.
			b.WriteByte(c)
			b.WriteByte(s[i+1])
		}
		i++ // consume the token's second character too
	}

	return b.String()
}

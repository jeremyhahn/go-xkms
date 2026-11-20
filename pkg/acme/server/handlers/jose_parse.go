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

package handlers

import (
	"strings"
	"unicode"

	"github.com/go-jose/go-jose/v4"
)

// parseSignedAny parses a JWS in either serialization, as the
// jose.ParseSigned of go-jose v4.1.6 did: the input is the JSON
// serialization when it starts with '{' once every Unicode white space
// character is removed, and is then parsed as given; otherwise it is the
// compact serialization, parsed with the white space removed.
func parseSignedAny(s string, algs []jose.SignatureAlgorithm) (*jose.JSONWebSignature, error) {
	stripped := stripWhitespace(s)
	if strings.HasPrefix(stripped, "{") {
		return jose.ParseSignedJSON(s, algs)
	}
	return jose.ParseSignedCompact(stripped, algs)
}

// stripWhitespace removes every Unicode white space character from s.
func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

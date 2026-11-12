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

package jwe

import (
	"strings"
	"unicode"

	"github.com/go-jose/go-jose/v4"
)

// parseEncryptedAny parses a JWE in either serialization, as the
// jose.ParseEncrypted of go-jose v4.1.6 did: every Unicode white space
// character is removed from the input, and the result is parsed as the
// JSON serialization when it starts with '{', as the compact
// serialization otherwise.
func parseEncryptedAny(s string, keyAlgs []jose.KeyAlgorithm, encs []jose.ContentEncryption) (*jose.JSONWebEncryption, error) {
	s = stripWhitespace(s)
	if strings.HasPrefix(s, "{") {
		return jose.ParseEncryptedJSON(s, keyAlgs, encs)
	}
	return jose.ParseEncryptedCompact(s, keyAlgs, encs)
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

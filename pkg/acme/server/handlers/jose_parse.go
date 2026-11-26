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

	"github.com/go-jose/go-jose/v4"
)

// parseSignedAny parses a JWS in either serialization: the JSON
// serialization when the input starts with '{' after white space, the
// compact serialization otherwise.
func parseSignedAny(s string, algs []jose.SignatureAlgorithm) (*jose.JSONWebSignature, error) {
	if strings.HasPrefix(strings.TrimLeft(s, " \t\r\n"), "{") {
		return jose.ParseSignedJSON(s, algs)
	}
	return jose.ParseSignedCompact(s, algs)
}

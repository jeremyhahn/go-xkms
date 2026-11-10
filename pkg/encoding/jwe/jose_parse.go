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

	"github.com/go-jose/go-jose/v4"
)

// parseEncryptedAny parses a JWE in either serialization: the JSON
// serialization when the input starts with '{' after white space, the
// compact serialization otherwise.
func parseEncryptedAny(s string, keyAlgs []jose.KeyAlgorithm, encs []jose.ContentEncryption) (*jose.JSONWebEncryption, error) {
	if strings.HasPrefix(strings.TrimLeft(s, " \t\r\n"), "{") {
		return jose.ParseEncryptedJSON(s, keyAlgs, encs)
	}
	return jose.ParseEncryptedCompact(s, keyAlgs, encs)
}

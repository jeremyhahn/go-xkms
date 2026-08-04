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

package server

import "github.com/go-jose/go-jose/v4"

// AllowedJOSEAlgorithms defines the signature algorithms permitted for ACME JWS operations.
// These algorithms are allowed for signing account keys and JWS protected headers per RFC 8555.
//
// Supported algorithms:
//   - RSA: RS256, RS384, RS512, PS256, PS384, PS512
//   - ECDSA: ES256, ES384, ES512
//   - EdDSA: EdDSA
var AllowedJOSEAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, // RSASSA-PKCS1-v1_5 with SHA-256
	jose.RS384, // RSASSA-PKCS1-v1_5 with SHA-384
	jose.RS512, // RSASSA-PKCS1-v1_5 with SHA-512
	jose.PS256, // RSASSA-PSS with SHA-256
	jose.PS384, // RSASSA-PSS with SHA-384
	jose.PS512, // RSASSA-PSS with SHA-512
	jose.ES256, // ECDSA with SHA-256
	jose.ES384, // ECDSA with SHA-384
	jose.ES512, // ECDSA with SHA-512
	jose.EdDSA, // EdDSA signature algorithm
}

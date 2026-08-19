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

package fips

import "strings"

// approvedAlgorithms is the set of key-algorithm identifiers a FIPS 140-3
// deployment may use, spelled exactly as the key-ID grammar accepts them
// (pkg/validation and pkg/xkms both admit several aliases per algorithm).
//
// It is an allowlist rather than a denylist so the control fails closed: an
// algorithm added to a caller's own list is refused in FIPS mode until it is
// added here deliberately, instead of being admitted by omission.
//
// What is deliberately absent, and why:
//
//   - x25519, x448 — SP 800-56A Rev. 3 approves only the NIST curves and finite
//     field groups for key agreement. Go agrees: under GODEBUG=fips140=only,
//     crypto/ecdh rejects X25519 with "use of X25519 is not allowed in FIPS
//     140-only mode", so a FIPS deployment cannot complete the exchange anyway.
//     ECDH P-256/384/521 is the approved substitute.
//   - chacha20-poly1305, xchacha20-poly1305 — not FIPS-approved AEADs.
//     AES-GCM is the approved substitute (see pkg/crypto/aead).
//   - frost-* — RFC 9591 threshold Schnorr is not a FIPS-approved signature
//     scheme in any of its ciphersuites, including frost-p256: the approval is
//     of the scheme, not merely of the curve underneath it.
//
// Ed25519/Ed448 (FIPS 186-5), ML-DSA (FIPS 204) and ML-KEM (FIPS 203) are
// approved algorithms. go-xkms reaches ML-DSA and Ed448 through
// github.com/cloudflare/circl, so admitting them asserts an approved algorithm,
// not a validated implementation; a deployment that must claim a validated
// module has a narrower list than this one.
var approvedAlgorithms = map[string]struct{}{
	// Asymmetric signature algorithms
	"rsa":        {},
	"ecdsa-p256": {}, "ecdsa-p-256": {}, "p256": {}, "p-256": {},
	"ecdsa-p384": {}, "ecdsa-p-384": {}, "p384": {}, "p-384": {},
	"ecdsa-p521": {}, "ecdsa-p-521": {}, "p521": {}, "p-521": {},
	"ed25519": {},
	"ed448":   {},
	// Symmetric algorithms
	"aes128-gcm": {}, "aes128": {},
	"aes192-gcm": {}, "aes192": {},
	"aes256-gcm": {}, "aes256": {},
	// Post-quantum signature algorithms (ML-DSA, FIPS 204)
	"ml-dsa-44": {}, "mldsa44": {},
	"ml-dsa-65": {}, "mldsa65": {},
	"ml-dsa-87": {}, "mldsa87": {},
	// Post-quantum key encapsulation algorithms (ML-KEM, FIPS 203)
	"ml-kem-512": {}, "mlkem512": {},
	"ml-kem-768": {}, "mlkem768": {},
	"ml-kem-1024": {}, "mlkem1024": {},
	// HMAC algorithms
	"hmac-sha256": {}, "hmac-sha384": {}, "hmac-sha512": {},
}

// ApprovedAlgorithm reports whether algo is a FIPS-approved key algorithm.
// The comparison is case-insensitive, matching the key-ID grammar.
//
// It answers only "is this algorithm approved" and does not consider whether
// FIPS mode is active — callers pair it with AlgorithmPermitted, or with their
// own policy, so the approved set stays inspectable in either build.
func ApprovedAlgorithm(algo string) bool {
	_, ok := approvedAlgorithms[strings.ToLower(algo)]
	return ok
}

// AlgorithmPermitted reports whether algo may be used in the current process.
// Outside FIPS mode every algorithm the caller already accepts is permitted;
// in FIPS mode only the approved set is.
//
// The predicate ORs the build-time and runtime signals for the reason given on
// Compiled: a FIPS-compiled shared library carries no GOFIPS140 in the process
// that loads it, so Enabled alone would let it accept non-approved algorithms.
func AlgorithmPermitted(algo string) bool {
	if !Compiled() && !Enabled() {
		return true
	}
	return ApprovedAlgorithm(algo)
}

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

// Package kdf is the canonical home for every key derivation function in
// go-xkms. Nothing else in the tree implements a KDF: the backends, the
// service layer, and the PKCS#11 module all reach these adapters, either
// directly or through types.KDFParams.Derive.
//
// Adapters
//
//   - HKDF (RFC 5869)
//   - PBKDF2 (RFC 8018)
//   - Argon2 / Argon2i / Argon2id
//   - NIST SP 800-108r1 Counter, Feedback, and Double-Pipeline Iteration modes
//   - ANSI X9.63 concatenation KDF
//   - NIST SP 800-56A concatenation KDF
//
// # BREAKING CHANGE: SP 800-108 no longer derives with HKDF
//
// Affected algorithm labels:
//
//	types.KDFAlgorithmSP800108Counter  ("SP800-108-COUNTER")
//	types.KDFAlgorithmSP800108Feedback ("SP800-108-FEEDBACK")
//
// What changed. The ECDH key agreement path in the backends previously
// accepted these two labels and derived the key with HKDF-Expand. HKDF and
// SP 800-108 have different constructions, so every key produced under those
// labels was not the key the label promised, and any FIPS claim resting on
// the label was false. Those labels now run the real SP 800-108r1 fixed-input
// construction:
//
//	Counter:  K(i) = PRF(KDK, [i]_r || Label || 0x00 || Context || [L]_2)
//	Feedback: K(i) = PRF(KDK, K(i-1) || [i]_r || Label || 0x00 || Context || [L]_2)
//
// with PRF = HMAC under the caller's configured hash.
//
// Blast radius. Keys derived under these two labels do not reproduce. HKDF,
// X9.63, and SP 800-56A derivations are bit-for-bit unchanged, as are the
// SP 800-108 derivations that already ran through this package (the
// DeriveKey service verb and its gRPC equivalent) — those were always
// correct, and their output is unchanged by this work.
//
// The parameters the two labels consume also changed. SP 800-108 has no salt
// and no HKDF info; it takes a Label and a Context. types.KDFParams.Salt and
// types.KDFParams.Info are therefore rejected for these labels rather than
// silently dropped, so a caller that supplied them gets a typed error instead
// of a key derived from inputs it did not choose. Supply
// types.KDFParams.Label and types.KDFParams.Context instead.
//
// What an operator must re-derive. Any symmetric key an application obtained
// from DeriveKeyECDH with KDFAlgorithm "SP800-108-COUNTER" or
// "SP800-108-FEEDBACK" must be re-derived, and anything encrypted or
// authenticated under such a key must be re-wrapped before upgrading. xkms
// itself never persists these derived keys — DeriveKeyECDH returns the key to
// the caller and keeps no copy — so there is no xkms-side data migration.
// Material held by an application that stored such a key is outside xkms and
// must be handled by that application.
//
// No compatibility shim and no legacy mode flag exist by design: a caller
// that needs the old bytes was never getting SP 800-108 and should ask for
// HKDF explicitly.
package kdf

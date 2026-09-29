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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"

// Key-derivation surface re-exported so the xkey GUI/CLI use the canonical
// pkg/crypto/kdf HKDF adapter through the SDK. The KDFParams identifier is
// prefixed Crypto* because the bare KDFParams SDK name already aliases the
// types.KDFParams key-agreement parameter struct.

// HKDFAdapter implements the HKDF key-derivation function.
type HKDFAdapter = kdf.HKDFAdapter

// AlgorithmHKDF identifies the HKDF key-derivation algorithm.
const AlgorithmHKDF = kdf.AlgorithmHKDF

// CryptoKDFParams holds parameters for a pkg/crypto/kdf derivation. It is
// distinct from KDFParams (= types.KDFParams), which describes key-agreement KDF
// parameters.
type CryptoKDFParams = kdf.KDFParams

// Password-based key derivation, re-exported so the xkey backup paths derive
// file-encryption keys through the one canonical FIPS-aware hasher
// (Argon2id, or PBKDF2-SHA256 when the Go FIPS 140 module is enabled) and
// persist the salt and cost parameters beside the ciphertext.

// PasswordHasher derives keys from passwords with a versioned, salted KDF.
type PasswordHasher = kdf.PasswordHasher

// PasswordHashVersion identifies a PasswordHasher derivation profile.
type PasswordHashVersion = kdf.HashVersion

// PasswordKeyParams is the persisted record of one password-based key
// derivation: version, algorithm, cost parameters and salt.
type PasswordKeyParams = kdf.PasswordKeyParams

// NewFIPSAwareHasher returns a PasswordHasher that uses Argon2id, or
// PBKDF2-SHA256 when the Go FIPS 140 module is enabled.
func NewFIPSAwareHasher() *PasswordHasher { return kdf.NewFIPSAwareHasher() }

// Password key-derivation errors.
var (
	// ErrPasswordHashInvalidVersion indicates an unknown hasher version.
	ErrPasswordHashInvalidVersion = kdf.ErrHasherInvalidVersion

	// ErrPasswordHashInvalidPassword indicates an empty password.
	ErrPasswordHashInvalidPassword = kdf.ErrHasherInvalidPassword

	// ErrPasswordHashInvalidSalt indicates a missing or short salt.
	ErrPasswordHashInvalidSalt = kdf.ErrHasherInvalidSalt

	// ErrPasswordHashParamsMismatch indicates a PasswordKeyParams record
	// whose algorithm or costs differ from the ones its version pins.
	ErrPasswordHashParamsMismatch = kdf.ErrHasherParamsMismatch
)

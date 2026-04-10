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

// Package fips provides FIPS 140 mode detection and algorithm selection.
//
// When the GOFIPS140 environment variable is set to a non-empty value,
// FIPS-compliant algorithm defaults are returned by the KDF selection
// functions. This allows the rest of the system to transparently adapt
// its cryptographic choices based on the runtime FIPS policy.
package fips

import "os"

const (
	// EnvGOFIPS140 is the environment variable that controls FIPS 140 mode.
	EnvGOFIPS140 = "GOFIPS140"

	// KDFArgon2id is the Argon2id key derivation function identifier.
	KDFArgon2id = "argon2id"

	// KDFPBKDF2 is the PBKDF2 key derivation function identifier.
	KDFPBKDF2 = "pbkdf2"
)

// Enabled reports whether FIPS 140 mode is active. It returns true when the
// GOFIPS140 environment variable is set to a non-empty value.
func Enabled() bool {
	return os.Getenv(EnvGOFIPS140) != ""
}

// DefaultKDF returns the default key derivation function identifier.
// In FIPS mode it returns "pbkdf2"; otherwise it returns "argon2id".
func DefaultKDF() string {
	if Enabled() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}

// DefaultLUKSKDF returns the default LUKS key derivation function identifier.
// In FIPS mode it returns "pbkdf2"; otherwise it returns "argon2id".
func DefaultLUKSKDF() string {
	if Enabled() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}

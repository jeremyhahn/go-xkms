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

import (
	"crypto/fips140"
	"os"
)

const (
	// EnvGOFIPS140 is the environment variable that controls FIPS 140 mode.
	EnvGOFIPS140 = "GOFIPS140"

	// KDFArgon2id is the Argon2id key derivation function identifier.
	KDFArgon2id = "argon2id"

	// KDFPBKDF2 is the PBKDF2 key derivation function identifier.
	KDFPBKDF2 = "pbkdf2"
)

// Compiled reports whether this binary was built as a FIPS 140-3 module — that
// is, compiled with GOFIPS140 set to an enabling value. It is the build-time
// truth, distinct from Enabled which also honours the runtime GOFIPS140
// environment variable: a shared library built with GOFIPS140=latest carries no
// such environment variable in the process that dlopen()s it, so only Compiled
// can tell a FIPS build from a non-FIPS one after the fact. Use it for anything
// that must describe the artifact itself — a token or library label a user
// reads to know they hold a FIPS module — rather than a per-process policy.
func Compiled() bool {
	return fips140.Enabled()
}

// Enabled reports whether FIPS 140 mode is active.
//
// The Go toolchain accepts "off", "latest", "inprocess", "certified" and a
// "v1.Y.Z" version for GOFIPS140, and only "off" means disabled. Testing for a
// non-empty value therefore read GOFIPS140=off — the one spelling a user
// reaches for to turn FIPS OFF — as a request to turn it ON, which silently
// enabled a compliance control the operator had explicitly declined. An
// unrecognized value is treated as disabled rather than assumed to be an
// enabling spelling, because the toolchain would refuse to build with it
// anyway.
func Enabled() bool {
	switch os.Getenv(EnvGOFIPS140) {
	case "", "off":
		return false
	default:
		// Any other value enables. The toolchain's accepted spellings are
		// "latest", "inprocess", "certified" and "v1.Y.Z", and it refuses to
		// build with anything else, so an unrecognized value cannot reach a
		// real FIPS deployment. Treating it as enabled keeps this control
		// failing toward more restriction rather than less.
		return true
	}
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

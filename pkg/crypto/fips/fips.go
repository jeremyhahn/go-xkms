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

// Package fips provides FIPS 140 build-provenance reporting and
// default-algorithm selection for functions that have more than one
// acceptable choice (the KDF selectors below).
//
// Whether FIPS 140 mode is ACTIVE in this process is answered by the Go
// standard library alone (go-xkms #21): crypto/fips140.Enabled is true under
// GODEBUG=fips140=on|only at runtime, or in a binary built with an enabling
// GOFIPS140 (which turns the module on by default). This package keeps no
// second copy of that signal and no approved-algorithm allowlist; callers
// needing "is FIPS mode active" — for their own gating of a third-party
// implementation the stdlib cannot see, such as cloudflare/circl, or for a
// default-algorithm choice like DefaultKDF below — call
// crypto/fips140.Enabled directly.
//
// What this package DOES provide, because the stdlib does not: BuildSetting
// and Built read the GOFIPS140 value the Go toolchain recorded in this
// binary's build metadata, which is build PROVENANCE — a statement about the
// artifact — as distinct from crypto/fips140.Enabled's module STATE, which
// moves with GODEBUG=fips140 in either direction and says nothing about how
// the binary was built (#219).
package fips

import (
	"crypto/fips140"
	"runtime/debug"
)

const (
	// buildSettingKey is the key under which cmd/go records the GOFIPS140
	// value in a binary's build metadata (the "build GOFIPS140=<value>" line
	// of `go version -m`). It is recorded only when the value enables the
	// module, so a binary built without GOFIPS140, or with GOFIPS140=off,
	// carries no such setting.
	buildSettingKey = "GOFIPS140"

	// KDFArgon2id is the Argon2id key derivation function identifier.
	KDFArgon2id = "argon2id"

	// KDFPBKDF2 is the PBKDF2 key derivation function identifier.
	KDFPBKDF2 = "pbkdf2"
)

// BuildSetting returns the GOFIPS140 value the Go toolchain recorded in this
// binary's build metadata, or "" when the binary was built without one.
//
// This is build provenance in the strict sense. cmd/go stamps the setting into
// the binary at link time — `go version -m` shows it as "build
// GOFIPS140=<value>" — it survives into a c-shared library that a foreign
// process dlopen()s, and no environment variable alters it afterwards:
// GODEBUG=fips140=off turns the module off in a FIPS build and leaves this
// value intact, which is exactly the case where crypto/fips140.Enabled goes
// false. The toolchain records the setting only when it enables the module,
// so an explicit GOFIPS140=off at build time reads back as "" like an unset
// one.
//
// The value is the selector the build ran with — "latest", "inprocess",
// "certified" or "v1.Y.Z" — so a compliance manifest can name the module
// version rather than just the fact of a FIPS build.
func BuildSetting() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	return buildSettingFrom(info)
}

// buildSettingFrom extracts the recorded GOFIPS140 value from info, or ""
// when info is nil or carries no such setting. It is the pure half of
// BuildSetting so the lookup can be tested against synthetic build metadata.
func buildSettingFrom(info *debug.BuildInfo) string {
	if info == nil {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == buildSettingKey {
			return setting.Value
		}
	}
	return ""
}

// Built reports whether this binary was compiled with GOFIPS140 set to an
// enabling value — whether the artifact IS a FIPS build, as opposed to
// crypto/fips140.Enabled, which reports whether the module is in force in
// this process.
//
// This is the predicate an artifact label uses: the PKCS#11 module's
// CK_INFO.libraryDescription and CK_TOKEN_INFO.model derive from it, so a
// FIPS-built .so identifies itself as FIPS even when the loading process sets
// GODEBUG=fips140=off, and a normally built binary never claims to be one even
// under GODEBUG=fips140=on.
//
// It is deliberately NOT part of any algorithm-policy decision. Whether an
// approved-only surface is enforced follows crypto/fips140.Enabled, because
// that is what the crypto actually running in the process honours — and the
// crypto itself is what enforces it (go-xkms #21): the standard library
// refuses a non-approved algorithm on its own under GODEBUG=fips140=only or a
// FIPS-only build, rather than this package keeping an approved-algorithm
// list to consult.
func Built() bool {
	return builtFrom(BuildSetting())
}

// builtFrom reports whether a recorded GOFIPS140 value enables the module. The
// toolchain never records "off", but the spelling is refused here too so the
// answer cannot flip if a future toolchain starts recording it.
func builtFrom(setting string) bool {
	switch setting {
	case "", "off":
		return false
	default:
		return true
	}
}

// DefaultKDF returns the default key derivation function identifier.
// In FIPS mode (crypto/fips140.Enabled) it returns "pbkdf2"; otherwise it
// returns "argon2id".
func DefaultKDF() string {
	if fips140.Enabled() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}

// DefaultLUKSKDF returns the default LUKS key derivation function identifier.
// In FIPS mode (crypto/fips140.Enabled) it returns "pbkdf2"; otherwise it
// returns "argon2id".
func DefaultLUKSKDF() string {
	if fips140.Enabled() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}

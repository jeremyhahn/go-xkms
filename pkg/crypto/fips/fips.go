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
	"runtime/debug"
)

const (
	// EnvGOFIPS140 is the environment variable that controls FIPS 140 mode.
	EnvGOFIPS140 = "GOFIPS140"

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

// Compiled reports whether the Go Cryptographic Module is ACTIVE in this
// process. Building with GOFIPS140 set to an enabling value is what normally
// turns it on, which is where the name comes from, and it is the signal that
// survives into a process that dlopen()s a FIPS-built shared library carrying
// no GOFIPS140 environment variable — the case Enabled cannot see.
//
// It is NOT build provenance, despite the name. crypto/fips140.Enabled reports
// module state, and GODEBUG=fips140 selects that state in either direction:
// "on" activates the module in a binary built without GOFIPS140, and "off"
// deactivates it in a binary built with it. So a true result means "the module
// is in force here", not "this artifact is a FIPS build", and a false result
// does not mean the artifact is not one. Nothing that labels an artifact — a
// token model string, a library banner, a compliance manifest — may rest on
// it; those rest on Built and BuildSetting, which read the GOFIPS140 value the
// toolchain records in the binary's build metadata (#219).
//
// Pair it with Enabled (see FIPSMode in sdk/go) for a policy decision: either
// signal alone is reason enough to refuse a non-approved algorithm.
func Compiled() bool {
	return fips140.Enabled()
}

// BuildSetting returns the GOFIPS140 value the Go toolchain recorded in this
// binary's build metadata, or "" when the binary was built without one.
//
// This is build provenance in the strict sense. cmd/go stamps the setting into
// the binary at link time — `go version -m` shows it as "build
// GOFIPS140=<value>" — it survives into a c-shared library that a foreign
// process dlopen()s, and no environment variable alters it afterwards:
// GODEBUG=fips140=off turns the module off in a FIPS build and leaves this
// value intact, which is exactly the case where Compiled goes false. The
// toolchain records the setting only when it enables the module, so an
// explicit GOFIPS140=off at build time reads back as "" like an unset one.
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
// Compiled, which reports whether the module is in force in this process.
//
// This is the predicate an artifact label uses: the PKCS#11 module's
// CK_INFO.libraryDescription and CK_TOKEN_INFO.model derive from it, so a
// FIPS-built .so identifies itself as FIPS even when the loading process sets
// GODEBUG=fips140=off, and a normally built binary never claims to be one even
// under GODEBUG=fips140=on.
//
// It is deliberately NOT part of any algorithm-policy decision. Whether an
// approved-only surface is enforced follows the module state (Compiled) and the
// operator's environment (Enabled), because that is what the crypto actually
// running in the process honours; see AlgorithmPermitted.
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

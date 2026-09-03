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

import "github.com/jeremyhahn/go-xkms/pkg/crypto/fips"

// FIPS 140 mode detection, re-exported for consumers that must refuse a
// non-approved algorithm before reaching the standard library, which panics
// rather than returning an error.
//
// Re-exported because the xkey module needs it and consumes this repository
// through sdk/go. Without a surface here the alternative was to re-derive the
// check locally, and the derivation has a trap worth stating: GOFIPS140 accepts
// "off", "latest", "inprocess", "certified" and "vX.Y.Z", so testing for a
// non-empty value reads GOFIPS140=off -- the spelling an operator reaches for
// to turn FIPS OFF -- as a request to turn it ON. A second copy of that logic
// is a second chance to get it backwards.
//
// Everything here describes the RUNNING PROCESS. See FIPSMode on why no
// build-provenance accessor is exported.
// FIPSEnabled reports whether GOFIPS140 selects FIPS 140 mode for this
// process. It is one of the two signals FIPSMode combines, exported for a
// caller that needs to tell an operator WHICH signal is in force.
//
// A function, not a function VARIABLE. As a var it was assignable by any
// consumer of this package, so a compliance signal could be replaced
// process-wide -- making diagnostics report whatever the last writer chose,
// and racing any concurrent reader. Nothing about a public API named
// FIPSEnabled suggests it is a test hook, and it was never meant to be one:
// the injectable seam lives in xkey/pkg/oath, unexported and below this
// boundary, where the tests that need it are.
func FIPSEnabled() bool { return fips.Enabled() }

// FIPSMode reports whether this process is under FIPS 140 rules, by either of
// the two signals that can put it there: the Go Cryptographic Module being
// active (crypto/fips140.Enabled, which a FIPS build turns on by default and
// GODEBUG=fips140 can also select), or GOFIPS140 naming an enabling value.
//
// Callers gating an algorithm want this rather than either half, and it fails
// toward more restriction: either signal alone is enough to refuse. It is the
// same pair pkg/pkcs11/module uses to decide whether a mechanism is
// admissible.
//
// Deliberately NOT exported alongside this: any claim about how the binary was
// BUILT. Both underlying signals are process state, not artifact provenance —
// crypto/fips140.Enabled reports the module being active, which a normally
// built binary can reach through GODEBUG. An SDK export promising build
// provenance would be read as immutable by exactly the compliance and
// artifact-labelling code that must not be misled, so the honest surface is
// the one that describes the process.
func FIPSMode() bool {
	return fips.Compiled() || fips.Enabled()
}

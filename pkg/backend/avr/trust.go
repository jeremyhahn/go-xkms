// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package avr

import (
	tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// tierTrust is what one crypto tier establishes about the keys behind it.
type tierTrust struct {
	level    types.AttestLevel
	security types.SecurityLevel
	hardware bool
}

// tierTrusts maps the device's own CAPS tier onto the xkms vocabulary. A map
// rather than a switch so an unrecognised tier is a lookup miss — one place,
// one answer — instead of a default branch that has to remember to be
// pessimistic.
//
// The mapping is the whole of this backend's attestation-level reporting.
// Nothing else contributes: not the presence of the attestation feature bit,
// not the algorithms the element offers, not whether a chain happened to
// verify. A backend that inferred hardware backing from anything other than
// what the device said about its own root of trust would be guessing at the
// one fact a verifier is relying on it for.
var tierTrusts = map[tfw.CryptoTier]tierTrust{
	// No crypto provider at all. Nothing established anything, which is what
	// unattested means — not a claim that the key is software, because there
	// is no key.
	tfw.CryptoNone: {
		level:    types.AttestLevelUnattested,
		security: types.SecurityLevelLow,
	},

	// A software provider on the MCU: no TRNG, no key isolation, and on the
	// symmetric path a verifier that holds the key could forge any response
	// it could check. Software is the positive claim that the key is not
	// hardware-resident, which is exactly what this tier reports about itself.
	tfw.CryptoSoftware: {
		level:    types.AttestLevelSoftware,
		security: types.SecurityLevelLow,
	},

	// A secure element on the device's I2C bus, with the private half of the
	// identity generated inside it and no command anywhere that exports it.
	tfw.CryptoSecureElement: {
		level:    types.AttestLevelHardware,
		security: types.SecurityLevelHigh,
		hardware: true,
	},

	// A discrete TPM 2.0. Hardware-bound and non-exportable, the same
	// classification xkms gives a TPM reached any other way.
	tfw.CryptoTPM2: {
		level:    types.AttestLevelHardware,
		security: types.SecurityLevelVeryHigh,
		hardware: true,
	},
}

// trustFor returns what the tier establishes, and whether this host knows the
// tier at all.
//
// A tier with no entry resolves to the unattested, low, not-hardware answer.
// That is deliberately the same answer as CryptoNone: tiers extend and never
// renumber, so a number this host has never seen says nothing about strength,
// and treating "newer" as "at least as good" would hand an unknown root of
// trust the standing reserved for a secure element. The bool lets a caller
// that needs to distinguish "the device has nothing" from "this host cannot
// read what the device has" do so; AttestLevel turns it into an error.
func trustFor(tier tfw.CryptoTier) (tierTrust, bool) {
	t, ok := tierTrusts[tier]
	if !ok {
		// Spelled out rather than left to the zero value. tierTrust's zero
		// AttestLevel is the empty string, which is not
		// types.AttestLevelUnattested and would reach a record or an API
		// response as a level nothing can parse.
		return unknownTierTrust, false
	}
	return t, true
}

// unknownTierTrust is what a tier with no entry establishes: nothing.
var unknownTierTrust = tierTrust{
	level:    types.AttestLevelUnattested,
	security: types.SecurityLevelLow,
}

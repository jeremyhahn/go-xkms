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
	"testing"

	tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"

	"github.com/stretchr/testify/assert"
)

// An ATECC608A performs ECDSA P-256 and HMAC-SHA256. It has no hardware
// Ed25519 and never claims it. This is the case the whole type exists for: a
// host that advertised Ed25519 here would negotiate a peer down onto an
// algorithm the element then fails to perform, at the point where it matters
// most.
func TestAlgorithmsReportsOnlyWhatTheDeviceClaims(t *testing.T) {
	a := Algorithms{set: tfw.AlgECDSAP256SHA256 | tfw.AlgHMACSHA256}

	assert.Equal(t, []Algorithm{AlgorithmECDSAP256SHA256, AlgorithmHMACSHA256}, a.Named())
	assert.True(t, a.Can(AlgorithmECDSAP256SHA256))
	assert.True(t, a.Can(AlgorithmHMACSHA256))
	assert.False(t, a.Can(AlgorithmEd25519),
		"the element has no hardware Ed25519 and did not claim it")
	assert.False(t, a.Empty())
	assert.Zero(t, a.Unnamed())
}

// The capability BIT for HMAC-SHA256 is 0x0004; the algorithm IDENTIFIER that
// travels in an attestation frame is 0x10. A reader that confused the two
// would read a device as offering nothing it actually offers.
func TestAlgorithmsUsesCapabilityBitsAndNotWireIdentifiers(t *testing.T) {
	a := Algorithms{set: tfw.AlgECDSAP256SHA256 | tfw.AlgHMACSHA256}

	assert.Equal(t, tfw.AlgorithmSet(0x0005), a.Set())
	assert.True(t, a.Can(AlgorithmHMACSHA256))
}

// Firmware built before the bitmap was appended to CAPS reports nothing, and
// that is not an error: the empty set is the honest reading of a reply that is
// complete by the contract its firmware was built against, and it is the
// direction a negotiation may safely fail in.
func TestAlgorithmsTreatsAnAbsentBitmapAsClaimingNothing(t *testing.T) {
	a := Algorithms{}

	assert.True(t, a.Empty())
	assert.Empty(t, a.Named())
	assert.False(t, a.Can(AlgorithmECDSAP256SHA256))
	assert.Equal(t, "(none)", a.String())
}

// A device offering something newer than this host is the ordinary state of a
// fleet mid-upgrade. The unnamed bits are reported rather than dropped, so an
// operator can see that the device said more than the host could read.
func TestAlgorithmsReportsBitsItCannotName(t *testing.T) {
	const future = tfw.AlgorithmSet(0x0100)
	a := Algorithms{set: tfw.AlgECDSAP256SHA256 | future}

	assert.Equal(t, []Algorithm{AlgorithmECDSAP256SHA256}, a.Named())
	assert.Equal(t, future, a.Unnamed())
	assert.Contains(t, a.String(), "0x0100")
}

// An algorithm name this package does not define can never be performed.
// Answering anything but false would let a typo negotiate up.
func TestAlgorithmsCanRefusesAnUnknownName(t *testing.T) {
	a := Algorithms{set: 0xFFFF}

	assert.False(t, a.Can(Algorithm("rsa-2048")))
	assert.False(t, a.Can(Algorithm("")))
	assert.True(t, a.Can(AlgorithmEd25519), "a device that really claims every bit does claim this one")
}

// The forward table and the reverse lookup are built from one source, so a
// name added to one is present in the other.
func TestAlgorithmTablesAgree(t *testing.T) {
	assert.Len(t, algorithmSets, len(algorithmBits))
	for _, entry := range algorithmBits {
		bit, ok := algorithmSets[entry.name]
		assert.True(t, ok, "%s has no reverse entry", entry.name)
		assert.Equal(t, entry.bit, bit)
		assert.NotZero(t, knownAlgorithms&entry.bit, "%s is missing from knownAlgorithms", entry.name)
	}
}

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

	aggeneric "github.com/jeremyhahn/trusted-firmware/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The attestation level a device is reported at comes from its own crypto tier
// and from nothing else. This is the table that mapping is, stated once.
func TestTrustForClassifiesEveryKnownTier(t *testing.T) {
	tests := []struct {
		name     string
		tier     aggeneric.CryptoTier
		level    types.AttestLevel
		security types.SecurityLevel
		hardware bool
	}{
		{"no provider", aggeneric.CryptoNone, types.AttestLevelUnattested, types.SecurityLevelLow, false},
		{"software", aggeneric.CryptoSoftware, types.AttestLevelSoftware, types.SecurityLevelLow, false},
		{"secure element", aggeneric.CryptoSecureElement, types.AttestLevelHardware, types.SecurityLevelHigh, true},
		{"discrete tpm2", aggeneric.CryptoTPM2, types.AttestLevelHardware, types.SecurityLevelVeryHigh, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, known := trustFor(tt.tier)
			require.True(t, known)
			assert.Equal(t, tt.level, got.level)
			assert.Equal(t, tt.security, got.security)
			assert.Equal(t, tt.hardware, got.hardware)
		})
	}
}

// A tier this host has no name for must never resolve to hardware. Tiers
// extend and never renumber, so a larger number carries no promise of being a
// stronger root of trust, and assuming it did would grant an unknown provider
// the standing reserved for a secure element.
func TestTrustForRefusesToGuessAtAnUnknownTier(t *testing.T) {
	for _, tier := range []aggeneric.CryptoTier{4, 7, 255} {
		got, known := trustFor(tier)

		assert.False(t, known, "tier %d", tier)
		assert.Equal(t, types.AttestLevelUnattested, got.level, "tier %d", tier)
		assert.Equal(t, types.SecurityLevelLow, got.security, "tier %d", tier)
		assert.False(t, got.hardware, "tier %d", tier)
	}
}

// The software tier is a POSITIVE claim and not the absence of one: the device
// affirmatively says its root of trust is not in hardware. Collapsing it to
// unattested would lose the difference between a device that answered and a
// device that could not.
func TestSoftwareTierIsNotTheSameAsNoProvider(t *testing.T) {
	software, _ := trustFor(aggeneric.CryptoSoftware)
	none, _ := trustFor(aggeneric.CryptoNone)

	assert.NotEqual(t, none.level, software.level)
	assert.Equal(t, types.AttestLevelSoftware, software.level)
}

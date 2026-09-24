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

	aggeneric "github.com/jeremyhahn/arduino-generic/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := DefaultConfig()
	require.NoError(t, cfg.Validate())

	assert.Equal(t, DefaultKeyCN, cfg.KeyCN)
	assert.Equal(t, aggeneric.SlotDeviceID, cfg.Slot)
	assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout)
	assert.NotNil(t, cfg.Logger)
}

func TestValidateFillsTheDefaultsItIsAllowedTo(t *testing.T) {
	cfg := &Config{KeyCN: "device"}
	require.NoError(t, cfg.Validate())

	assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout,
		"a zero timeout is a request for the default, not a zero deadline")
	assert.NotNil(t, cfg.Logger)
	assert.Equal(t, "device", cfg.KeyCN, "a name the caller set is never replaced")
}

// The empty common name is refused rather than defaulted. Defaulting it would
// make a KeyAttributes that simply forgot its CN resolve to the device's
// identity key, which is the one key on the part.
func TestValidateRefusesAnEmptyKeyName(t *testing.T) {
	cfg := DefaultConfig()
	cfg.KeyCN = ""

	assert.ErrorIs(t, cfg.Validate(), ErrMissingKeyCN)
}

// Slot 1 is the UDS. Reading it as a public key would hand out a derivation
// secret's slot as an identity, so a configuration naming it is refused before
// any command goes on the wire.
func TestValidateRefusesASlotThatIsNotTheIdentity(t *testing.T) {
	for _, slot := range []uint8{aggeneric.SlotUDS, 2, 15} {
		cfg := DefaultConfig()
		cfg.Slot = slot
		assert.ErrorIs(t, cfg.Validate(), ErrInvalidSlot, "slot %d", slot)
	}
}

func TestValidateRefusesANegativeTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequestTimeout = -1

	require.NoError(t, cfg.Validate())
	assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout,
		"a negative deadline would expire before the first byte left")
}

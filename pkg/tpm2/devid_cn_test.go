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

package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DevIDCommonName is the one naming rule for both DevID keys. These tests
// pin its three outcomes -- explicit name, derived name, refusal -- so the
// IAK and the IDevID of a device can never be named by different logic.

func TestDevIDCommonName_ExplicitNameWins(t *testing.T) {
	cn, err := DevIDCommonName("host-iak", &PlatformAttributes{Model: "edge", Serial: "001"})
	require.NoError(t, err)
	assert.Equal(t, "host-iak", cn, "a configured cn is used verbatim even when model and serial are present")
}

func TestDevIDCommonName_DerivesFromModelAndSerial(t *testing.T) {
	cn, err := DevIDCommonName("", &PlatformAttributes{Model: "edge", Serial: "001"})
	require.NoError(t, err)
	assert.Equal(t, "edge-001", cn,
		"TCG 7.2.3 step 4a / 802.1AR 2.3.4: the device is identified by model and serial number")
}

func TestDevIDCommonName_RefusesRatherThanDefaults(t *testing.T) {
	cases := []struct {
		name     string
		platform *PlatformAttributes
	}{
		{"nil platform", nil},
		{"empty platform", &PlatformAttributes{}},
		{"model without serial", &PlatformAttributes{Model: "edge"}},
		{"serial without model", &PlatformAttributes{Serial: "001"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cn, err := DevIDCommonName("", tc.platform)
			assert.ErrorIs(t, err, ErrDevIDCNUnresolved,
				"an unnameable key is refused; a fabricated default would put every such device on one storage key")
			assert.Empty(t, cn, "no name may be returned alongside the refusal")
		})
	}
}

// The IAK is named from the IDevID's CONFIGURED model and serial -- the same
// input IDevIDAttributesFromConfig uses -- and never from DMI discovery, so
// the two keys' names are symmetric and a test's outcome does not depend on
// the host it runs on.
func TestDevIDPlatformFromConfig_UsesConfiguredValuesOnly(t *testing.T) {
	assert.Nil(t, devidPlatformFromConfig(nil), "no IDevID configuration yields no platform identity")

	got := devidPlatformFromConfig(&IDevIDConfig{Model: "edge", Serial: "001", Manufacturer: "ATT"})
	require.NotNil(t, got)
	assert.Equal(t, "edge", got.Model)
	assert.Equal(t, "001", got.Serial)
	assert.Empty(t, got.Manufacturer, "only the fields the CN is built from are carried")

	empty := devidPlatformFromConfig(&IDevIDConfig{})
	require.NotNil(t, empty)
	_, err := DevIDCommonName("", empty)
	assert.ErrorIs(t, err, ErrDevIDCNUnresolved,
		"an IDevID configuration without model and serial does not name the IAK either")
}

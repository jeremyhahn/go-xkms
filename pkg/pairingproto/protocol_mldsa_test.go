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

package pairingproto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLocalGenerateKeyParams_KeyBacking_RoundTrip covers #2405: the phone
// accepts an optional keyBacking for ML-DSA keys; absent means the phone picks.
func TestLocalGenerateKeyParams_KeyBacking_RoundTrip(t *testing.T) {
	for _, backing := range []string{KeyBackingHardware, KeyBackingSoftware} {
		params := LocalGenerateKeyParams{KeyID: "pq", Algorithm: AlgorithmMLDSA65, KeyBacking: backing}
		data, err := json.Marshal(params)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"keyBacking":"`+backing+`"`)

		var decoded LocalGenerateKeyParams
		require.NoError(t, json.Unmarshal(data, &decoded))
		assert.Equal(t, params, decoded)
	}

	data, err := json.Marshal(LocalGenerateKeyParams{KeyID: "pq", Algorithm: AlgorithmMLDSA44})
	require.NoError(t, err)
	assert.NotContains(t, string(data), "keyBacking", "keyBacking is omitted when the phone picks")
}

// TestLocalGetCapabilitiesResult_HardwareAlgorithms_RoundTrip covers #2405:
// getCapabilities lists the ML-DSA names and which algorithms are hardware backed.
func TestLocalGetCapabilitiesResult_HardwareAlgorithms_RoundTrip(t *testing.T) {
	result := LocalGetCapabilitiesResult{
		Version:             "1.0",
		DeviceName:          "phone",
		SupportedAlgorithms: []string{"ES256", AlgorithmMLDSA44, AlgorithmMLDSA65, AlgorithmMLDSA87},
		HardwareAlgorithms:  []string{"ES256", AlgorithmMLDSA65},
		SupportedFormats:    []string{"der", "pem"},
	}
	data, err := json.Marshal(result)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"hardwareAlgorithms":["ES256","ML-DSA-65"]`)

	var decoded LocalGetCapabilitiesResult
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, result, decoded)

	data, err = json.Marshal(LocalGetCapabilitiesResult{Version: "1.0"})
	require.NoError(t, err)
	assert.NotContains(t, string(data), "hardwareAlgorithms", "an older phone sends no hardwareAlgorithms")
}

// TestCOSEAlgorithmName_MLDSA covers #2405: COSE ids -48/-49/-50 name the
// ML-DSA parameter sets; the existing ids keep their names.
func TestCOSEAlgorithmName_MLDSA(t *testing.T) {
	assert.Equal(t, -48, COSEAlgMLDSA44)
	assert.Equal(t, -49, COSEAlgMLDSA65)
	assert.Equal(t, -50, COSEAlgMLDSA87)

	cases := map[int]string{
		COSEAlgMLDSA44: "ML-DSA-44",
		COSEAlgMLDSA65: "ML-DSA-65",
		COSEAlgMLDSA87: "ML-DSA-87",
		COSEAlgES256:   "ES256",
		COSEAlgES384:   "ES384",
		COSEAlgES512:   "ES512",
	}
	for id, want := range cases {
		name, ok := COSEAlgorithmName(id)
		assert.True(t, ok, "COSE id %d", id)
		assert.Equal(t, want, name, "COSE id %d", id)
	}

	_, ok := COSEAlgorithmName(-1)
	assert.False(t, ok, "an unknown COSE id has no name")
}

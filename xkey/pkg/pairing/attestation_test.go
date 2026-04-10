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

package pairing

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLaptopAttestor_NilConfig(t *testing.T) {
	attestor, err := NewLaptopAttestor(nil)
	require.NoError(t, err)
	require.NotNil(t, attestor)

	assert.Equal(t, AttestationModeAuto, attestor.Mode())
	assert.False(t, attestor.IsTPM2Available())
}

func TestNewLaptopAttestor_WithConfig(t *testing.T) {
	attestor, err := NewLaptopAttestor(&LaptopAttestorConfig{
		Mode: AttestationModeSoftware,
		PCRs: []uint{0, 1, 2, 7},
	})
	require.NoError(t, err)
	require.NotNil(t, attestor)

	assert.Equal(t, AttestationModeSoftware, attestor.Mode())
	assert.False(t, attestor.IsTPM2Available())
}

func TestLaptopAttestor_SoftwareAttestation(t *testing.T) {
	attestor, err := NewLaptopAttestor(&LaptopAttestorConfig{
		Mode: AttestationModeSoftware,
	})
	require.NoError(t, err)

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	result, err := attestor.GenerateAttestation(nonce)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "software", result.Format)
	assert.Equal(t, "software", result.SecurityLevel)
	assert.Equal(t, nonce, result.Nonce)
	assert.False(t, result.BootStateVerified)
	assert.Nil(t, result.CertificateChain)
	assert.Nil(t, result.PlatformPCRs)
	assert.Nil(t, result.QuoteData)
	assert.Nil(t, result.QuoteSignature)
	assert.Empty(t, result.BootHashHex)
	assert.Empty(t, result.FirmwareVersion)
}

func TestLaptopAttestor_InvalidNonce_TooShort(t *testing.T) {
	attestor, err := NewLaptopAttestor(nil)
	require.NoError(t, err)

	// Too short nonce (16 bytes instead of 32)
	shortNonce := make([]byte, 16)
	_, err = rand.Read(shortNonce)
	require.NoError(t, err)

	_, err = attestor.GenerateAttestation(shortNonce)
	assert.ErrorIs(t, err, ErrInvalidAttestationNonce)
}

func TestLaptopAttestor_InvalidNonce_TooLong(t *testing.T) {
	attestor, err := NewLaptopAttestor(nil)
	require.NoError(t, err)

	// Too long nonce (64 bytes instead of 32)
	longNonce := make([]byte, 64)
	_, err = rand.Read(longNonce)
	require.NoError(t, err)

	_, err = attestor.GenerateAttestation(longNonce)
	assert.ErrorIs(t, err, ErrInvalidAttestationNonce)
}

func TestLaptopAttestor_InvalidNonce_Empty(t *testing.T) {
	attestor, err := NewLaptopAttestor(nil)
	require.NoError(t, err)

	_, err = attestor.GenerateAttestation(nil)
	assert.ErrorIs(t, err, ErrInvalidAttestationNonce)

	_, err = attestor.GenerateAttestation([]byte{})
	assert.ErrorIs(t, err, ErrInvalidAttestationNonce)
}

func TestLaptopAttestor_AutoMode_NoTPM(t *testing.T) {
	attestor, err := NewLaptopAttestor(&LaptopAttestorConfig{
		Mode: AttestationModeAuto,
		TPM:  nil, // No TPM available
	})
	require.NoError(t, err)

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	result, err := attestor.GenerateAttestation(nonce)
	require.NoError(t, err)

	// Should fall back to software
	assert.Equal(t, "software", result.Format)
	assert.Equal(t, "software", result.SecurityLevel)
	assert.Equal(t, nonce, result.Nonce)
}

func TestLaptopAttestor_TPM2Required_NoTPM(t *testing.T) {
	attestor, err := NewLaptopAttestor(&LaptopAttestorConfig{
		Mode: AttestationModeTPM2,
		TPM:  nil, // No TPM available
	})
	require.NoError(t, err)

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	_, err = attestor.GenerateAttestation(nonce)
	assert.ErrorIs(t, err, ErrTPM2Required)
}

func TestParseAttestationMode(t *testing.T) {
	tests := []struct {
		input    string
		expected AttestationMode
	}{
		{"auto", AttestationModeAuto},
		{"", AttestationModeAuto},
		{"tpm2", AttestationModeTPM2},
		{"software", AttestationModeSoftware},
		{"invalid", AttestationModeAuto}, // Unknown defaults to auto
		{"AUTO", AttestationModeAuto},    // Case sensitivity - defaults to auto
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := ParseAttestationMode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestComputeBootHash(t *testing.T) {
	t.Run("empty PCRs", func(t *testing.T) {
		result := computeBootHash(nil)
		assert.Empty(t, result)

		result = computeBootHash(map[int][]byte{})
		assert.Empty(t, result)
	})

	t.Run("single PCR", func(t *testing.T) {
		pcrs := map[int][]byte{
			0: {0x01, 0x02, 0x03, 0x04},
		}
		result := computeBootHash(pcrs)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 64) // SHA256 hex = 64 chars
	})

	t.Run("multiple PCRs", func(t *testing.T) {
		pcrs := map[int][]byte{
			0: {0x01, 0x02, 0x03, 0x04},
			1: {0x05, 0x06, 0x07, 0x08},
			7: {0x09, 0x0a, 0x0b, 0x0c},
		}
		result := computeBootHash(pcrs)
		assert.NotEmpty(t, result)
		assert.Len(t, result, 64)
	})

	t.Run("deterministic", func(t *testing.T) {
		pcrs := map[int][]byte{
			0: {0x01, 0x02, 0x03, 0x04},
			1: {0x05, 0x06, 0x07, 0x08},
		}
		result1 := computeBootHash(pcrs)
		result2 := computeBootHash(pcrs)
		assert.Equal(t, result1, result2)
	})

	t.Run("different PCRs produce different hash", func(t *testing.T) {
		pcrs1 := map[int][]byte{
			0: {0x01, 0x02, 0x03, 0x04},
		}
		pcrs2 := map[int][]byte{
			0: {0x05, 0x06, 0x07, 0x08},
		}
		result1 := computeBootHash(pcrs1)
		result2 := computeBootHash(pcrs2)
		assert.NotEqual(t, result1, result2)
	})
}

func TestLaptopAttestor_ModeMethod(t *testing.T) {
	tests := []struct {
		mode     AttestationMode
		expected AttestationMode
	}{
		{AttestationModeAuto, AttestationModeAuto},
		{AttestationModeTPM2, AttestationModeTPM2},
		{AttestationModeSoftware, AttestationModeSoftware},
	}

	for _, tc := range tests {
		t.Run(string(tc.mode), func(t *testing.T) {
			attestor, err := NewLaptopAttestor(&LaptopAttestorConfig{
				Mode: tc.mode,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, attestor.Mode())
		})
	}
}

func TestLaptopAttestor_IsTPM2Available(t *testing.T) {
	t.Run("no TPM", func(t *testing.T) {
		attestor, err := NewLaptopAttestor(&LaptopAttestorConfig{
			TPM: nil,
		})
		require.NoError(t, err)
		assert.False(t, attestor.IsTPM2Available())
	})

	// Note: Testing with actual TPM would require integration tests
	// or mocking the TrustedPlatformModule interface
}

func TestLaptopAttestor_DefaultPCRs(t *testing.T) {
	// Verify default PCRs are set correctly
	cfg := &LaptopAttestorConfig{
		Mode: AttestationModeSoftware,
	}

	// After NewLaptopAttestor, PCRs should be set to default
	attestor, err := NewLaptopAttestor(cfg)
	require.NoError(t, err)
	require.NotNil(t, attestor)

	// Verify the config was updated with defaults
	assert.Equal(t, defaultAttestationPCRs, cfg.PCRs)
}

func TestLaptopAttestor_CustomPCRs(t *testing.T) {
	customPCRs := []uint{0, 1, 2, 3, 4, 5, 6, 7}

	cfg := &LaptopAttestorConfig{
		Mode: AttestationModeSoftware,
		PCRs: customPCRs,
	}

	attestor, err := NewLaptopAttestor(cfg)
	require.NoError(t, err)
	require.NotNil(t, attestor)

	// Custom PCRs should not be overwritten
	assert.Equal(t, customPCRs, cfg.PCRs)
}

func TestLaptopAttestor_SoftwareAttestationNonceEchoed(t *testing.T) {
	attestor, err := NewLaptopAttestor(&LaptopAttestorConfig{
		Mode: AttestationModeSoftware,
	})
	require.NoError(t, err)

	// Generate a specific nonce pattern
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}

	result, err := attestor.GenerateAttestation(nonce)
	require.NoError(t, err)

	// Nonce should be echoed exactly
	assert.Equal(t, nonce, result.Nonce)
}

func TestLaptopAttestor_UnknownModeDefaultsToAuto(t *testing.T) {
	attestor, err := NewLaptopAttestor(&LaptopAttestorConfig{
		Mode: AttestationMode("unknown"),
		TPM:  nil,
	})
	require.NoError(t, err)

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	// Unknown mode with no TPM should fall back to software
	result, err := attestor.GenerateAttestation(nonce)
	require.NoError(t, err)
	assert.Equal(t, "software", result.Format)
}

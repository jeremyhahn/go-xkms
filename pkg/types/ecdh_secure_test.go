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

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// KeyDerivationMode Tests
// =============================================================================

func TestKeyDerivationMode_String(t *testing.T) {
	testCases := []struct {
		name     string
		mode     KeyDerivationMode
		expected string
	}{
		{"Export", KeyDerivationModeExport, "EXPORT"},
		{"HSMResident", KeyDerivationModeHSMResident, "HSM_RESIDENT"},
		{"HSMKDF", KeyDerivationModeHSMKDF, "HSM_KDF"},
		{"TPMWrapped", KeyDerivationModeTPMWrapped, "TPM_WRAPPED"},
		{"Unknown", KeyDerivationMode(99), "UNKNOWN(99)"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.mode.String())
		})
	}
}

func TestKeyDerivationMode_IsValid(t *testing.T) {
	testCases := []struct {
		name     string
		mode     KeyDerivationMode
		expected bool
	}{
		{"Export", KeyDerivationModeExport, true},
		{"HSMResident", KeyDerivationModeHSMResident, true},
		{"HSMKDF", KeyDerivationModeHSMKDF, true},
		{"TPMWrapped", KeyDerivationModeTPMWrapped, true},
		{"Invalid", KeyDerivationMode(99), false},
		{"Negative", KeyDerivationMode(-1), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.mode.IsValid())
		})
	}
}

func TestParseKeyDerivationMode(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected KeyDerivationMode
	}{
		{"Export uppercase", "EXPORT", KeyDerivationModeExport},
		{"Export lowercase", "export", KeyDerivationModeExport},
		{"Empty string", "", KeyDerivationModeExport},
		{"HSM_RESIDENT", "HSM_RESIDENT", KeyDerivationModeHSMResident},
		{"HSMRESIDENT no underscore", "HSMRESIDENT", KeyDerivationModeHSMResident},
		{"HSM_KDF", "HSM_KDF", KeyDerivationModeHSMKDF},
		{"HSMKDF no underscore", "HSMKDF", KeyDerivationModeHSMKDF},
		{"TPM_WRAPPED", "TPM_WRAPPED", KeyDerivationModeTPMWrapped},
		{"TPMWRAPPED no underscore", "TPMWRAPPED", KeyDerivationModeTPMWrapped},
		{"With whitespace", "  HSM_RESIDENT  ", KeyDerivationModeHSMResident},
		{"Mixed case", "hsm_resident", KeyDerivationModeHSMResident},
		{"Unknown defaults to export", "INVALID", KeyDerivationModeExport},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseKeyDerivationMode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// =============================================================================
// DerivedKeyHandle Tests
// =============================================================================

func TestDerivedKeyHandle_JSONRoundTrip(t *testing.T) {
	original := &DerivedKeyHandle{
		ID:          "test-key-id",
		Backend:     "pkcs11",
		Extractable: false,
		KeyLength:   32,
		Algorithm:   "AES",
		Ephemeral:   true,
		HSMHandle:   12345,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var parsed DerivedKeyHandle
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, original.ID, parsed.ID)
	assert.Equal(t, original.Backend, parsed.Backend)
	assert.Equal(t, original.Extractable, parsed.Extractable)
	assert.Equal(t, original.KeyLength, parsed.KeyLength)
	assert.Equal(t, original.Algorithm, parsed.Algorithm)
	assert.Equal(t, original.Ephemeral, parsed.Ephemeral)
	assert.Equal(t, original.HSMHandle, parsed.HSMHandle)
}

func TestDerivedKeyHandle_WithTPMHandle(t *testing.T) {
	original := &DerivedKeyHandle{
		ID:      "tpm-key",
		Backend: "tpm2",
		TPMHandle: &TPMDerivedKeyHandle{
			Handle:       0x81000001,
			ParentHandle: 0x81000000,
			Public:       []byte{0x01, 0x02, 0x03},
			Private:      []byte{0x04, 0x05, 0x06},
			PolicyDigest: []byte{0x07, 0x08, 0x09},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var parsed DerivedKeyHandle
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	require.NotNil(t, parsed.TPMHandle)
	assert.Equal(t, original.TPMHandle.Handle, parsed.TPMHandle.Handle)
	assert.Equal(t, original.TPMHandle.ParentHandle, parsed.TPMHandle.ParentHandle)
	assert.Equal(t, original.TPMHandle.Public, parsed.TPMHandle.Public)
	assert.Equal(t, original.TPMHandle.Private, parsed.TPMHandle.Private)
	assert.Equal(t, original.TPMHandle.PolicyDigest, parsed.TPMHandle.PolicyDigest)
}

// =============================================================================
// ECDHResult Tests
// =============================================================================

func TestECDHResult_HasKey(t *testing.T) {
	testCases := []struct {
		name     string
		result   *ECDHResult
		expected bool
	}{
		{
			name:     "With derived key",
			result:   &ECDHResult{DerivedKey: []byte{0x01, 0x02, 0x03}},
			expected: true,
		},
		{
			name:     "With handle",
			result:   &ECDHResult{Handle: &DerivedKeyHandle{ID: "test"}},
			expected: true,
		},
		{
			name:     "With both",
			result:   &ECDHResult{DerivedKey: []byte{0x01}, Handle: &DerivedKeyHandle{ID: "test"}},
			expected: true,
		},
		{
			name:     "Empty",
			result:   &ECDHResult{},
			expected: false,
		},
		{
			name:     "Empty derived key",
			result:   &ECDHResult{DerivedKey: []byte{}},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.result.HasKey())
		})
	}
}

func TestECDHResult_IsExported(t *testing.T) {
	testCases := []struct {
		name     string
		result   *ECDHResult
		expected bool
	}{
		{
			name:     "With derived key",
			result:   &ECDHResult{DerivedKey: []byte{0x01, 0x02, 0x03}},
			expected: true,
		},
		{
			name:     "Empty derived key",
			result:   &ECDHResult{DerivedKey: []byte{}},
			expected: false,
		},
		{
			name:     "Nil derived key",
			result:   &ECDHResult{},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.result.IsExported())
		})
	}
}

func TestECDHResult_IsResident(t *testing.T) {
	testCases := []struct {
		name     string
		result   *ECDHResult
		expected bool
	}{
		{
			name:     "With handle",
			result:   &ECDHResult{Handle: &DerivedKeyHandle{ID: "test"}},
			expected: true,
		},
		{
			name:     "Nil handle",
			result:   &ECDHResult{},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.result.IsResident())
		})
	}
}

func TestECDHResult_JSONRoundTrip(t *testing.T) {
	original := &ECDHResult{
		Mode:               KeyDerivationModeHSMResident,
		Handle:             &DerivedKeyHandle{ID: "test-handle", Backend: "pkcs11"},
		EphemeralPublicKey: []byte{0x04, 0x01, 0x02, 0x03},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var parsed ECDHResult
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, original.Mode, parsed.Mode)
	require.NotNil(t, parsed.Handle)
	assert.Equal(t, original.Handle.ID, parsed.Handle.ID)
	assert.Equal(t, original.Handle.Backend, parsed.Handle.Backend)
	assert.Equal(t, original.EphemeralPublicKey, parsed.EphemeralPublicKey)
}

// =============================================================================
// DerivedKeyTemplateParams Tests
// =============================================================================

func TestDefaultDerivedKeyTemplateParams(t *testing.T) {
	params := DefaultDerivedKeyTemplateParams()

	assert.Equal(t, "AES", params.KeyType)
	assert.False(t, params.Token)    // Session key by default
	assert.True(t, params.Private)   // Require login
	assert.True(t, params.Sensitive) // Never reveal plaintext
	assert.True(t, params.AllowEncrypt)
	assert.True(t, params.AllowDecrypt)
	assert.False(t, params.AllowWrap)
	assert.False(t, params.AllowUnwrap)
	assert.False(t, params.AllowDerive)
}

func TestDerivedKeyTemplateParams_JSONRoundTrip(t *testing.T) {
	original := &DerivedKeyTemplateParams{
		Label:        "my-derived-key",
		ID:           "key-001",
		KeyType:      "GENERIC_SECRET",
		Token:        true,
		Private:      true,
		Sensitive:    true,
		AllowEncrypt: true,
		AllowDecrypt: true,
		AllowWrap:    true,
		AllowUnwrap:  true,
		AllowDerive:  false,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var parsed DerivedKeyTemplateParams
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, original.Label, parsed.Label)
	assert.Equal(t, original.ID, parsed.ID)
	assert.Equal(t, original.KeyType, parsed.KeyType)
	assert.Equal(t, original.Token, parsed.Token)
	assert.Equal(t, original.Private, parsed.Private)
	assert.Equal(t, original.Sensitive, parsed.Sensitive)
	assert.Equal(t, original.AllowEncrypt, parsed.AllowEncrypt)
	assert.Equal(t, original.AllowDecrypt, parsed.AllowDecrypt)
	assert.Equal(t, original.AllowWrap, parsed.AllowWrap)
	assert.Equal(t, original.AllowUnwrap, parsed.AllowUnwrap)
	assert.Equal(t, original.AllowDerive, parsed.AllowDerive)
}

// =============================================================================
// ResidentKeyOperation Tests
// =============================================================================

func TestResidentKeyOperation_String(t *testing.T) {
	testCases := []struct {
		name     string
		op       ResidentKeyOperation
		expected string
	}{
		{"Encrypt", ResidentKeyOpEncrypt, "ENCRYPT"},
		{"Decrypt", ResidentKeyOpDecrypt, "DECRYPT"},
		{"MAC", ResidentKeyOpMAC, "MAC"},
		{"VerifyMAC", ResidentKeyOpVerifyMAC, "VERIFY_MAC"},
		{"Wrap", ResidentKeyOpWrap, "WRAP"},
		{"Unwrap", ResidentKeyOpUnwrap, "UNWRAP"},
		{"Unknown", ResidentKeyOperation(99), "UNKNOWN(99)"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.op.String())
		})
	}
}

// =============================================================================
// OperationParams Tests
// =============================================================================

func TestOperationParams_JSONRoundTrip(t *testing.T) {
	original := &OperationParams{
		Algorithm: "AES-GCM",
		IV:        []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c},
		AAD:       []byte("additional-data"),
		TagLength: 128,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var parsed OperationParams
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, original.Algorithm, parsed.Algorithm)
	assert.Equal(t, original.IV, parsed.IV)
	assert.Equal(t, original.AAD, parsed.AAD)
	assert.Equal(t, original.TagLength, parsed.TagLength)
}

// =============================================================================
// Extended KDFParams Tests
// =============================================================================

func TestKDFParams_WithDerivationMode(t *testing.T) {
	params := &KDFParams{
		Algorithm:      KDFAlgorithmHKDF,
		Hash:           "SHA-256",
		KeyLength:      32,
		DerivationMode: KeyDerivationModeHSMResident,
		DerivedKeyAttributes: &DerivedKeyTemplateParams{
			Label:   "test-key",
			KeyType: "AES",
		},
		HSMKDFType: 0x00000002, // CKD_SHA256_KDF
	}

	err := params.Validate()
	require.NoError(t, err)

	assert.Equal(t, KeyDerivationModeHSMResident, params.DerivationMode)
	assert.NotNil(t, params.DerivedKeyAttributes)
	assert.Equal(t, "test-key", params.DerivedKeyAttributes.Label)
	assert.Equal(t, uint32(0x00000002), params.HSMKDFType)
}

func TestKDFParams_ValidateDerivationMode(t *testing.T) {
	testCases := []struct {
		name      string
		mode      KeyDerivationMode
		expectErr bool
	}{
		{"Export", KeyDerivationModeExport, false},
		{"HSMResident", KeyDerivationModeHSMResident, false},
		{"HSMKDF", KeyDerivationModeHSMKDF, false},
		{"TPMWrapped", KeyDerivationModeTPMWrapped, false},
		{"Invalid", KeyDerivationMode(99), true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			params := &KDFParams{
				Algorithm:      KDFAlgorithmHKDF,
				Hash:           "SHA-256",
				KeyLength:      32,
				DerivationMode: tc.mode,
			}
			err := params.Validate()
			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid derivation mode")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestKDFParams_DefaultsDerivationModeToExport(t *testing.T) {
	params := &KDFParams{
		KeyLength: 32,
	}

	err := params.Validate()
	require.NoError(t, err)

	// DerivationMode should remain 0 (Export) as default
	assert.Equal(t, KeyDerivationModeExport, params.DerivationMode)
}

// =============================================================================
// TPMDerivedKeyHandle Tests
// =============================================================================

func TestTPMDerivedKeyHandle_JSONRoundTrip(t *testing.T) {
	original := &TPMDerivedKeyHandle{
		Handle:       0x81000001,
		ParentHandle: 0x81000000,
		Public:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		Private:      []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		PolicyDigest: []byte{0x20, 0x21, 0x22, 0x23},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var parsed TPMDerivedKeyHandle
	err = json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	assert.Equal(t, original.Handle, parsed.Handle)
	assert.Equal(t, original.ParentHandle, parsed.ParentHandle)
	assert.Equal(t, original.Public, parsed.Public)
	assert.Equal(t, original.Private, parsed.Private)
	assert.Equal(t, original.PolicyDigest, parsed.PolicyDigest)
}

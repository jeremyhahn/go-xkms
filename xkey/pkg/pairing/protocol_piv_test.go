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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPIVSlotConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"PIVSlotAuthentication", PIVSlotAuthentication, "9a"},
		{"PIVSlotDigitalSignature", PIVSlotDigitalSignature, "9c"},
		{"PIVSlotKeyManagement", PIVSlotKeyManagement, "9d"},
		{"PIVSlotCardAuth", PIVSlotCardAuth, "9e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	assert.Equal(t, 4, len(tests), "expected exactly 4 PIV slot constants")
}

func TestPIVMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"MethodLocalPIVGenerateKey", MethodLocalPIVGenerateKey, "local.pivGenerateKey"},
		{"MethodLocalPIVImportCert", MethodLocalPIVImportCert, "local.pivImportCert"},
		{"MethodLocalPIVListSlots", MethodLocalPIVListSlots, "local.pivListSlots"},
		{"MethodLocalPIVSign", MethodLocalPIVSign, "local.pivSign"},
		{"MethodLocalPIVGetCert", MethodLocalPIVGetCert, "local.pivGetCert"},
		{"MethodRemotePIVListSlots", MethodRemotePIVListSlots, "remote.pivListSlots"},
		{"MethodRemotePIVSign", MethodRemotePIVSign, "remote.pivSign"},
		{"MethodRemotePIVGetCert", MethodRemotePIVGetCert, "remote.pivGetCert"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	assert.Equal(t, 8, len(tests), "expected exactly 8 PIV method constants")
}

func TestIsPIVLocalMethod(t *testing.T) {
	t.Run("valid PIV local methods", func(t *testing.T) {
		validMethods := []string{
			MethodLocalPIVGenerateKey,
			MethodLocalPIVImportCert,
			MethodLocalPIVListSlots,
			MethodLocalPIVSign,
			MethodLocalPIVGetCert,
		}
		for _, method := range validMethods {
			assert.True(t, IsPIVLocalMethod(method),
				"expected IsPIVLocalMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"local.sign",
			"remote.pivListSlots",
			"local.pivGenerateKey_typo",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsPIVLocalMethod(method),
				"expected IsPIVLocalMethod(%q) to return false", method)
		}
	})
}

func TestIsPIVRemoteMethod(t *testing.T) {
	t.Run("valid PIV remote methods", func(t *testing.T) {
		validMethods := []string{
			MethodRemotePIVListSlots,
			MethodRemotePIVSign,
			MethodRemotePIVGetCert,
		}
		for _, method := range validMethods {
			assert.True(t, IsPIVRemoteMethod(method),
				"expected IsPIVRemoteMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"remote.sign",
			"local.pivListSlots",
			"remote.pivListSlots_typo",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsPIVRemoteMethod(method),
				"expected IsPIVRemoteMethod(%q) to return false", method)
		}
	})
}

func TestPIVMethodsRegisteredInGlobalMaps(t *testing.T) {
	// Verify PIV local methods are registered in the global localMethodNames map.
	assert.True(t, IsLocalMethod(MethodLocalPIVGenerateKey))
	assert.True(t, IsLocalMethod(MethodLocalPIVImportCert))
	assert.True(t, IsLocalMethod(MethodLocalPIVListSlots))
	assert.True(t, IsLocalMethod(MethodLocalPIVSign))
	assert.True(t, IsLocalMethod(MethodLocalPIVGetCert))

	// Verify PIV remote methods are registered in the global remoteMethodNames map.
	assert.True(t, IsRemoteMethod(MethodRemotePIVListSlots))
	assert.True(t, IsRemoteMethod(MethodRemotePIVSign))
	assert.True(t, IsRemoteMethod(MethodRemotePIVGetCert))
}

// --- PIVSlotInfo ---

func TestPIVSlotInfo_JSONRoundTrip(t *testing.T) {
	original := PIVSlotInfo{
		Slot:           PIVSlotAuthentication,
		Label:          "Authentication Key",
		Algorithm:      "ECDSA-P256",
		HasKey:         true,
		HasCertificate: true,
		CertSubject:    "CN=test-user",
		CertExpiry:     "2026-12-31T23:59:59Z",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PIVSlotInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestPIVSlotInfo_JSONFieldNames(t *testing.T) {
	info := PIVSlotInfo{
		Slot:           "9a",
		Label:          "test",
		Algorithm:      "RSA-2048",
		HasKey:         true,
		HasCertificate: true,
		CertSubject:    "CN=test",
		CertExpiry:     "2026-01-01T00:00:00Z",
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"slot", "label", "algorithm", "has_key",
		"has_certificate", "cert_subject", "cert_expiry",
	}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

func TestPIVSlotInfo_OmitEmptyFields(t *testing.T) {
	info := PIVSlotInfo{
		Slot:   "9a",
		HasKey: false,
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "label")
	assert.NotContains(t, raw, "algorithm")
	assert.NotContains(t, raw, "cert_subject")
	assert.NotContains(t, raw, "cert_expiry")
}

func TestPIVSlotInfo_EmptySlot(t *testing.T) {
	original := PIVSlotInfo{
		Slot:           PIVSlotKeyManagement,
		HasKey:         false,
		HasCertificate: false,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PIVSlotInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, PIVSlotKeyManagement, decoded.Slot)
	assert.False(t, decoded.HasKey)
	assert.False(t, decoded.HasCertificate)
	assert.Empty(t, decoded.Label)
	assert.Empty(t, decoded.Algorithm)
}

// --- local.pivGenerateKey ---

func TestLocalPIVGenerateKeyParams_JSONRoundTrip(t *testing.T) {
	original := &LocalPIVGenerateKeyParams{
		Slot:      PIVSlotAuthentication,
		Algorithm: "ECDSA-P256",
		Label:     "my-auth-key",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVGenerateKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Slot, decoded.Slot)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
	assert.Equal(t, original.Label, decoded.Label)
}

func TestLocalPIVGenerateKeyParams_JSONFieldNames(t *testing.T) {
	params := LocalPIVGenerateKeyParams{
		Slot:      "9a",
		Algorithm: "ECDSA-P256",
		Label:     "test",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "slot")
	assert.Contains(t, raw, "algorithm")
	assert.Contains(t, raw, "label")
}

func TestLocalPIVGenerateKeyParams_OmitEmptyLabel(t *testing.T) {
	params := LocalPIVGenerateKeyParams{
		Slot:      "9c",
		Algorithm: "RSA-2048",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "label")
}

func TestLocalPIVGenerateKeyResult_JSONRoundTrip(t *testing.T) {
	original := &LocalPIVGenerateKeyResult{
		Slot:         PIVSlotAuthentication,
		PublicKeyDER: []byte{0x30, 0x59, 0x30, 0x13},
		Algorithm:    "ECDSA-P256",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVGenerateKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Slot, decoded.Slot)
	assert.Equal(t, original.PublicKeyDER, decoded.PublicKeyDER)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
}

func TestLocalPIVGenerateKeyResult_OmitEmptyPublicKey(t *testing.T) {
	result := LocalPIVGenerateKeyResult{
		Slot:      "9a",
		Algorithm: "AES-256",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "public_key_der")
}

// --- local.pivImportCert ---

func TestLocalPIVImportCertParams_JSONRoundTrip(t *testing.T) {
	original := &LocalPIVImportCertParams{
		Slot:           PIVSlotDigitalSignature,
		CertificateDER: []byte{0x30, 0x82, 0x01, 0x00},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVImportCertParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Slot, decoded.Slot)
	assert.Equal(t, original.CertificateDER, decoded.CertificateDER)
}

func TestLocalPIVImportCertParams_JSONFieldNames(t *testing.T) {
	params := LocalPIVImportCertParams{
		Slot:           "9c",
		CertificateDER: []byte{0x01},
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "slot")
	assert.Contains(t, raw, "certificate_der")
}

func TestLocalPIVImportCertResult_JSONRoundTrip(t *testing.T) {
	original := &LocalPIVImportCertResult{
		Success: true,
		Message: "certificate imported into slot 9c",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVImportCertResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.Message, decoded.Message)
}

func TestLocalPIVImportCertResult_OmitEmptyMessage(t *testing.T) {
	result := LocalPIVImportCertResult{
		Success: true,
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "message")
}

func TestLocalPIVImportCertResult_NotSuccess(t *testing.T) {
	original := &LocalPIVImportCertResult{
		Success: false,
		Message: "slot already occupied",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVImportCertResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.False(t, decoded.Success)
	assert.Equal(t, "slot already occupied", decoded.Message)
}

// --- local.pivListSlots ---

func TestLocalPIVListSlotsParams_JSONRoundTrip(t *testing.T) {
	original := &LocalPIVListSlotsParams{}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVListSlotsParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, *original, decoded)
}

func TestLocalPIVListSlotsResult_JSONRoundTrip(t *testing.T) {
	original := &LocalPIVListSlotsResult{
		Slots: []PIVSlotInfo{
			{
				Slot:           PIVSlotAuthentication,
				Label:          "Auth Key",
				Algorithm:      "ECDSA-P256",
				HasKey:         true,
				HasCertificate: true,
				CertSubject:    "CN=user",
				CertExpiry:     "2026-12-31T23:59:59Z",
			},
			{
				Slot:           PIVSlotDigitalSignature,
				HasKey:         false,
				HasCertificate: false,
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVListSlotsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Slots, 2)
	assert.Equal(t, original.Slots[0].Slot, decoded.Slots[0].Slot)
	assert.True(t, decoded.Slots[0].HasKey)
	assert.Equal(t, original.Slots[1].Slot, decoded.Slots[1].Slot)
	assert.False(t, decoded.Slots[1].HasKey)
}

func TestLocalPIVListSlotsResult_EmptySlots(t *testing.T) {
	original := &LocalPIVListSlotsResult{
		Slots: []PIVSlotInfo{},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVListSlotsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.Slots)
}

// --- local.pivSign ---

func TestLocalPIVSignParams_JSONRoundTrip(t *testing.T) {
	t.Run("with algorithm", func(t *testing.T) {
		original := &LocalPIVSignParams{
			Slot:      PIVSlotAuthentication,
			Data:      []byte("data to sign"),
			Algorithm: "SHA256withECDSA",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalPIVSignParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Slot, decoded.Slot)
		assert.Equal(t, original.Data, decoded.Data)
		assert.Equal(t, original.Algorithm, decoded.Algorithm)
	})

	t.Run("without algorithm", func(t *testing.T) {
		original := &LocalPIVSignParams{
			Slot: PIVSlotDigitalSignature,
			Data: []byte("sign me"),
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		assert.NotContains(t, raw, "algorithm")
	})
}

func TestLocalPIVSignResult_JSONRoundTrip(t *testing.T) {
	original := &LocalPIVSignResult{
		Signature: []byte{0x30, 0x44, 0x02, 0x20, 0xAB, 0xCD},
		Algorithm: "SHA256withECDSA",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVSignResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Signature, decoded.Signature)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
}

// --- local.pivGetCert ---

func TestLocalPIVGetCertParams_JSONRoundTrip(t *testing.T) {
	original := &LocalPIVGetCertParams{
		Slot: PIVSlotKeyManagement,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVGetCertParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Slot, decoded.Slot)
}

func TestLocalPIVGetCertResult_JSONRoundTrip(t *testing.T) {
	original := &LocalPIVGetCertResult{
		CertificateDER: []byte{0x30, 0x82, 0x01, 0x00},
		Subject:        "CN=test-user",
		Issuer:         "CN=test-ca",
		Expiry:         "2026-12-31T23:59:59Z",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalPIVGetCertResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.CertificateDER, decoded.CertificateDER)
	assert.Equal(t, original.Subject, decoded.Subject)
	assert.Equal(t, original.Issuer, decoded.Issuer)
	assert.Equal(t, original.Expiry, decoded.Expiry)
}

func TestLocalPIVGetCertResult_OmitEmptyFields(t *testing.T) {
	result := LocalPIVGetCertResult{
		CertificateDER: []byte{0x01},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "subject")
	assert.NotContains(t, raw, "issuer")
	assert.NotContains(t, raw, "expiry")
}

func TestLocalPIVGetCertResult_JSONFieldNames(t *testing.T) {
	result := LocalPIVGetCertResult{
		CertificateDER: []byte{0x01},
		Subject:        "CN=test",
		Issuer:         "CN=ca",
		Expiry:         "2026-01-01T00:00:00Z",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"certificate_der", "subject", "issuer", "expiry"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

// --- remote.pivListSlots ---

func TestRemotePIVListSlotsParams_JSONRoundTrip(t *testing.T) {
	t.Run("with backend", func(t *testing.T) {
		original := &RemotePIVListSlotsParams{
			Backend: "pkcs11",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemotePIVListSlotsParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Backend, decoded.Backend)
	})

	t.Run("without backend (omitempty)", func(t *testing.T) {
		original := &RemotePIVListSlotsParams{}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "backend")
	})
}

func TestRemotePIVListSlotsResult_JSONRoundTrip(t *testing.T) {
	original := &RemotePIVListSlotsResult{
		Slots: []PIVSlotInfo{
			{
				Slot:           PIVSlotAuthentication,
				Label:          "Auth",
				Algorithm:      "ECDSA-P256",
				HasKey:         true,
				HasCertificate: true,
				CertSubject:    "CN=admin",
				CertExpiry:     "2027-06-15T12:00:00Z",
			},
			{
				Slot:           PIVSlotCardAuth,
				HasKey:         false,
				HasCertificate: false,
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemotePIVListSlotsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Slots, 2)
	assert.Equal(t, original.Slots[0], decoded.Slots[0])
	assert.Equal(t, original.Slots[1].Slot, decoded.Slots[1].Slot)
	assert.False(t, decoded.Slots[1].HasKey)
}

func TestRemotePIVListSlotsResult_EmptySlots(t *testing.T) {
	original := &RemotePIVListSlotsResult{
		Slots: []PIVSlotInfo{},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemotePIVListSlotsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.Slots)
}

// --- remote.pivSign ---

func TestRemotePIVSignParams_JSONRoundTrip(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		original := &RemotePIVSignParams{
			Slot:      PIVSlotAuthentication,
			Data:      []byte("data to sign"),
			Algorithm: "SHA256withECDSA",
			Backend:   "pkcs11",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemotePIVSignParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, &decoded)
	})

	t.Run("without optional fields", func(t *testing.T) {
		original := &RemotePIVSignParams{
			Slot: PIVSlotDigitalSignature,
			Data: []byte("sign this"),
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "algorithm")
		assert.NotContains(t, raw, "backend")
	})
}

func TestRemotePIVSignParams_JSONFieldNames(t *testing.T) {
	params := RemotePIVSignParams{
		Slot:      "9a",
		Data:      []byte{0x01},
		Algorithm: "SHA256",
		Backend:   "sw",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "slot")
	assert.Contains(t, raw, "data")
	assert.Contains(t, raw, "algorithm")
	assert.Contains(t, raw, "backend")
}

func TestRemotePIVSignResult_JSONRoundTrip(t *testing.T) {
	original := &RemotePIVSignResult{
		Signature: []byte{0x30, 0x44, 0x02, 0x20, 0xAB},
		Algorithm: "SHA256withECDSA",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemotePIVSignResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Signature, decoded.Signature)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
}

// --- remote.pivGetCert ---

func TestRemotePIVGetCertParams_JSONRoundTrip(t *testing.T) {
	t.Run("with backend", func(t *testing.T) {
		original := &RemotePIVGetCertParams{
			Slot:    PIVSlotAuthentication,
			Backend: "pkcs11",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemotePIVGetCertParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Slot, decoded.Slot)
		assert.Equal(t, original.Backend, decoded.Backend)
	})

	t.Run("without backend (omitempty)", func(t *testing.T) {
		original := &RemotePIVGetCertParams{
			Slot: PIVSlotKeyManagement,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "backend")
	})
}

func TestRemotePIVGetCertParams_JSONFieldNames(t *testing.T) {
	params := RemotePIVGetCertParams{
		Slot:    "9a",
		Backend: "sw",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "slot")
	assert.Contains(t, raw, "backend")
}

func TestRemotePIVGetCertResult_JSONRoundTrip(t *testing.T) {
	original := &RemotePIVGetCertResult{
		CertificateDER: []byte{0x30, 0x82, 0x01, 0x00},
		Subject:        "CN=laptop-user",
		Issuer:         "CN=enterprise-ca",
		Expiry:         "2027-01-01T00:00:00Z",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemotePIVGetCertResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.CertificateDER, decoded.CertificateDER)
	assert.Equal(t, original.Subject, decoded.Subject)
	assert.Equal(t, original.Issuer, decoded.Issuer)
	assert.Equal(t, original.Expiry, decoded.Expiry)
}

func TestRemotePIVGetCertResult_OmitEmptyFields(t *testing.T) {
	result := RemotePIVGetCertResult{
		CertificateDER: []byte{0x01},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "subject")
	assert.NotContains(t, raw, "issuer")
	assert.NotContains(t, raw, "expiry")
}

func TestRemotePIVGetCertResult_JSONFieldNames(t *testing.T) {
	result := RemotePIVGetCertResult{
		CertificateDER: []byte{0x01},
		Subject:        "CN=test",
		Issuer:         "CN=ca",
		Expiry:         "2026-01-01T00:00:00Z",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"certificate_der", "subject", "issuer", "expiry"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

// --- Zero-value and edge case tests ---

func TestPIVTypes_ZeroValues(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
	}{
		{"PIVSlotInfo", &PIVSlotInfo{}},
		{"LocalPIVGenerateKeyParams", &LocalPIVGenerateKeyParams{}},
		{"LocalPIVGenerateKeyResult", &LocalPIVGenerateKeyResult{}},
		{"LocalPIVImportCertParams", &LocalPIVImportCertParams{}},
		{"LocalPIVImportCertResult", &LocalPIVImportCertResult{}},
		{"LocalPIVListSlotsParams", &LocalPIVListSlotsParams{}},
		{"LocalPIVListSlotsResult", &LocalPIVListSlotsResult{}},
		{"LocalPIVSignParams", &LocalPIVSignParams{}},
		{"LocalPIVSignResult", &LocalPIVSignResult{}},
		{"LocalPIVGetCertParams", &LocalPIVGetCertParams{}},
		{"LocalPIVGetCertResult", &LocalPIVGetCertResult{}},
		{"RemotePIVListSlotsParams", &RemotePIVListSlotsParams{}},
		{"RemotePIVListSlotsResult", &RemotePIVListSlotsResult{}},
		{"RemotePIVSignParams", &RemotePIVSignParams{}},
		{"RemotePIVSignResult", &RemotePIVSignResult{}},
		{"RemotePIVGetCertParams", &RemotePIVGetCertParams{}},
		{"RemotePIVGetCertResult", &RemotePIVGetCertResult{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.val)
			require.NoError(t, err)
			require.NotEmpty(t, data)
			assert.True(t, json.Valid(data), "expected valid JSON for zero-value %s", tt.name)
		})
	}
}

// --- Error code mapping tests ---

func TestPIVErrorCodeMapping(t *testing.T) {
	t.Run("PIV slot not found maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodePIVSlotNotFound, Message: "not found"})
		assert.Equal(t, ErrPIVSlotNotFound, mapped)
	})

	t.Run("PIV slot occupied maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodePIVSlotOccupied, Message: "occupied"})
		assert.Equal(t, ErrPIVSlotOccupied, mapped)
	})

	t.Run("PIV sign failed maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodePIVSignFailed, Message: "sign failed"})
		assert.Equal(t, ErrPIVSignFailed, mapped)
	})

	t.Run("PIV invalid slot maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodePIVInvalidSlot, Message: "invalid slot"})
		assert.Equal(t, ErrPIVInvalidSlot, mapped)
	})
}

// --- NewRequest integration tests ---

func TestNewRequest_PIVMethods(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "local pivGenerateKey",
			method: MethodLocalPIVGenerateKey,
			params: &LocalPIVGenerateKeyParams{
				Slot:      PIVSlotAuthentication,
				Algorithm: "ECDSA-P256",
				Label:     "auth-key",
			},
		},
		{
			name:   "local pivImportCert",
			method: MethodLocalPIVImportCert,
			params: &LocalPIVImportCertParams{
				Slot:           PIVSlotDigitalSignature,
				CertificateDER: []byte{0x30, 0x82, 0x01, 0x00},
			},
		},
		{
			name:   "local pivListSlots",
			method: MethodLocalPIVListSlots,
			params: &LocalPIVListSlotsParams{},
		},
		{
			name:   "local pivSign",
			method: MethodLocalPIVSign,
			params: &LocalPIVSignParams{
				Slot:      PIVSlotAuthentication,
				Data:      []byte("challenge data"),
				Algorithm: "SHA256withECDSA",
			},
		},
		{
			name:   "local pivGetCert",
			method: MethodLocalPIVGetCert,
			params: &LocalPIVGetCertParams{
				Slot: PIVSlotKeyManagement,
			},
		},
		{
			name:   "remote pivListSlots",
			method: MethodRemotePIVListSlots,
			params: &RemotePIVListSlotsParams{
				Backend: "pkcs11",
			},
		},
		{
			name:   "remote pivSign",
			method: MethodRemotePIVSign,
			params: &RemotePIVSignParams{
				Slot: PIVSlotAuthentication,
				Data: []byte("sign this"),
			},
		},
		{
			name:   "remote pivGetCert",
			method: MethodRemotePIVGetCert,
			params: &RemotePIVGetCertParams{
				Slot: PIVSlotCardAuth,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := NewRequest(tt.method, tt.params)

			require.NotNil(t, req)
			assert.Equal(t, JSONRPCVersion, req.JSONRPC)
			assert.NotZero(t, req.ID)
			assert.Equal(t, tt.method, req.Method)
			assert.Equal(t, tt.params, req.Params)

			data, err := EncodeRequest(req)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			var raw map[string]interface{}
			err = json.Unmarshal(data, &raw)
			require.NoError(t, err)
			assert.Equal(t, tt.method, raw["method"])
		})
	}
}

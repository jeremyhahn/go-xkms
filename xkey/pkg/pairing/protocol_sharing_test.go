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

func TestSharingMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"MethodLocalSharePublicKey", MethodLocalSharePublicKey, "local.sharePublicKey"},
		{"MethodLocalShareSymmetric", MethodLocalShareSymmetric, "local.shareSymmetric"},
		{"MethodLocalImportSharedKey", MethodLocalImportSharedKey, "local.importSharedKey"},
		{"MethodRemoteSharePublicKey", MethodRemoteSharePublicKey, "remote.sharePublicKey"},
		{"MethodRemoteShareSymmetric", MethodRemoteShareSymmetric, "remote.shareSymmetric"},
		{"MethodRemoteImportSharedKey", MethodRemoteImportSharedKey, "remote.importSharedKey"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	assert.Equal(t, 6, len(tests), "expected exactly 6 sharing method constants")
}

func TestIsSharingLocalMethod(t *testing.T) {
	t.Run("valid sharing local methods", func(t *testing.T) {
		validMethods := []string{
			MethodLocalSharePublicKey,
			MethodLocalShareSymmetric,
			MethodLocalImportSharedKey,
		}
		for _, method := range validMethods {
			assert.True(t, IsSharingLocalMethod(method),
				"expected IsSharingLocalMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"local.sign",
			"remote.sharePublicKey",
			"local.sharePublicKey_typo",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsSharingLocalMethod(method),
				"expected IsSharingLocalMethod(%q) to return false", method)
		}
	})
}

func TestIsSharingRemoteMethod(t *testing.T) {
	t.Run("valid sharing remote methods", func(t *testing.T) {
		validMethods := []string{
			MethodRemoteSharePublicKey,
			MethodRemoteShareSymmetric,
			MethodRemoteImportSharedKey,
		}
		for _, method := range validMethods {
			assert.True(t, IsSharingRemoteMethod(method),
				"expected IsSharingRemoteMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"remote.sign",
			"local.sharePublicKey",
			"remote.sharePublicKey_typo",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsSharingRemoteMethod(method),
				"expected IsSharingRemoteMethod(%q) to return false", method)
		}
	})
}

func TestSharingMethodsRegisteredInGlobalMaps(t *testing.T) {
	// Verify sharing local methods are registered in the global localMethodNames map.
	assert.True(t, IsLocalMethod(MethodLocalSharePublicKey))
	assert.True(t, IsLocalMethod(MethodLocalShareSymmetric))
	assert.True(t, IsLocalMethod(MethodLocalImportSharedKey))

	// Verify sharing remote methods are registered in the global remoteMethodNames map.
	assert.True(t, IsRemoteMethod(MethodRemoteSharePublicKey))
	assert.True(t, IsRemoteMethod(MethodRemoteShareSymmetric))
	assert.True(t, IsRemoteMethod(MethodRemoteImportSharedKey))
}

// --- local.sharePublicKey ---

func TestLocalSharePublicKeyParams_JSONRoundTrip(t *testing.T) {
	original := &LocalSharePublicKeyParams{
		Backend:        "tpm2",
		KeyID:          "signing-key-001",
		PublicKeyPEM:   []byte("-----BEGIN PUBLIC KEY-----\nMFkw..."),
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nMIIB..."),
		Algorithm:      "ES256",
		Label:          "Laptop Signing Key",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSharePublicKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Backend, decoded.Backend)
	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.PublicKeyPEM, decoded.PublicKeyPEM)
	assert.Equal(t, original.CertificatePEM, decoded.CertificatePEM)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
	assert.Equal(t, original.Label, decoded.Label)
}

func TestLocalSharePublicKeyParams_JSONFieldNames(t *testing.T) {
	params := LocalSharePublicKeyParams{
		Backend:        "software",
		KeyID:          "k1",
		PublicKeyPEM:   []byte("pem-data"),
		CertificatePEM: []byte("cert-data"),
		Algorithm:      "RS256",
		Label:          "test",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"backend", "key_id", "public_key_pem", "certificate_pem",
		"algorithm", "label",
	}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

func TestLocalSharePublicKeyParams_OmitEmptyOptionalFields(t *testing.T) {
	params := LocalSharePublicKeyParams{
		Backend:      "software",
		KeyID:        "k1",
		PublicKeyPEM: []byte("pem-data"),
		Algorithm:    "ES256",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "certificate_pem")
	assert.NotContains(t, raw, "label")
}

func TestLocalSharePublicKeyResult_JSONRoundTrip(t *testing.T) {
	original := &LocalSharePublicKeyResult{
		Accepted: true,
		ImportID: "import-abc-123",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSharePublicKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Accepted, decoded.Accepted)
	assert.Equal(t, original.ImportID, decoded.ImportID)
}

func TestLocalSharePublicKeyResult_NotAccepted(t *testing.T) {
	original := &LocalSharePublicKeyResult{
		Accepted: false,
		ImportID: "",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSharePublicKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.False(t, decoded.Accepted)
	assert.Empty(t, decoded.ImportID)
}

// --- remote.sharePublicKey ---

func TestRemoteSharePublicKeyParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteSharePublicKeyParams{
		KeyID:          "phone-signing-key",
		PublicKeyPEM:   []byte("-----BEGIN PUBLIC KEY-----\nMFkw..."),
		CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nMIIB..."),
		Algorithm:      "ES256",
		Label:          "Phone Signing Key",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSharePublicKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.PublicKeyPEM, decoded.PublicKeyPEM)
	assert.Equal(t, original.CertificatePEM, decoded.CertificatePEM)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
	assert.Equal(t, original.Label, decoded.Label)
}

func TestRemoteSharePublicKeyParams_WithoutOptionalFields(t *testing.T) {
	original := &RemoteSharePublicKeyParams{
		KeyID:        "k1",
		PublicKeyPEM: []byte("data"),
		Algorithm:    "ES256",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "certificate_pem")
	assert.NotContains(t, raw, "label")
}

func TestRemoteSharePublicKeyResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteSharePublicKeyResult{
		Accepted: true,
		ImportID: "remote-import-456",
		Backend:  "software",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSharePublicKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Accepted, decoded.Accepted)
	assert.Equal(t, original.ImportID, decoded.ImportID)
	assert.Equal(t, original.Backend, decoded.Backend)
}

// --- local.shareSymmetric ---

func TestLocalShareSymmetricParams_JSONRoundTrip(t *testing.T) {
	original := &LocalShareSymmetricParams{
		Backend:    "software",
		KeyID:      "aes-key-001",
		WrappedKey: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE},
		Algorithm:  "AES256",
		KeySize:    256,
		Label:      "Shared AES Key",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalShareSymmetricParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Backend, decoded.Backend)
	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.WrappedKey, decoded.WrappedKey)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
	assert.Equal(t, original.KeySize, decoded.KeySize)
	assert.Equal(t, original.Label, decoded.Label)
}

func TestLocalShareSymmetricParams_JSONFieldNames(t *testing.T) {
	params := LocalShareSymmetricParams{
		Backend:    "tpm2",
		KeyID:      "k1",
		WrappedKey: []byte{0x01},
		Algorithm:  "AES256",
		KeySize:    256,
		Label:      "test",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"backend", "key_id", "wrapped_key", "algorithm",
		"key_size", "label",
	}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

func TestLocalShareSymmetricParams_OmitEmptyLabel(t *testing.T) {
	params := LocalShareSymmetricParams{
		Backend:    "software",
		KeyID:      "k1",
		WrappedKey: []byte{0x01},
		Algorithm:  "AES256",
		KeySize:    256,
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "label")
}

func TestLocalShareSymmetricResult_JSONRoundTrip(t *testing.T) {
	original := &LocalShareSymmetricResult{
		Accepted: true,
		ImportID: "sym-import-789",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalShareSymmetricResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Accepted, decoded.Accepted)
	assert.Equal(t, original.ImportID, decoded.ImportID)
}

// --- remote.shareSymmetric ---

func TestRemoteShareSymmetricParams_JSONRoundTrip(t *testing.T) {
	original := &RemoteShareSymmetricParams{
		KeyID:      "phone-aes-key",
		WrappedKey: []byte{0xCA, 0xFE, 0xBA, 0xBE},
		Algorithm:  "CHACHA20",
		KeySize:    256,
		Label:      "Phone AES Key",
		Backend:    "software",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteShareSymmetricParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.WrappedKey, decoded.WrappedKey)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
	assert.Equal(t, original.KeySize, decoded.KeySize)
	assert.Equal(t, original.Label, decoded.Label)
	assert.Equal(t, original.Backend, decoded.Backend)
}

func TestRemoteShareSymmetricParams_OptionalFields(t *testing.T) {
	original := &RemoteShareSymmetricParams{
		KeyID:      "k1",
		WrappedKey: []byte{0x01},
		Algorithm:  "AES256",
		KeySize:    256,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "label")
	assert.NotContains(t, raw, "backend")
}

func TestRemoteShareSymmetricResult_JSONRoundTrip(t *testing.T) {
	original := &RemoteShareSymmetricResult{
		Accepted: true,
		ImportID: "remote-sym-import-001",
		Backend:  "tpm2",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteShareSymmetricResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Accepted, decoded.Accepted)
	assert.Equal(t, original.ImportID, decoded.ImportID)
	assert.Equal(t, original.Backend, decoded.Backend)
}

// --- local.importSharedKey ---

func TestLocalImportSharedKeyParams_JSONRoundTrip(t *testing.T) {
	t.Run("with format", func(t *testing.T) {
		original := &LocalImportSharedKeyParams{
			KeyID:  "export-key-001",
			Format: "der",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalImportSharedKeyParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.KeyID, decoded.KeyID)
		assert.Equal(t, original.Format, decoded.Format)
	})

	t.Run("without format (omitempty)", func(t *testing.T) {
		original := &LocalImportSharedKeyParams{
			KeyID: "export-key-002",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "format")
	})
}

func TestLocalImportSharedKeyResult_JSONRoundTrip(t *testing.T) {
	t.Run("public key export", func(t *testing.T) {
		original := &LocalImportSharedKeyResult{
			PublicKeyPEM:   []byte("-----BEGIN PUBLIC KEY-----\nMFkw..."),
			CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nMIIB..."),
			Algorithm:      "ES256",
			KeyType:        "public",
			Exportable:     true,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalImportSharedKeyResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.PublicKeyPEM, decoded.PublicKeyPEM)
		assert.Equal(t, original.CertificatePEM, decoded.CertificatePEM)
		assert.Equal(t, original.Algorithm, decoded.Algorithm)
		assert.Equal(t, original.KeyType, decoded.KeyType)
		assert.True(t, decoded.Exportable)
		assert.Nil(t, decoded.WrappedKey)
		assert.Zero(t, decoded.KeySize)
	})

	t.Run("symmetric key export", func(t *testing.T) {
		original := &LocalImportSharedKeyResult{
			Algorithm:  "AES256",
			KeyType:    "symmetric",
			WrappedKey: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			KeySize:    256,
			Exportable: true,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalImportSharedKeyResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Algorithm, decoded.Algorithm)
		assert.Equal(t, original.KeyType, decoded.KeyType)
		assert.Equal(t, original.WrappedKey, decoded.WrappedKey)
		assert.Equal(t, original.KeySize, decoded.KeySize)
		assert.True(t, decoded.Exportable)
	})

	t.Run("not exportable", func(t *testing.T) {
		original := &LocalImportSharedKeyResult{
			Algorithm:  "ES256",
			KeyType:    "public",
			Exportable: false,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalImportSharedKeyResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.False(t, decoded.Exportable)
	})
}

func TestLocalImportSharedKeyResult_OmitEmptyOptionalFields(t *testing.T) {
	result := LocalImportSharedKeyResult{
		Algorithm:  "ES256",
		KeyType:    "public",
		Exportable: true,
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "certificate_pem")
	assert.NotContains(t, raw, "wrapped_key")
	assert.NotContains(t, raw, "key_size")
}

// --- remote.importSharedKey ---

func TestRemoteImportSharedKeyParams_JSONRoundTrip(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		original := &RemoteImportSharedKeyParams{
			Backend: "tpm2",
			KeyID:   "laptop-key-001",
			Format:  "pem",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteImportSharedKeyParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Backend, decoded.Backend)
		assert.Equal(t, original.KeyID, decoded.KeyID)
		assert.Equal(t, original.Format, decoded.Format)
	})

	t.Run("without format (omitempty)", func(t *testing.T) {
		original := &RemoteImportSharedKeyParams{
			Backend: "software",
			KeyID:   "key-002",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "backend")
		assert.Contains(t, raw, "key_id")
		assert.NotContains(t, raw, "format")
	})
}

func TestRemoteImportSharedKeyResult_JSONRoundTrip(t *testing.T) {
	t.Run("public key result", func(t *testing.T) {
		original := &RemoteImportSharedKeyResult{
			PublicKeyPEM:   []byte("-----BEGIN PUBLIC KEY-----\nMFkw..."),
			CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nMIIB..."),
			Algorithm:      "ES256",
			KeyType:        "public",
			Exportable:     true,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteImportSharedKeyResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.PublicKeyPEM, decoded.PublicKeyPEM)
		assert.Equal(t, original.CertificatePEM, decoded.CertificatePEM)
		assert.Equal(t, original.Algorithm, decoded.Algorithm)
		assert.Equal(t, original.KeyType, decoded.KeyType)
		assert.True(t, decoded.Exportable)
	})

	t.Run("symmetric key result", func(t *testing.T) {
		original := &RemoteImportSharedKeyResult{
			Algorithm:  "AES256",
			KeyType:    "symmetric",
			WrappedKey: []byte{0xCA, 0xFE, 0xBA, 0xBE},
			KeySize:    256,
			Exportable: true,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteImportSharedKeyResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.WrappedKey, decoded.WrappedKey)
		assert.Equal(t, original.KeySize, decoded.KeySize)
		assert.Equal(t, original.KeyType, decoded.KeyType)
	})
}

func TestRemoteImportSharedKeyResult_OmitEmptyOptionalFields(t *testing.T) {
	result := RemoteImportSharedKeyResult{
		Algorithm:  "ES256",
		KeyType:    "public",
		Exportable: false,
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.NotContains(t, raw, "certificate_pem")
	assert.NotContains(t, raw, "wrapped_key")
	assert.NotContains(t, raw, "key_size")
}

// --- Zero-value and edge case tests ---

func TestSharingTypes_ZeroValues(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
	}{
		{"LocalSharePublicKeyParams", &LocalSharePublicKeyParams{}},
		{"LocalSharePublicKeyResult", &LocalSharePublicKeyResult{}},
		{"RemoteSharePublicKeyParams", &RemoteSharePublicKeyParams{}},
		{"RemoteSharePublicKeyResult", &RemoteSharePublicKeyResult{}},
		{"LocalShareSymmetricParams", &LocalShareSymmetricParams{}},
		{"LocalShareSymmetricResult", &LocalShareSymmetricResult{}},
		{"RemoteShareSymmetricParams", &RemoteShareSymmetricParams{}},
		{"RemoteShareSymmetricResult", &RemoteShareSymmetricResult{}},
		{"LocalImportSharedKeyParams", &LocalImportSharedKeyParams{}},
		{"LocalImportSharedKeyResult", &LocalImportSharedKeyResult{}},
		{"RemoteImportSharedKeyParams", &RemoteImportSharedKeyParams{}},
		{"RemoteImportSharedKeyResult", &RemoteImportSharedKeyResult{}},
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

func TestSharingErrorCodeMapping(t *testing.T) {
	t.Run("share denied maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeShareDenied, Message: "denied"})
		assert.Equal(t, ErrShareDenied, mapped)
	})

	t.Run("share not exportable maps correctly", func(t *testing.T) {
		mapped := MapRPCError(&RPCError{Code: ErrorCodeShareNotExportable, Message: "not exportable"})
		assert.Equal(t, ErrShareNotExportable, mapped)
	})
}

// --- NewRequest integration tests ---

func TestNewRequest_SharingMethods(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "local sharePublicKey",
			method: MethodLocalSharePublicKey,
			params: &LocalSharePublicKeyParams{
				Backend:      "software",
				KeyID:        "key-1",
				PublicKeyPEM: []byte("pem-data"),
				Algorithm:    "ES256",
			},
		},
		{
			name:   "local shareSymmetric",
			method: MethodLocalShareSymmetric,
			params: &LocalShareSymmetricParams{
				Backend:    "software",
				KeyID:      "aes-key",
				WrappedKey: []byte{0x01, 0x02},
				Algorithm:  "AES256",
				KeySize:    256,
			},
		},
		{
			name:   "local importSharedKey",
			method: MethodLocalImportSharedKey,
			params: &LocalImportSharedKeyParams{
				KeyID:  "key-to-export",
				Format: "pem",
			},
		},
		{
			name:   "remote sharePublicKey",
			method: MethodRemoteSharePublicKey,
			params: &RemoteSharePublicKeyParams{
				KeyID:        "phone-key",
				PublicKeyPEM: []byte("phone-pem"),
				Algorithm:    "ES256",
			},
		},
		{
			name:   "remote shareSymmetric",
			method: MethodRemoteShareSymmetric,
			params: &RemoteShareSymmetricParams{
				KeyID:      "phone-aes",
				WrappedKey: []byte{0x03, 0x04},
				Algorithm:  "AES256",
				KeySize:    256,
				Backend:    "software",
			},
		},
		{
			name:   "remote importSharedKey",
			method: MethodRemoteImportSharedKey,
			params: &RemoteImportSharedKeyParams{
				Backend: "tpm2",
				KeyID:   "laptop-key",
				Format:  "der",
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

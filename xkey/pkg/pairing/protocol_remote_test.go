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

func TestRemoteMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"MethodRemoteListBackends", MethodRemoteListBackends, "remote.listBackends"},
		{"MethodRemoteListKeys", MethodRemoteListKeys, "remote.listKeys"},
		{"MethodRemoteGetPublicKey", MethodRemoteGetPublicKey, "remote.getPublicKey"},
		{"MethodRemoteSign", MethodRemoteSign, "remote.sign"},
		{"MethodRemoteVerify", MethodRemoteVerify, "remote.verify"},
		{"MethodRemoteEncrypt", MethodRemoteEncrypt, "remote.encrypt"},
		{"MethodRemoteDecrypt", MethodRemoteDecrypt, "remote.decrypt"},
		{"MethodRemoteDeriveKey", MethodRemoteDeriveKey, "remote.deriveKey"},
		{"MethodRemoteGenerateKey", MethodRemoteGenerateKey, "remote.generateKey"},
		{"MethodRemoteGetKeyInfo", MethodRemoteGetKeyInfo, "remote.getKeyInfo"},
		{"MethodRemoteDeleteKey", MethodRemoteDeleteKey, "remote.deleteKey"},
		{"MethodRemoteAttestKey", MethodRemoteAttestKey, "remote.attestKey"},
		{"MethodRemoteAttestDevice", MethodRemoteAttestDevice, "remote.attestDevice"},
		// TCG-CSR-IDEVID enrollment methods
		{"MethodRemoteGetTCGCSRIDevID", MethodRemoteGetTCGCSRIDevID, "remote.getTCGCSRIDevID"},
		{"MethodRemoteActivateCredential", MethodRemoteActivateCredential, "remote.activateCredential"},
		{"MethodRemoteGetAttestationQuote", MethodRemoteGetAttestationQuote, "remote.getAttestationQuote"},
		// Key sharing methods (registered via init() in protocol_sharing.go)
		{"MethodRemoteSharePublicKey", MethodRemoteSharePublicKey, "remote.sharePublicKey"},
		{"MethodRemoteShareSymmetric", MethodRemoteShareSymmetric, "remote.shareSymmetric"},
		{"MethodRemoteImportSharedKey", MethodRemoteImportSharedKey, "remote.importSharedKey"},
		// Backup/restore methods (registered via init() in protocol_backup.go)
		{"MethodRemoteCreateBackup", MethodRemoteCreateBackup, "remote.createBackup"},
		{"MethodRemoteRestoreBackup", MethodRemoteRestoreBackup, "remote.restoreBackup"},
		{"MethodRemoteListBackups", MethodRemoteListBackups, "remote.listBackups"},
		// OATH credential sync methods (registered via init() in protocol_oath.go)
		{"MethodRemoteOATHAdd", MethodRemoteOATHAdd, "remote.oathAdd"},
		{"MethodRemoteOATHGenerate", MethodRemoteOATHGenerate, "remote.oathGenerate"},
		// PIV methods (registered via init() in protocol_piv.go)
		{"MethodRemotePIVListSlots", MethodRemotePIVListSlots, "remote.pivListSlots"},
		{"MethodRemotePIVSign", MethodRemotePIVSign, "remote.pivSign"},
		{"MethodRemotePIVGetCert", MethodRemotePIVGetCert, "remote.pivGetCert"},
		// Sync methods (registered via init() in protocol_sync.go)
		{"MethodRemoteSyncTrustStore", MethodRemoteSyncTrustStore, "remote.syncTrustStore"},
		{"MethodRemoteSyncOATH", MethodRemoteSyncOATH, "remote.syncOATH"},
		{"MethodRemoteSyncPasswords", MethodRemoteSyncPasswords, "remote.syncPasswords"},
		{"MethodRemoteSyncAll", MethodRemoteSyncAll, "remote.syncAll"},
		{"MethodRemoteSyncStatus", MethodRemoteSyncStatus, "remote.syncStatus"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	// Verify there are exactly 32 remote method constants
	// (13 original + 3 TCG-CSR-IDEVID + 3 key sharing + 3 backup/restore + 2 OATH + 3 PIV + 5 sync).
	assert.Len(t, remoteMethodNames, 32)
}

func TestIsRemoteMethod(t *testing.T) {
	t.Run("valid remote methods", func(t *testing.T) {
		validMethods := []string{
			MethodRemoteListBackends,
			MethodRemoteListKeys,
			MethodRemoteGetPublicKey,
			MethodRemoteSign,
			MethodRemoteVerify,
			MethodRemoteEncrypt,
			MethodRemoteDecrypt,
			MethodRemoteDeriveKey,
			MethodRemoteGenerateKey,
			MethodRemoteGetKeyInfo,
			MethodRemoteDeleteKey,
			MethodRemoteAttestKey,
			MethodRemoteAttestDevice,
			// TCG-CSR-IDEVID enrollment methods
			MethodRemoteGetTCGCSRIDevID,
			MethodRemoteActivateCredential,
			MethodRemoteGetAttestationQuote,
			// Key sharing methods
			MethodRemoteSharePublicKey,
			MethodRemoteShareSymmetric,
			MethodRemoteImportSharedKey,
			// Backup/restore methods
			MethodRemoteCreateBackup,
			MethodRemoteRestoreBackup,
			MethodRemoteListBackups,
			// OATH credential sync methods
			MethodRemoteOATHAdd,
			MethodRemoteOATHGenerate,
			// PIV methods
			MethodRemotePIVListSlots,
			MethodRemotePIVSign,
			MethodRemotePIVGetCert,
			// Sync methods
			MethodRemoteSyncTrustStore,
			MethodRemoteSyncOATH,
			MethodRemoteSyncPasswords,
			MethodRemoteSyncAll,
			MethodRemoteSyncStatus,
		}
		for _, method := range validMethods {
			assert.True(t, IsRemoteMethod(method), "expected IsRemoteMethod(%q) to be true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"local.sign",
			"sign",
			"nonexistent",
			"remote.",
			"remote.unknown",
			"REMOTE.sign",
			"remote.Sign",
			// TCG-CSR-IDEVID local.* variants are not remote methods
			"local.getTCGCSRIDevID",
			"local.activateCredential",
			"local.getAttestationQuote",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsRemoteMethod(method), "expected IsRemoteMethod(%q) to be false", method)
		}
	})
}

func TestBackendInfo_JSONRoundTrip(t *testing.T) {
	original := BackendInfo{
		Name:            "tpm2-backend",
		Type:            "tpm2",
		HardwareBacked:  true,
		Signing:         true,
		Decryption:      true,
		SymmetricCrypto: false,
		KeyAgreement:    true,
		Attestation:     true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded BackendInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestBackendInfo_JSONTags(t *testing.T) {
	info := BackendInfo{
		Name:            "test",
		Type:            "software",
		HardwareBacked:  false,
		Signing:         true,
		Decryption:      false,
		SymmetricCrypto: true,
		KeyAgreement:    false,
		Attestation:     false,
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"name", "type", "hardwareBacked", "signing",
		"decryption", "symmetricCrypto", "keyAgreement", "attestation",
	}
	for _, field := range expectedFields {
		_, ok := raw[field]
		assert.True(t, ok, "expected JSON field %q to be present", field)
	}
}

func TestBackendInfo_AllCapabilitiesFalse(t *testing.T) {
	original := BackendInfo{
		Name: "minimal-backend",
		Type: "software",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded BackendInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.False(t, decoded.HardwareBacked)
	assert.False(t, decoded.Signing)
	assert.False(t, decoded.Decryption)
	assert.False(t, decoded.SymmetricCrypto)
	assert.False(t, decoded.KeyAgreement)
	assert.False(t, decoded.Attestation)
}

func TestRemoteListBackendsResult_JSONRoundTrip(t *testing.T) {
	original := RemoteListBackendsResult{
		Backends: []BackendInfo{
			{
				Name:            "tpm2",
				Type:            "tpm2",
				HardwareBacked:  true,
				Signing:         true,
				Decryption:      true,
				SymmetricCrypto: false,
				KeyAgreement:    true,
				Attestation:     true,
			},
			{
				Name:            "software",
				Type:            "software",
				HardwareBacked:  false,
				Signing:         true,
				Decryption:      true,
				SymmetricCrypto: true,
				KeyAgreement:    true,
				Attestation:     false,
			},
			{
				Name:            "pkcs11",
				Type:            "pkcs11",
				HardwareBacked:  true,
				Signing:         true,
				Decryption:      false,
				SymmetricCrypto: false,
				KeyAgreement:    false,
				Attestation:     false,
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteListBackendsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Backends, 3)
	assert.Equal(t, original, decoded)
}

func TestRemoteListBackendsResult_EmptyBackends(t *testing.T) {
	original := RemoteListBackendsResult{
		Backends: []BackendInfo{},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteListBackendsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.Backends)
}

func TestRemoteListKeysParams_JSONRoundTrip(t *testing.T) {
	t.Run("with algorithm filter", func(t *testing.T) {
		original := RemoteListKeysParams{
			Backend:   "tpm2",
			Algorithm: "ECDSA-P256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteListKeysParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})

	t.Run("without algorithm filter", func(t *testing.T) {
		original := RemoteListKeysParams{
			Backend: "software",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		// Verify algorithm field is omitted when empty.
		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		_, hasAlgorithm := raw["algorithm"]
		assert.False(t, hasAlgorithm, "algorithm field should be omitted when empty")

		var decoded RemoteListKeysParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, "software", decoded.Backend)
		assert.Empty(t, decoded.Algorithm)
	})
}

func TestRemoteKeyInfo_JSONRoundTrip(t *testing.T) {
	original := RemoteKeyInfo{
		KeyID:       "key-001",
		Backend:     "tpm2",
		Algorithm:   "ECDSA-P256",
		KeySizeBits: 256,
		Label:       "signing-key",
		CreatedAt:   1706140800,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteKeyInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestRemoteKeyInfo_JSONTags(t *testing.T) {
	info := RemoteKeyInfo{
		KeyID:       "k1",
		Backend:     "sw",
		Algorithm:   "RSA",
		KeySizeBits: 2048,
		Label:       "test",
		CreatedAt:   12345,
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"keyId", "backend", "algorithm", "keySizeBits", "label", "createdAt"}
	for _, field := range expectedFields {
		_, ok := raw[field]
		assert.True(t, ok, "expected JSON field %q to be present", field)
	}
}

func TestRemoteListKeysResult_JSONRoundTrip(t *testing.T) {
	original := RemoteListKeysResult{
		Keys: []RemoteKeyInfo{
			{
				KeyID:       "key-1",
				Backend:     "tpm2",
				Algorithm:   "ECDSA-P256",
				KeySizeBits: 256,
				Label:       "auth-key",
				CreatedAt:   1706140800,
			},
			{
				KeyID:       "key-2",
				Backend:     "tpm2",
				Algorithm:   "RSA-2048",
				KeySizeBits: 2048,
				Label:       "encryption-key",
				CreatedAt:   1706141000,
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteListKeysResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Keys, 2)
	assert.Equal(t, original, decoded)
}

func TestRemoteGetPublicKeyParams_JSONRoundTrip(t *testing.T) {
	original := RemoteGetPublicKeyParams{
		Backend: "tpm2",
		KeyID:   "signing-key-001",
		Format:  "pem",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteGetPublicKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestRemoteGetPublicKeyParams_JSONTags(t *testing.T) {
	params := RemoteGetPublicKeyParams{
		Backend: "sw",
		KeyID:   "k1",
		Format:  "der",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Equal(t, "sw", raw["backend"])
	assert.Equal(t, "k1", raw["keyId"])
	assert.Equal(t, "der", raw["format"])
}

func TestRemoteGetPublicKeyResult_JSONRoundTrip(t *testing.T) {
	original := RemoteGetPublicKeyResult{
		PublicKey: []byte{0x30, 0x59, 0x30, 0x13},
		Format:    "der",
		Algorithm: "ECDSA-P256",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteGetPublicKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PublicKey, decoded.PublicKey)
	assert.Equal(t, original.Format, decoded.Format)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
}

func TestRemoteSignParams_JSONRoundTrip(t *testing.T) {
	t.Run("with algorithm", func(t *testing.T) {
		original := RemoteSignParams{
			Backend:   "tpm2",
			KeyID:     "signing-key",
			Data:      []byte("data to sign"),
			Algorithm: "SHA256withECDSA",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteSignParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})

	t.Run("without algorithm", func(t *testing.T) {
		original := RemoteSignParams{
			Backend: "software",
			KeyID:   "my-key",
			Data:    []byte("sign me"),
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		_, hasAlgorithm := raw["algorithm"]
		assert.False(t, hasAlgorithm, "algorithm field should be omitted when empty")

		var decoded RemoteSignParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})
}

func TestRemoteSignResult_JSONRoundTrip(t *testing.T) {
	original := RemoteSignResult{
		Signature: []byte{0x30, 0x44, 0x02, 0x20, 0xAB, 0xCD},
		Algorithm: "SHA256withECDSA",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteSignResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Signature, decoded.Signature)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
}

func TestRemoteVerifyParams_JSONRoundTrip(t *testing.T) {
	t.Run("with algorithm", func(t *testing.T) {
		original := RemoteVerifyParams{
			Backend:   "tpm2",
			KeyID:     "verify-key",
			Data:      []byte("original data"),
			Signature: []byte{0x30, 0x44},
			Algorithm: "SHA256withECDSA",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteVerifyParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})

	t.Run("without algorithm", func(t *testing.T) {
		original := RemoteVerifyParams{
			Backend:   "software",
			KeyID:     "key-1",
			Data:      []byte("payload"),
			Signature: []byte{0xDE, 0xAD},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		_, hasAlgorithm := raw["algorithm"]
		assert.False(t, hasAlgorithm, "algorithm field should be omitted when empty")

		var decoded RemoteVerifyParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})
}

func TestRemoteVerifyResult_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"valid signature", true},
		{"invalid signature", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := RemoteVerifyResult{Valid: tt.valid}

			data, err := json.Marshal(original)
			require.NoError(t, err)

			var decoded RemoteVerifyResult
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.valid, decoded.Valid)
		})
	}
}

func TestRemoteEncryptParams_JSONRoundTrip(t *testing.T) {
	t.Run("with AAD", func(t *testing.T) {
		original := RemoteEncryptParams{
			Backend:   "tpm2",
			KeyID:     "enc-key",
			Plaintext: []byte("secret data"),
			Algorithm: "AES-256-GCM",
			AAD:       []byte("additional authenticated data"),
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteEncryptParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})

	t.Run("without AAD", func(t *testing.T) {
		original := RemoteEncryptParams{
			Backend:   "software",
			KeyID:     "rsa-key",
			Plaintext: []byte("secret"),
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		_, hasAAD := raw["aad"]
		assert.False(t, hasAAD, "aad field should be omitted when empty")
		_, hasAlgorithm := raw["algorithm"]
		assert.False(t, hasAlgorithm, "algorithm field should be omitted when empty")

		var decoded RemoteEncryptParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})
}

func TestRemoteEncryptResult_JSONRoundTrip(t *testing.T) {
	original := RemoteEncryptResult{
		Ciphertext: []byte{0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteEncryptResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Ciphertext, decoded.Ciphertext)
}

func TestRemoteDecryptParams_JSONRoundTrip(t *testing.T) {
	t.Run("with AAD", func(t *testing.T) {
		original := RemoteDecryptParams{
			Backend:    "tpm2",
			KeyID:      "enc-key",
			Ciphertext: []byte{0xCA, 0xFE, 0xBA, 0xBE},
			Algorithm:  "AES-256-GCM",
			AAD:        []byte("aad-context"),
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteDecryptParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})

	t.Run("without AAD", func(t *testing.T) {
		original := RemoteDecryptParams{
			Backend:    "software",
			KeyID:      "rsa-key",
			Ciphertext: []byte{0xDE, 0xAD},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		_, hasAAD := raw["aad"]
		assert.False(t, hasAAD, "aad field should be omitted when empty")
		_, hasAlgorithm := raw["algorithm"]
		assert.False(t, hasAlgorithm, "algorithm field should be omitted when empty")

		var decoded RemoteDecryptParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})
}

func TestRemoteDecryptResult_JSONRoundTrip(t *testing.T) {
	original := RemoteDecryptResult{
		Plaintext: []byte("decrypted secret data"),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteDecryptResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Plaintext, decoded.Plaintext)
}

func TestRemoteDeriveKeyParams_JSONRoundTrip(t *testing.T) {
	original := RemoteDeriveKeyParams{
		Backend:       "tpm2",
		KeyID:         "ecdh-key",
		PeerPublicKey: []byte{0x04, 0x01, 0x02, 0x03, 0x04},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteDeriveKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestRemoteDeriveKeyParams_JSONTags(t *testing.T) {
	params := RemoteDeriveKeyParams{
		Backend:       "tpm2",
		KeyID:         "k1",
		PeerPublicKey: []byte{0x04},
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "backend")
	assert.Contains(t, raw, "keyId")
	assert.Contains(t, raw, "peerPublicKey")
}

func TestRemoteDeriveKeyResult_JSONRoundTrip(t *testing.T) {
	original := RemoteDeriveKeyResult{
		SharedSecret: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteDeriveKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.SharedSecret, decoded.SharedSecret)
}

func TestRemoteGenerateKeyParams_JSONRoundTrip(t *testing.T) {
	t.Run("all fields", func(t *testing.T) {
		original := RemoteGenerateKeyParams{
			Backend:     "tpm2",
			KeyID:       "new-key-001",
			Algorithm:   "ECDSA-P256",
			KeySizeBits: 256,
			Label:       "my-signing-key",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteGenerateKeyParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})

	t.Run("omitempty fields absent", func(t *testing.T) {
		original := RemoteGenerateKeyParams{
			Backend:   "software",
			KeyID:     "key-2",
			Algorithm: "RSA",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		_, hasKeySizeBits := raw["keySizeBits"]
		assert.False(t, hasKeySizeBits, "keySizeBits should be omitted when zero")
		_, hasLabel := raw["label"]
		assert.False(t, hasLabel, "label should be omitted when empty")

		var decoded RemoteGenerateKeyParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})
}

func TestRemoteGenerateKeyResult_JSONRoundTrip(t *testing.T) {
	t.Run("with public key", func(t *testing.T) {
		original := RemoteGenerateKeyResult{
			KeyID:       "generated-key-001",
			PublicKey:   []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07},
			Algorithm:   "ECDSA-P256",
			KeySizeBits: 256,
			Backend:     "tpm2",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteGenerateKeyResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})

	t.Run("without public key", func(t *testing.T) {
		original := RemoteGenerateKeyResult{
			KeyID:       "sym-key",
			Algorithm:   "AES",
			KeySizeBits: 256,
			Backend:     "software",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		_, hasPublicKey := raw["publicKey"]
		assert.False(t, hasPublicKey, "publicKey should be omitted when nil")

		var decoded RemoteGenerateKeyResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.KeyID, decoded.KeyID)
		assert.Nil(t, decoded.PublicKey)
	})
}

func TestRemoteGenerateKeyResult_JSONTags(t *testing.T) {
	result := RemoteGenerateKeyResult{
		KeyID:       "k1",
		PublicKey:   []byte{0x01},
		Algorithm:   "ECDSA",
		KeySizeBits: 256,
		Backend:     "tpm2",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"keyId", "publicKey", "algorithm", "keySizeBits", "backend"}
	for _, field := range expectedFields {
		_, ok := raw[field]
		assert.True(t, ok, "expected JSON field %q to be present", field)
	}
}

func TestRemoteGetKeyInfoParams_JSONRoundTrip(t *testing.T) {
	original := RemoteGetKeyInfoParams{
		Backend: "tpm2",
		KeyID:   "my-key",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteGetKeyInfoParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestRemoteGetKeyInfoResult_JSONRoundTrip(t *testing.T) {
	original := RemoteGetKeyInfoResult{
		RemoteKeyInfo: RemoteKeyInfo{
			KeyID:       "info-key",
			Backend:     "tpm2",
			Algorithm:   "ECDSA-P256",
			KeySizeBits: 256,
			Label:       "labeled-key",
			CreatedAt:   1706140800,
		},
		HardwareBacked: true,
		Exportable:     false,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteGetKeyInfoResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.Backend, decoded.Backend)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
	assert.Equal(t, original.KeySizeBits, decoded.KeySizeBits)
	assert.Equal(t, original.Label, decoded.Label)
	assert.Equal(t, original.CreatedAt, decoded.CreatedAt)
	assert.Equal(t, original.HardwareBacked, decoded.HardwareBacked)
	assert.Equal(t, original.Exportable, decoded.Exportable)
}

func TestRemoteGetKeyInfoResult_EmbeddedFields(t *testing.T) {
	result := RemoteGetKeyInfoResult{
		RemoteKeyInfo: RemoteKeyInfo{
			KeyID:       "embedded-key",
			Backend:     "pkcs11",
			Algorithm:   "RSA-2048",
			KeySizeBits: 2048,
			Label:       "hw-key",
			CreatedAt:   1706200000,
		},
		HardwareBacked: true,
		Exportable:     true,
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	// Embedded RemoteKeyInfo fields should be at the top level.
	expectedFields := []string{
		"keyId", "backend", "algorithm", "keySizeBits",
		"label", "createdAt", "hardwareBacked", "exportable",
	}
	for _, field := range expectedFields {
		_, ok := raw[field]
		assert.True(t, ok, "expected JSON field %q to be present at top level", field)
	}
}

func TestRemoteDeleteKeyParams_JSONRoundTrip(t *testing.T) {
	original := RemoteDeleteKeyParams{
		Backend: "software",
		KeyID:   "old-key",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteDeleteKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestRemoteDeleteKeyResult_JSONRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		deleted bool
	}{
		{"key deleted", true},
		{"key not deleted", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := RemoteDeleteKeyResult{Deleted: tt.deleted}

			data, err := json.Marshal(original)
			require.NoError(t, err)

			var decoded RemoteDeleteKeyResult
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.deleted, decoded.Deleted)
		})
	}
}

func TestRemoteAttestKeyParams_JSONRoundTrip(t *testing.T) {
	original := RemoteAttestKeyParams{
		Backend: "tpm2",
		KeyID:   "attest-key",
		Nonce:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteAttestKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original, decoded)
}

func TestRemoteAttestKeyResult_JSONRoundTrip(t *testing.T) {
	original := RemoteAttestKeyResult{
		Format: "tpm2",
		CertificateChain: [][]byte{
			{0x30, 0x82, 0x01, 0x00}, // Leaf certificate (mock DER)
			{0x30, 0x82, 0x02, 0x00}, // Intermediate CA (mock DER)
			{0x30, 0x82, 0x03, 0x00}, // Root CA (mock DER)
		},
		AttestationData: []byte{0xFF, 0x54, 0x43, 0x47, 0x80, 0x17},
		Nonce:           []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteAttestKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Format, decoded.Format)
	require.Len(t, decoded.CertificateChain, 3)
	assert.Equal(t, original.CertificateChain[0], decoded.CertificateChain[0])
	assert.Equal(t, original.CertificateChain[1], decoded.CertificateChain[1])
	assert.Equal(t, original.CertificateChain[2], decoded.CertificateChain[2])
	assert.Equal(t, original.AttestationData, decoded.AttestationData)
	assert.Equal(t, original.Nonce, decoded.Nonce)
}

func TestRemoteAttestKeyResult_JSONTags(t *testing.T) {
	result := RemoteAttestKeyResult{
		Format:           "tpm2",
		CertificateChain: [][]byte{{0x01}},
		AttestationData:  []byte{0x02},
		Nonce:            []byte{0x03},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"format", "certificateChain", "attestationData", "nonce"}
	for _, field := range expectedFields {
		_, ok := raw[field]
		assert.True(t, ok, "expected JSON field %q to be present", field)
	}
}

func TestRemoteAttestKeyResult_EmptyCertificateChain(t *testing.T) {
	original := RemoteAttestKeyResult{
		Format:           "pkcs11",
		CertificateChain: [][]byte{},
		AttestationData:  []byte{0x01},
		Nonce:            []byte{0x02},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteAttestKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Empty(t, decoded.CertificateChain)
}

func TestNewRequest_RemoteMethod(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "remote sign",
			method: MethodRemoteSign,
			params: &RemoteSignParams{
				Backend: "tpm2",
				KeyID:   "my-key",
				Data:    []byte("test data"),
			},
		},
		{
			name:   "remote list backends",
			method: MethodRemoteListBackends,
			params: nil,
		},
		{
			name:   "remote list keys",
			method: MethodRemoteListKeys,
			params: &RemoteListKeysParams{
				Backend:   "tpm2",
				Algorithm: "ECDSA-P256",
			},
		},
		{
			name:   "remote get public key",
			method: MethodRemoteGetPublicKey,
			params: &RemoteGetPublicKeyParams{
				Backend: "tpm2",
				KeyID:   "key-1",
				Format:  "pem",
			},
		},
		{
			name:   "remote verify",
			method: MethodRemoteVerify,
			params: &RemoteVerifyParams{
				Backend:   "tpm2",
				KeyID:     "key-1",
				Data:      []byte("data"),
				Signature: []byte{0x30, 0x44},
			},
		},
		{
			name:   "remote encrypt",
			method: MethodRemoteEncrypt,
			params: &RemoteEncryptParams{
				Backend:   "tpm2",
				KeyID:     "key-1",
				Plaintext: []byte("secret"),
			},
		},
		{
			name:   "remote decrypt",
			method: MethodRemoteDecrypt,
			params: &RemoteDecryptParams{
				Backend:    "tpm2",
				KeyID:      "key-1",
				Ciphertext: []byte{0xCA, 0xFE},
			},
		},
		{
			name:   "remote derive key",
			method: MethodRemoteDeriveKey,
			params: &RemoteDeriveKeyParams{
				Backend:       "tpm2",
				KeyID:         "ecdh-key",
				PeerPublicKey: []byte{0x04, 0x01},
			},
		},
		{
			name:   "remote generate key",
			method: MethodRemoteGenerateKey,
			params: &RemoteGenerateKeyParams{
				Backend:   "tpm2",
				KeyID:     "new-key",
				Algorithm: "ECDSA-P256",
			},
		},
		{
			name:   "remote get key info",
			method: MethodRemoteGetKeyInfo,
			params: &RemoteGetKeyInfoParams{
				Backend: "tpm2",
				KeyID:   "key-1",
			},
		},
		{
			name:   "remote delete key",
			method: MethodRemoteDeleteKey,
			params: &RemoteDeleteKeyParams{
				Backend: "tpm2",
				KeyID:   "old-key",
			},
		},
		{
			name:   "remote attest key",
			method: MethodRemoteAttestKey,
			params: &RemoteAttestKeyParams{
				Backend: "tpm2",
				KeyID:   "attest-key",
				Nonce:   []byte{0x01, 0x02, 0x03, 0x04},
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

			if tt.params != nil {
				assert.Equal(t, tt.params, req.Params)
			} else {
				assert.Nil(t, req.Params)
			}

			// Verify the request can be encoded to JSON.
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

func TestNewRequest_RemoteMethodUniqueIDs(t *testing.T) {
	req1 := NewRequest(MethodRemoteSign, nil)
	req2 := NewRequest(MethodRemoteEncrypt, nil)
	req3 := NewRequest(MethodRemoteDecrypt, nil)

	assert.NotEqual(t, req1.ID, req2.ID)
	assert.NotEqual(t, req2.ID, req3.ID)
	assert.NotEqual(t, req1.ID, req3.ID)
}

func TestDecodeResult_RemoteListBackendsResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      100,
		Result: json.RawMessage(`{
			"backends": [
				{
					"name": "tpm2",
					"type": "tpm2",
					"hardwareBacked": true,
					"signing": true,
					"decryption": true,
					"symmetricCrypto": false,
					"keyAgreement": true,
					"attestation": true
				}
			]
		}`),
	}

	result, err := DecodeResult[RemoteListBackendsResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Backends, 1)
	assert.Equal(t, "tpm2", result.Backends[0].Name)
	assert.True(t, result.Backends[0].HardwareBacked)
	assert.True(t, result.Backends[0].Attestation)
}

func TestDecodeResult_RemoteSignResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      101,
		Result:  json.RawMessage(`{"signature":"AQIDBA==","algorithm":"SHA256withECDSA"}`),
	}

	result, err := DecodeResult[RemoteSignResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, result.Signature)
	assert.Equal(t, "SHA256withECDSA", result.Algorithm)
}

func TestDecodeResult_RemoteVerifyResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      102,
		Result:  json.RawMessage(`{"valid":true}`),
	}

	result, err := DecodeResult[RemoteVerifyResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
}

func TestDecodeResult_RemoteEncryptResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      103,
		Result:  json.RawMessage(`{"ciphertext":"yv66vg=="}`),
	}

	result, err := DecodeResult[RemoteEncryptResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []byte{0xCA, 0xFE, 0xBA, 0xBE}, result.Ciphertext)
}

func TestDecodeResult_RemoteDecryptResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      104,
		Result:  json.RawMessage(`{"plaintext":"c2VjcmV0"}`),
	}

	result, err := DecodeResult[RemoteDecryptResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []byte("secret"), result.Plaintext)
}

func TestDecodeResult_RemoteDeriveKeyResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      105,
		Result:  json.RawMessage(`{"sharedSecret":"q83v"}`),
	}

	result, err := DecodeResult[RemoteDeriveKeyResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.SharedSecret)
}

func TestDecodeResult_RemoteGenerateKeyResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      106,
		Result: json.RawMessage(`{
			"keyId": "new-key",
			"publicKey": "AQID",
			"algorithm": "ECDSA-P256",
			"keySizeBits": 256,
			"backend": "tpm2"
		}`),
	}

	result, err := DecodeResult[RemoteGenerateKeyResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "new-key", result.KeyID)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, result.PublicKey)
	assert.Equal(t, "ECDSA-P256", result.Algorithm)
	assert.Equal(t, 256, result.KeySizeBits)
	assert.Equal(t, "tpm2", result.Backend)
}

func TestDecodeResult_RemoteGetKeyInfoResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      107,
		Result: json.RawMessage(`{
			"keyId": "info-key",
			"backend": "tpm2",
			"algorithm": "ECDSA-P256",
			"keySizeBits": 256,
			"label": "my-key",
			"createdAt": 1706140800,
			"hardwareBacked": true,
			"exportable": false
		}`),
	}

	result, err := DecodeResult[RemoteGetKeyInfoResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "info-key", result.KeyID)
	assert.Equal(t, "tpm2", result.Backend)
	assert.Equal(t, "ECDSA-P256", result.Algorithm)
	assert.Equal(t, 256, result.KeySizeBits)
	assert.Equal(t, "my-key", result.Label)
	assert.Equal(t, int64(1706140800), result.CreatedAt)
	assert.True(t, result.HardwareBacked)
	assert.False(t, result.Exportable)
}

func TestDecodeResult_RemoteDeleteKeyResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      108,
		Result:  json.RawMessage(`{"deleted":true}`),
	}

	result, err := DecodeResult[RemoteDeleteKeyResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Deleted)
}

func TestDecodeResult_RemoteAttestKeyResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      109,
		Result: json.RawMessage(`{
			"format": "tpm2",
			"certificateChain": ["AQID", "BAUG"],
			"attestationData": "AQIDBA==",
			"nonce": "BQY="
		}`),
	}

	result, err := DecodeResult[RemoteAttestKeyResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "tpm2", result.Format)
	require.Len(t, result.CertificateChain, 2)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, result.CertificateChain[0])
	assert.Equal(t, []byte{0x04, 0x05, 0x06}, result.CertificateChain[1])
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, result.AttestationData)
	assert.Equal(t, []byte{0x05, 0x06}, result.Nonce)
}

func TestDecodeResult_RemoteResultWithRPCError(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      110,
		Error: &RPCError{
			Code:    ErrorCodeBackendDenied,
			Message: "backend denied access",
		},
	}

	result, err := DecodeResult[RemoteSignResult](resp)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "backend denied access", err.Error())
}

func TestDecodeResult_RemoteResultInvalidJSON(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      111,
		Result:  json.RawMessage(`{invalid`),
	}

	result, err := DecodeResult[RemoteSignResult](resp)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestDecodeResult_RemoteListKeysResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      112,
		Result: json.RawMessage(`{
			"keys": [
				{
					"keyId": "k1",
					"backend": "tpm2",
					"algorithm": "ECDSA-P256",
					"keySizeBits": 256,
					"label": "key-one",
					"createdAt": 1706140800
				},
				{
					"keyId": "k2",
					"backend": "tpm2",
					"algorithm": "RSA-2048",
					"keySizeBits": 2048,
					"label": "key-two",
					"createdAt": 1706141000
				}
			]
		}`),
	}

	result, err := DecodeResult[RemoteListKeysResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Keys, 2)
	assert.Equal(t, "k1", result.Keys[0].KeyID)
	assert.Equal(t, "k2", result.Keys[1].KeyID)
	assert.Equal(t, 2048, result.Keys[1].KeySizeBits)
}

func TestDecodeResult_RemoteGetPublicKeyResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      113,
		Result:  json.RawMessage(`{"publicKey":"MFYW","format":"der","algorithm":"ECDSA-P256"}`),
	}

	result, err := DecodeResult[RemoteGetPublicKeyResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.PublicKey)
	assert.Equal(t, "der", result.Format)
	assert.Equal(t, "ECDSA-P256", result.Algorithm)
}

func TestRemoteParamsTypes_JSONFieldConsistency(t *testing.T) {
	// Verify that all param types with backend+keyId use consistent field names.
	tests := []struct {
		name   string
		params interface{}
	}{
		{"RemoteGetPublicKeyParams", RemoteGetPublicKeyParams{Backend: "b", KeyID: "k", Format: "pem"}},
		{"RemoteSignParams", RemoteSignParams{Backend: "b", KeyID: "k", Data: []byte{0x01}}},
		{"RemoteVerifyParams", RemoteVerifyParams{Backend: "b", KeyID: "k", Data: []byte{0x01}, Signature: []byte{0x02}}},
		{"RemoteEncryptParams", RemoteEncryptParams{Backend: "b", KeyID: "k", Plaintext: []byte{0x01}}},
		{"RemoteDecryptParams", RemoteDecryptParams{Backend: "b", KeyID: "k", Ciphertext: []byte{0x01}}},
		{"RemoteDeriveKeyParams", RemoteDeriveKeyParams{Backend: "b", KeyID: "k", PeerPublicKey: []byte{0x01}}},
		{"RemoteGenerateKeyParams", RemoteGenerateKeyParams{Backend: "b", KeyID: "k", Algorithm: "RSA"}},
		{"RemoteGetKeyInfoParams", RemoteGetKeyInfoParams{Backend: "b", KeyID: "k"}},
		{"RemoteDeleteKeyParams", RemoteDeleteKeyParams{Backend: "b", KeyID: "k"}},
		{"RemoteAttestKeyParams", RemoteAttestKeyParams{Backend: "b", KeyID: "k", Nonce: []byte{0x01}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.params)
			require.NoError(t, err)

			var raw map[string]interface{}
			err = json.Unmarshal(data, &raw)
			require.NoError(t, err)

			assert.Equal(t, "b", raw["backend"], "backend field mismatch")
			assert.Equal(t, "k", raw["keyId"], "keyId field mismatch")
		})
	}
}

func TestRemoteListKeysParams_JSONTags(t *testing.T) {
	params := RemoteListKeysParams{
		Backend:   "tpm2",
		Algorithm: "ECDSA-P256",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Equal(t, "tpm2", raw["backend"])
	assert.Equal(t, "ECDSA-P256", raw["algorithm"])
}

// --- TCG-CSR-IDEVID Enrollment Protocol Tests ---

func TestRemoteGetTCGCSRIDevIDParams_JSONRoundTrip(t *testing.T) {
	t.Run("with backend specified", func(t *testing.T) {
		original := RemoteGetTCGCSRIDevIDParams{
			Backend: "tpm2",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteGetTCGCSRIDevIDParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})

	t.Run("without backend (omitempty)", func(t *testing.T) {
		original := RemoteGetTCGCSRIDevIDParams{}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		// Verify backend field is omitted when empty.
		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		_, hasBackend := raw["backend"]
		assert.False(t, hasBackend, "backend field should be omitted when empty")

		var decoded RemoteGetTCGCSRIDevIDParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})
}

func TestRemoteGetTCGCSRIDevIDResult_JSONRoundTrip(t *testing.T) {
	t.Run("complete result with all fields", func(t *testing.T) {
		original := RemoteGetTCGCSRIDevIDResult{
			CSR:                  []byte{0x30, 0x82, 0x01, 0x00}, // Mock TCG-CSR-IDEVID
			EKCert:               []byte{0x30, 0x82, 0x02, 0x00}, // Mock EK certificate
			IAKPublicKey:         []byte{0x00, 0x23, 0x00, 0x0B}, // Mock IAK TPM2B_PUBLIC
			IDevIDPublicKey:      []byte{0x00, 0x23, 0x00, 0x0B}, // Mock IDevID TPM2B_PUBLIC
			PlatformManufacturer: "Dell Inc.",
			PlatformModel:        "XPS 15 9520",
			PlatformSerial:       "ABCD1234567",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteGetTCGCSRIDevIDResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.CSR, decoded.CSR)
		assert.Equal(t, original.EKCert, decoded.EKCert)
		assert.Equal(t, original.IAKPublicKey, decoded.IAKPublicKey)
		assert.Equal(t, original.IDevIDPublicKey, decoded.IDevIDPublicKey)
		assert.Equal(t, original.PlatformManufacturer, decoded.PlatformManufacturer)
		assert.Equal(t, original.PlatformModel, decoded.PlatformModel)
		assert.Equal(t, original.PlatformSerial, decoded.PlatformSerial)
	})

	t.Run("without EK certificate (omitempty)", func(t *testing.T) {
		original := RemoteGetTCGCSRIDevIDResult{
			CSR:             []byte{0x30, 0x82, 0x01, 0x00},
			IAKPublicKey:    []byte{0x00, 0x23, 0x00, 0x0B},
			IDevIDPublicKey: []byte{0x00, 0x23, 0x00, 0x0B},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		// Verify optional fields are omitted when empty.
		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		_, hasEKCert := raw["ekCert"]
		assert.False(t, hasEKCert, "ekCert field should be omitted when empty")

		var decoded RemoteGetTCGCSRIDevIDResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.CSR, decoded.CSR)
		assert.Nil(t, decoded.EKCert)
	})
}

func TestRemoteGetTCGCSRIDevIDResult_JSONTags(t *testing.T) {
	result := RemoteGetTCGCSRIDevIDResult{
		CSR:                  []byte{0x01},
		EKCert:               []byte{0x02},
		IAKPublicKey:         []byte{0x03},
		IDevIDPublicKey:      []byte{0x04},
		PlatformManufacturer: "Test",
		PlatformModel:        "Model",
		PlatformSerial:       "Serial",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"csr", "ekCert", "iakPublicKey", "idevidPublicKey",
		"platformManufacturer", "platformModel", "platformSerial",
	}
	for _, field := range expectedFields {
		_, ok := raw[field]
		assert.True(t, ok, "expected JSON field %q to be present", field)
	}
}

func TestRemoteActivateCredentialParams_JSONRoundTrip(t *testing.T) {
	t.Run("with backend specified", func(t *testing.T) {
		original := RemoteActivateCredentialParams{
			Backend:         "tpm2",
			CredentialBlob:  []byte{0x00, 0x20, 0xAB, 0xCD}, // Mock TPM2B_ID_OBJECT
			EncryptedSecret: []byte{0x00, 0x80, 0xEF, 0x01}, // Mock TPM2B_ENCRYPTED_SECRET
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteActivateCredentialParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})

	t.Run("without backend (omitempty)", func(t *testing.T) {
		original := RemoteActivateCredentialParams{
			CredentialBlob:  []byte{0x00, 0x20, 0xAB, 0xCD},
			EncryptedSecret: []byte{0x00, 0x80, 0xEF, 0x01},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		// Verify backend field is omitted when empty.
		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		_, hasBackend := raw["backend"]
		assert.False(t, hasBackend, "backend field should be omitted when empty")

		var decoded RemoteActivateCredentialParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.CredentialBlob, decoded.CredentialBlob)
		assert.Equal(t, original.EncryptedSecret, decoded.EncryptedSecret)
		assert.Empty(t, decoded.Backend)
	})
}

func TestRemoteActivateCredentialParams_JSONTags(t *testing.T) {
	params := RemoteActivateCredentialParams{
		Backend:         "tpm2",
		CredentialBlob:  []byte{0x01},
		EncryptedSecret: []byte{0x02},
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Equal(t, "tpm2", raw["backend"])
	assert.Contains(t, raw, "credentialBlob")
	assert.Contains(t, raw, "encryptedSecret")
}

func TestRemoteActivateCredentialResult_JSONRoundTrip(t *testing.T) {
	original := RemoteActivateCredentialResult{
		DecryptedSecret: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RemoteActivateCredentialResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.DecryptedSecret, decoded.DecryptedSecret)
}

func TestRemoteActivateCredentialResult_JSONTags(t *testing.T) {
	result := RemoteActivateCredentialResult{
		DecryptedSecret: []byte{0x01, 0x02, 0x03},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, ok := raw["decryptedSecret"]
	assert.True(t, ok, "expected JSON field 'decryptedSecret' to be present")
}

func TestRemoteGetAttestationQuoteParams_JSONRoundTrip(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		original := RemoteGetAttestationQuoteParams{
			Backend:    "tpm2",
			Nonce:      []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			PCRIndices: []int{0, 1, 2, 3, 4, 5, 6, 7},
			PCRBank:    "sha256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteGetAttestationQuoteParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original, decoded)
	})

	t.Run("without optional fields (omitempty)", func(t *testing.T) {
		original := RemoteGetAttestationQuoteParams{
			Nonce:      []byte{0x01, 0x02, 0x03, 0x04},
			PCRIndices: []int{0, 1, 2},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		// Verify optional fields are omitted when empty.
		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		_, hasBackend := raw["backend"]
		assert.False(t, hasBackend, "backend field should be omitted when empty")
		_, hasPCRBank := raw["pcrBank"]
		assert.False(t, hasPCRBank, "pcrBank field should be omitted when empty")

		var decoded RemoteGetAttestationQuoteParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Nonce, decoded.Nonce)
		assert.Equal(t, original.PCRIndices, decoded.PCRIndices)
		assert.Empty(t, decoded.Backend)
		assert.Empty(t, decoded.PCRBank)
	})
}

func TestRemoteGetAttestationQuoteParams_JSONTags(t *testing.T) {
	params := RemoteGetAttestationQuoteParams{
		Backend:    "tpm2",
		Nonce:      []byte{0x01},
		PCRIndices: []int{0, 7, 14},
		PCRBank:    "sha256",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "backend")
	assert.Contains(t, raw, "nonce")
	assert.Contains(t, raw, "pcrIndices")
	assert.Contains(t, raw, "pcrBank")
}

func TestRemoteGetAttestationQuoteResult_JSONRoundTrip(t *testing.T) {
	t.Run("complete result", func(t *testing.T) {
		original := RemoteGetAttestationQuoteResult{
			Quoted:    []byte{0xFF, 0x54, 0x43, 0x47, 0x80, 0x18}, // Mock TPMS_ATTEST
			Signature: []byte{0x30, 0x44, 0x02, 0x20, 0xAB, 0xCD}, // Mock ECDSA signature
			PCRValues: map[int][]byte{
				0: {0x01, 0x02, 0x03, 0x04},
				1: {0x05, 0x06, 0x07, 0x08},
				7: {0x09, 0x0A, 0x0B, 0x0C},
			},
			PCRBank: "sha256",
			Nonce:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteGetAttestationQuoteResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Quoted, decoded.Quoted)
		assert.Equal(t, original.Signature, decoded.Signature)
		assert.Equal(t, original.PCRBank, decoded.PCRBank)
		assert.Equal(t, original.Nonce, decoded.Nonce)
		require.Len(t, decoded.PCRValues, 3)
		assert.Equal(t, original.PCRValues[0], decoded.PCRValues[0])
		assert.Equal(t, original.PCRValues[1], decoded.PCRValues[1])
		assert.Equal(t, original.PCRValues[7], decoded.PCRValues[7])
	})

	t.Run("empty PCR values", func(t *testing.T) {
		original := RemoteGetAttestationQuoteResult{
			Quoted:    []byte{0xFF},
			Signature: []byte{0x30},
			PCRValues: map[int][]byte{},
			PCRBank:   "sha256",
			Nonce:     []byte{0x01},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded RemoteGetAttestationQuoteResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.PCRValues)
	})
}

func TestRemoteGetAttestationQuoteResult_JSONTags(t *testing.T) {
	result := RemoteGetAttestationQuoteResult{
		Quoted:    []byte{0x01},
		Signature: []byte{0x02},
		PCRValues: map[int][]byte{0: {0x03}},
		PCRBank:   "sha256",
		Nonce:     []byte{0x04},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"quoted", "signature", "pcrValues", "pcrBank", "nonce"}
	for _, field := range expectedFields {
		_, ok := raw[field]
		assert.True(t, ok, "expected JSON field %q to be present", field)
	}
}

func TestDecodeResult_RemoteGetTCGCSRIDevIDResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      200,
		Result: json.RawMessage(`{
			"csr": "AQID",
			"ekCert": "BAUG",
			"iakPublicKey": "BwgJ",
			"idevidPublicKey": "CgsM",
			"platformManufacturer": "Test Manufacturer",
			"platformModel": "Test Model",
			"platformSerial": "SERIAL123"
		}`),
	}

	result, err := DecodeResult[RemoteGetTCGCSRIDevIDResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, result.CSR)
	assert.Equal(t, []byte{0x04, 0x05, 0x06}, result.EKCert)
	assert.Equal(t, []byte{0x07, 0x08, 0x09}, result.IAKPublicKey)
	assert.Equal(t, []byte{0x0A, 0x0B, 0x0C}, result.IDevIDPublicKey)
	assert.Equal(t, "Test Manufacturer", result.PlatformManufacturer)
	assert.Equal(t, "Test Model", result.PlatformModel)
	assert.Equal(t, "SERIAL123", result.PlatformSerial)
}

func TestDecodeResult_RemoteActivateCredentialResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      201,
		Result:  json.RawMessage(`{"decryptedSecret":"3q2+78r+ur4="}`),
	}

	result, err := DecodeResult[RemoteActivateCredentialResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}, result.DecryptedSecret)
}

func TestDecodeResult_RemoteGetAttestationQuoteResult(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      202,
		Result: json.RawMessage(`{
			"quoted": "AQID",
			"signature": "BAUG",
			"pcrValues": {"0": "BwgJ", "7": "CgsM"},
			"pcrBank": "sha256",
			"nonce": "DQ4P"
		}`),
	}

	result, err := DecodeResult[RemoteGetAttestationQuoteResult](resp)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, result.Quoted)
	assert.Equal(t, []byte{0x04, 0x05, 0x06}, result.Signature)
	assert.Equal(t, "sha256", result.PCRBank)
	assert.Equal(t, []byte{0x0D, 0x0E, 0x0F}, result.Nonce)
	require.Len(t, result.PCRValues, 2)
	assert.Equal(t, []byte{0x07, 0x08, 0x09}, result.PCRValues[0])
	assert.Equal(t, []byte{0x0A, 0x0B, 0x0C}, result.PCRValues[7])
}

func TestNewRequest_TCGCSRIDevIDEnrollmentMethods(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "remote getTCGCSRIDevID",
			method: MethodRemoteGetTCGCSRIDevID,
			params: &RemoteGetTCGCSRIDevIDParams{
				Backend: "tpm2",
			},
		},
		{
			name:   "remote activateCredential",
			method: MethodRemoteActivateCredential,
			params: &RemoteActivateCredentialParams{
				Backend:         "tpm2",
				CredentialBlob:  []byte{0x01, 0x02},
				EncryptedSecret: []byte{0x03, 0x04},
			},
		},
		{
			name:   "remote getAttestationQuote",
			method: MethodRemoteGetAttestationQuote,
			params: &RemoteGetAttestationQuoteParams{
				Backend:    "tpm2",
				Nonce:      []byte{0x01, 0x02, 0x03, 0x04},
				PCRIndices: []int{0, 1, 2, 7},
				PCRBank:    "sha256",
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

			if tt.params != nil {
				assert.Equal(t, tt.params, req.Params)
			}

			// Verify the request can be encoded to JSON.
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

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

func TestLocalMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"MethodLocalGenerateKey", MethodLocalGenerateKey, "local.generateKey"},
		{"MethodLocalSign", MethodLocalSign, "local.sign"},
		{"MethodLocalDecrypt", MethodLocalDecrypt, "local.decrypt"},
		{"MethodLocalSymmetricEncrypt", MethodLocalSymmetricEncrypt, "local.symmetricEncrypt"},
		{"MethodLocalSymmetricDecrypt", MethodLocalSymmetricDecrypt, "local.symmetricDecrypt"},
		{"MethodLocalHMAC", MethodLocalHMAC, "local.hmac"},
		{"MethodLocalECDH", MethodLocalECDH, "local.ecdh"},
		{"MethodLocalGetPublicKey", MethodLocalGetPublicKey, "local.getPublicKey"},
		{"MethodLocalListKeys", MethodLocalListKeys, "local.listKeys"},
		{"MethodLocalGetKeyInfo", MethodLocalGetKeyInfo, "local.getKeyInfo"},
		{"MethodLocalDeleteKey", MethodLocalDeleteKey, "local.deleteKey"},
		{"MethodLocalSetKeyPolicy", MethodLocalSetKeyPolicy, "local.setKeyPolicy"},
		{"MethodLocalAttestKey", MethodLocalAttestKey, "local.attestKey"},
		{"MethodLocalGetCapabilities", MethodLocalGetCapabilities, "local.getCapabilities"},
		{"MethodLocalListFido2Credentials", MethodLocalListFido2Credentials, "local.listFido2Credentials"},
		{"MethodLocalSignFido2Assertion", MethodLocalSignFido2Assertion, "local.signFido2Assertion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	// Verify the total count of local methods is exactly 16
	assert.Equal(t, 16, len(tests), "expected exactly 16 local method constants")
}

func TestPhoneMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"MethodPhoneRequestChallenge", MethodPhoneRequestChallenge, "phone.requestChallenge"},
		{"MethodPhoneSubmitAttestation", MethodPhoneSubmitAttestation, "phone.submitAttestation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	// Verify the total count of phone methods
	assert.Equal(t, 2, len(tests), "expected exactly 2 phone method constants")
}

func TestIsLocalMethod(t *testing.T) {
	t.Run("valid methods", func(t *testing.T) {
		validMethods := []string{
			MethodLocalGenerateKey,
			MethodLocalSign,
			MethodLocalDecrypt,
			MethodLocalSymmetricEncrypt,
			MethodLocalSymmetricDecrypt,
			MethodLocalHMAC,
			MethodLocalECDH,
			MethodLocalGetPublicKey,
			MethodLocalListKeys,
			MethodLocalGetKeyInfo,
			MethodLocalDeleteKey,
			MethodLocalSetKeyPolicy,
			MethodLocalAttestKey,
			MethodLocalGetCapabilities,
			MethodLocalListFido2Credentials,
			MethodLocalSignFido2Assertion,
		}
		for _, method := range validMethods {
			assert.True(t, IsLocalMethod(method), "expected IsLocalMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"remote.sign",
			"generateKey",
			"nonexistent",
			"local.",
			"local",
			"LOCAL.generateKey",
			"local.GenerateKey",
			"phone.requestChallenge", // phone.* methods are not local methods
			"phone.submitAttestation",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsLocalMethod(method), "expected IsLocalMethod(%q) to return false", method)
		}
	})
}

func TestIsPhoneMethod(t *testing.T) {
	t.Run("valid methods", func(t *testing.T) {
		validMethods := []string{
			MethodPhoneRequestChallenge,
			MethodPhoneSubmitAttestation,
		}
		for _, method := range validMethods {
			assert.True(t, IsPhoneMethod(method), "expected IsPhoneMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"phone.",
			"phone",
			"PHONE.requestChallenge",
			"phone.RequestChallenge",
			"local.generateKey", // local.* methods are not phone methods
			"local.sign",
			"remote.submitAttestation",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsPhoneMethod(method), "expected IsPhoneMethod(%q) to return false", method)
		}
	})
}

func TestPhoneRequestChallengeResult_JSONRoundTrip(t *testing.T) {
	original := &PhoneRequestChallengeResult{
		Nonce:         []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20},
		ChallengeID:   "abc123def456",
		ExpiresInSecs: 300,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PhoneRequestChallengeResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.ChallengeID, decoded.ChallengeID)
	assert.Equal(t, original.ExpiresInSecs, decoded.ExpiresInSecs)
}

func TestPhoneRequestChallengeResult_JSONFieldNames(t *testing.T) {
	result := PhoneRequestChallengeResult{
		Nonce:         []byte{0x01, 0x02},
		ChallengeID:   "test-id",
		ExpiresInSecs: 600,
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "nonce")
	assert.Contains(t, raw, "challengeId")
	assert.Contains(t, raw, "expiresInSecs")
}

func TestPhoneSubmitAttestationParams_JSONRoundTrip(t *testing.T) {
	original := &PhoneSubmitAttestationParams{
		ChallengeID:      "challenge-abc123",
		Nonce:            []byte{0x01, 0x02, 0x03, 0x04},
		Format:           "android-keystore",
		CertificateChain: [][]byte{{0x30, 0x82}, {0x30, 0x83}, {0x30, 0x84}},
		SecurityLevel:    "strongbox",
		BootState:        0,
		DeviceLocked:     true,
		VerifiedBootKey:  []byte{0xAA, 0xBB, 0xCC},
		VerifiedBootHash: []byte{0xDD, 0xEE, 0xFF},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PhoneSubmitAttestationParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ChallengeID, decoded.ChallengeID)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.Format, decoded.Format)
	assert.Equal(t, original.CertificateChain, decoded.CertificateChain)
	assert.Equal(t, original.SecurityLevel, decoded.SecurityLevel)
	assert.Equal(t, original.BootState, decoded.BootState)
	assert.Equal(t, original.DeviceLocked, decoded.DeviceLocked)
	assert.Equal(t, original.VerifiedBootKey, decoded.VerifiedBootKey)
	assert.Equal(t, original.VerifiedBootHash, decoded.VerifiedBootHash)
}

func TestPhoneSubmitAttestationParams_JSONFieldNames(t *testing.T) {
	params := PhoneSubmitAttestationParams{
		ChallengeID:      "id",
		Nonce:            []byte{0x01},
		Format:           "android-keystore",
		CertificateChain: [][]byte{{0x01}},
		SecurityLevel:    "tee",
		BootState:        0,
		DeviceLocked:     true,
		VerifiedBootKey:  []byte{0x02},
		VerifiedBootHash: []byte{0x03},
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"challengeId", "nonce", "format", "certificateChain",
		"securityLevel", "bootState", "deviceLocked",
		"verifiedBootKey", "verifiedBootHash",
	}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

func TestPhoneSubmitAttestationResult_JSONRoundTrip(t *testing.T) {
	t.Run("verified with message and fingerprint", func(t *testing.T) {
		original := &PhoneSubmitAttestationResult{
			Verified:          true,
			Message:           "Attestation verified successfully",
			DeviceFingerprint: "a1b2c3d4e5f6...",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded PhoneSubmitAttestationResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Verified, decoded.Verified)
		assert.Equal(t, original.Message, decoded.Message)
		assert.Equal(t, original.DeviceFingerprint, decoded.DeviceFingerprint)
	})

	t.Run("not verified without optional fields", func(t *testing.T) {
		original := &PhoneSubmitAttestationResult{
			Verified: false,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded PhoneSubmitAttestationResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.False(t, decoded.Verified)
		assert.Empty(t, decoded.Message)
		assert.Empty(t, decoded.DeviceFingerprint)
	})
}

func TestPhoneSubmitAttestationResult_JSONFieldNames(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		result := PhoneSubmitAttestationResult{
			Verified:          true,
			Message:           "test",
			DeviceFingerprint: "fingerprint",
		}

		data, err := json.Marshal(result)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "verified")
		assert.Contains(t, raw, "message")
		assert.Contains(t, raw, "deviceFingerprint")
	})

	t.Run("omitempty fields excluded", func(t *testing.T) {
		result := PhoneSubmitAttestationResult{
			Verified: true,
		}

		data, err := json.Marshal(result)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "verified")
		assert.NotContains(t, raw, "message")
		assert.NotContains(t, raw, "deviceFingerprint")
	})
}

func TestPhoneAttestationTypes_ZeroValues(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
	}{
		{"PhoneRequestChallengeResult", &PhoneRequestChallengeResult{}},
		{"PhoneSubmitAttestationParams", &PhoneSubmitAttestationParams{}},
		{"PhoneSubmitAttestationResult", &PhoneSubmitAttestationResult{}},
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

func TestPhoneSubmitAttestationParams_BootStates(t *testing.T) {
	bootStates := []struct {
		name  string
		state int
	}{
		{"VERIFIED", 0},
		{"SELF_SIGNED", 1},
		{"UNVERIFIED", 2},
		{"FAILED", 3},
	}

	for _, bs := range bootStates {
		t.Run(bs.name, func(t *testing.T) {
			params := PhoneSubmitAttestationParams{
				ChallengeID: "test",
				BootState:   bs.state,
			}

			data, err := json.Marshal(params)
			require.NoError(t, err)

			var decoded PhoneSubmitAttestationParams
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, bs.state, decoded.BootState)
		})
	}
}

func TestLocalGenerateKeyParams_JSONRoundTrip(t *testing.T) {
	original := &LocalGenerateKeyParams{
		KeyID:                    "test-key-1",
		Algorithm:                "ES256",
		KeySizeBits:              256,
		StrongBoxBacked:          true,
		BiometricRequired:        true,
		AuthDurationSeconds:      30,
		UserVerificationRequired: true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalGenerateKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
	assert.Equal(t, original.KeySizeBits, decoded.KeySizeBits)
	assert.Equal(t, original.StrongBoxBacked, decoded.StrongBoxBacked)
	assert.Equal(t, original.BiometricRequired, decoded.BiometricRequired)
	assert.Equal(t, original.AuthDurationSeconds, decoded.AuthDurationSeconds)
	assert.Equal(t, original.UserVerificationRequired, decoded.UserVerificationRequired)
}

func TestLocalGenerateKeyResult_JSONRoundTrip(t *testing.T) {
	original := &LocalGenerateKeyResult{
		KeyID:         "test-key-1",
		PublicKeyDER:  []byte{0x30, 0x59, 0x30, 0x13},
		PublicKeyCOSE: []byte{0xa5, 0x01, 0x02},
		Algorithm:     "ES256",
		KeySizeBits:   256,
		SecurityLevel: "strongbox",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalGenerateKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.PublicKeyDER, decoded.PublicKeyDER)
	assert.Equal(t, original.PublicKeyCOSE, decoded.PublicKeyCOSE)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
	assert.Equal(t, original.KeySizeBits, decoded.KeySizeBits)
	assert.Equal(t, original.SecurityLevel, decoded.SecurityLevel)
}

func TestLocalSignParams_JSONRoundTrip(t *testing.T) {
	original := &LocalSignParams{
		KeyID:                    "signing-key-1",
		Data:                     []byte("data to sign"),
		Algorithm:                "ES256",
		UserVerificationRequired: true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSignParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.Data, decoded.Data)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
	assert.Equal(t, original.UserVerificationRequired, decoded.UserVerificationRequired)
}

func TestLocalSignResult_JSONRoundTrip(t *testing.T) {
	original := &LocalSignResult{
		Signature: []byte{0x30, 0x44, 0x02, 0x20},
		Algorithm: "ES256",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSignResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Signature, decoded.Signature)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
}

func TestLocalDecryptParams_JSONRoundTrip(t *testing.T) {
	original := &LocalDecryptParams{
		KeyID:      "rsa-key-1",
		Ciphertext: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		Algorithm:  "RSA-OAEP-SHA256",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalDecryptParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.Ciphertext, decoded.Ciphertext)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
}

func TestLocalDecryptResult_JSONRoundTrip(t *testing.T) {
	original := &LocalDecryptResult{
		Plaintext: []byte("decrypted secret data"),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalDecryptResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Plaintext, decoded.Plaintext)
}

func TestLocalSymmetricEncryptParams_JSONRoundTrip(t *testing.T) {
	original := &LocalSymmetricEncryptParams{
		KeyID:     "aes-key-1",
		Plaintext: []byte("secret message"),
		AAD:       []byte("additional data"),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSymmetricEncryptParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.Plaintext, decoded.Plaintext)
	assert.Equal(t, original.AAD, decoded.AAD)
}

func TestLocalSymmetricEncryptResult_JSONRoundTrip(t *testing.T) {
	original := &LocalSymmetricEncryptResult{
		Ciphertext: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSymmetricEncryptResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Ciphertext, decoded.Ciphertext)
}

func TestLocalSymmetricDecryptParams_JSONRoundTrip(t *testing.T) {
	original := &LocalSymmetricDecryptParams{
		KeyID:      "aes-key-1",
		Ciphertext: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		AAD:        []byte("additional data"),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSymmetricDecryptParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.Ciphertext, decoded.Ciphertext)
	assert.Equal(t, original.AAD, decoded.AAD)
}

func TestLocalSymmetricDecryptResult_JSONRoundTrip(t *testing.T) {
	original := &LocalSymmetricDecryptResult{
		Plaintext: []byte("decrypted message"),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSymmetricDecryptResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Plaintext, decoded.Plaintext)
}

func TestLocalHMACParams_JSONRoundTrip(t *testing.T) {
	original := &LocalHMACParams{
		KeyID: "hmac-key-1",
		Data:  []byte("data to authenticate"),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalHMACParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.Data, decoded.Data)
}

func TestLocalHMACResult_JSONRoundTrip(t *testing.T) {
	original := &LocalHMACResult{
		MAC: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalHMACResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.MAC, decoded.MAC)
}

func TestLocalECDHParams_JSONRoundTrip(t *testing.T) {
	original := &LocalECDHParams{
		KeyID:         "ecdh-key-1",
		PeerPublicKey: []byte{0x04, 0x01, 0x02, 0x03},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalECDHParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.PeerPublicKey, decoded.PeerPublicKey)
}

func TestLocalECDHResult_JSONRoundTrip(t *testing.T) {
	original := &LocalECDHResult{
		SharedSecret: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalECDHResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.SharedSecret, decoded.SharedSecret)
}

func TestLocalGetPublicKeyParams_JSONRoundTrip(t *testing.T) {
	original := &LocalGetPublicKeyParams{
		KeyID:  "pub-key-1",
		Format: "der",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalGetPublicKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.Format, decoded.Format)
}

func TestLocalGetPublicKeyResult_JSONRoundTrip(t *testing.T) {
	original := &LocalGetPublicKeyResult{
		PublicKey: []byte{0x30, 0x59, 0x30, 0x13},
		Format:    "der",
		Algorithm: "ES256",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalGetPublicKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PublicKey, decoded.PublicKey)
	assert.Equal(t, original.Format, decoded.Format)
	assert.Equal(t, original.Algorithm, decoded.Algorithm)
}

func TestLocalListKeysParams_JSONRoundTrip(t *testing.T) {
	t.Run("with filters", func(t *testing.T) {
		original := &LocalListKeysParams{
			KeyType:   "fido2",
			Algorithm: "ES256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalListKeysParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.KeyType, decoded.KeyType)
		assert.Equal(t, original.Algorithm, decoded.Algorithm)
	})

	t.Run("without filters", func(t *testing.T) {
		original := &LocalListKeysParams{}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		// When omitempty fields are zero, they should not appear in JSON
		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)
		assert.NotContains(t, raw, "keyType")
		assert.NotContains(t, raw, "algorithm")

		var decoded LocalListKeysParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.KeyType)
		assert.Empty(t, decoded.Algorithm)
	})
}

func TestLocalListKeysResult_JSONRoundTrip(t *testing.T) {
	original := &LocalListKeysResult{
		Keys: []KeyInfo{
			{
				KeyID:             "key-1",
				KeyType:           "fido2",
				Algorithm:         "ES256",
				KeySizeBits:       256,
				Label:             "My FIDO2 Key",
				StrongBoxBacked:   true,
				BiometricRequired: true,
				Exportable:        false,
				Shareable:         false,
				Source:            "local",
				UseCount:          42,
				CreatedAt:         1700000000,
				LastUsedAt:        1700001000,
			},
			{
				KeyID:             "key-2",
				KeyType:           "signing",
				Algorithm:         "RS256",
				KeySizeBits:       2048,
				Label:             "Signing Key",
				StrongBoxBacked:   false,
				BiometricRequired: false,
				Exportable:        true,
				Shareable:         true,
				Source:            "remote_ble",
				UseCount:          10,
				CreatedAt:         1700002000,
				LastUsedAt:        1700003000,
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalListKeysResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Keys, 2)
	assert.Equal(t, original.Keys[0], decoded.Keys[0])
	assert.Equal(t, original.Keys[1], decoded.Keys[1])
}

func TestLocalGetKeyInfoParams_JSONRoundTrip(t *testing.T) {
	original := &LocalGetKeyInfoParams{
		KeyID: "info-key-1",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalGetKeyInfoParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
}

func TestLocalGetKeyInfoResult_JSONRoundTrip(t *testing.T) {
	t.Run("non-fido2 key", func(t *testing.T) {
		original := &LocalGetKeyInfoResult{
			KeyInfo: KeyInfo{
				KeyID:             "key-1",
				KeyType:           "signing",
				Algorithm:         "ES256",
				KeySizeBits:       256,
				Label:             "Signing Key",
				StrongBoxBacked:   true,
				BiometricRequired: false,
				Exportable:        false,
				Shareable:         false,
				Source:            "local",
				UseCount:          5,
				CreatedAt:         1700000000,
				LastUsedAt:        1700001000,
			},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetKeyInfoResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.KeyInfo, decoded.KeyInfo)
		assert.Empty(t, decoded.RpID)
		assert.Empty(t, decoded.UserName)
	})

	t.Run("fido2 key with all fields", func(t *testing.T) {
		original := &LocalGetKeyInfoResult{
			KeyInfo: KeyInfo{
				KeyID:             "fido2-key-1",
				KeyType:           "fido2",
				Algorithm:         "ES256",
				KeySizeBits:       256,
				Label:             "FIDO2 Credential",
				StrongBoxBacked:   true,
				BiometricRequired: true,
				Exportable:        false,
				Shareable:         false,
				Source:            "local",
				UseCount:          100,
				CreatedAt:         1700000000,
				LastUsedAt:        1700005000,
			},
			RpID:            "example.com",
			RpName:          "Example Site",
			UserID:          "user-123",
			UserName:        "alice@example.com",
			UserDisplayName: "Alice",
			IsDiscoverable:  true,
			SignCount:       99,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetKeyInfoResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.KeyInfo, decoded.KeyInfo)
		assert.Equal(t, original.RpID, decoded.RpID)
		assert.Equal(t, original.RpName, decoded.RpName)
		assert.Equal(t, original.UserID, decoded.UserID)
		assert.Equal(t, original.UserName, decoded.UserName)
		assert.Equal(t, original.UserDisplayName, decoded.UserDisplayName)
		assert.Equal(t, original.IsDiscoverable, decoded.IsDiscoverable)
		assert.Equal(t, original.SignCount, decoded.SignCount)
	})
}

func TestLocalDeleteKeyParams_JSONRoundTrip(t *testing.T) {
	original := &LocalDeleteKeyParams{
		KeyID: "delete-me",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalDeleteKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
}

func TestLocalDeleteKeyResult_JSONRoundTrip(t *testing.T) {
	original := &LocalDeleteKeyResult{
		Deleted: true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalDeleteKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Deleted, decoded.Deleted)
}

func TestLocalSetKeyPolicyParams_JSONRoundTrip(t *testing.T) {
	t.Run("all pointer fields set", func(t *testing.T) {
		shareable := true
		biometric := false
		authDuration := 60

		original := &LocalSetKeyPolicyParams{
			KeyID:               "policy-key-1",
			Shareable:           &shareable,
			BiometricRequired:   &biometric,
			AuthDurationSeconds: &authDuration,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalSetKeyPolicyParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.KeyID, decoded.KeyID)
		require.NotNil(t, decoded.Shareable)
		assert.Equal(t, true, *decoded.Shareable)
		require.NotNil(t, decoded.BiometricRequired)
		assert.Equal(t, false, *decoded.BiometricRequired)
		require.NotNil(t, decoded.AuthDurationSeconds)
		assert.Equal(t, 60, *decoded.AuthDurationSeconds)
	})

	t.Run("nil pointer fields omitted", func(t *testing.T) {
		original := &LocalSetKeyPolicyParams{
			KeyID: "policy-key-2",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "keyId")
		assert.NotContains(t, raw, "shareable")
		assert.NotContains(t, raw, "biometricRequired")
		assert.NotContains(t, raw, "authDurationSeconds")

		var decoded LocalSetKeyPolicyParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, "policy-key-2", decoded.KeyID)
		assert.Nil(t, decoded.Shareable)
		assert.Nil(t, decoded.BiometricRequired)
		assert.Nil(t, decoded.AuthDurationSeconds)
	})

	t.Run("pointer fields with zero values", func(t *testing.T) {
		shareableFalse := false
		biometricFalse := false
		authDurationZero := 0

		original := &LocalSetKeyPolicyParams{
			KeyID:               "policy-key-3",
			Shareable:           &shareableFalse,
			BiometricRequired:   &biometricFalse,
			AuthDurationSeconds: &authDurationZero,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		// Even with zero values, pointer fields should be present in JSON
		// because the pointer itself is non-nil
		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "shareable")
		assert.Contains(t, raw, "biometricRequired")
		assert.Contains(t, raw, "authDurationSeconds")

		var decoded LocalSetKeyPolicyParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		require.NotNil(t, decoded.Shareable)
		assert.Equal(t, false, *decoded.Shareable)
		require.NotNil(t, decoded.BiometricRequired)
		assert.Equal(t, false, *decoded.BiometricRequired)
		require.NotNil(t, decoded.AuthDurationSeconds)
		assert.Equal(t, 0, *decoded.AuthDurationSeconds)
	})
}

func TestLocalSetKeyPolicyResult_JSONRoundTrip(t *testing.T) {
	original := &LocalSetKeyPolicyResult{
		Updated: true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSetKeyPolicyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Updated, decoded.Updated)
}

func TestLocalAttestKeyParams_JSONRoundTrip(t *testing.T) {
	original := &LocalAttestKeyParams{
		KeyID: "attest-key-1",
		Nonce: []byte{0xCA, 0xFE, 0xBA, 0xBE},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalAttestKeyParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.KeyID, decoded.KeyID)
	assert.Equal(t, original.Nonce, decoded.Nonce)
}

func TestLocalAttestKeyResult_JSONRoundTrip(t *testing.T) {
	original := &LocalAttestKeyResult{
		Format: "android-keystore",
		CertificateChain: [][]byte{
			{0x30, 0x82, 0x01, 0x01}, // leaf cert
			{0x30, 0x82, 0x02, 0x02}, // intermediate cert
			{0x30, 0x82, 0x03, 0x03}, // root cert
		},
		SecurityLevel: "strongbox",
		Nonce:         []byte{0xCA, 0xFE, 0xBA, 0xBE},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalAttestKeyResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Format, decoded.Format)
	require.Len(t, decoded.CertificateChain, 3)
	assert.Equal(t, original.CertificateChain[0], decoded.CertificateChain[0])
	assert.Equal(t, original.CertificateChain[1], decoded.CertificateChain[1])
	assert.Equal(t, original.CertificateChain[2], decoded.CertificateChain[2])
	assert.Equal(t, original.SecurityLevel, decoded.SecurityLevel)
	assert.Equal(t, original.Nonce, decoded.Nonce)
}

func TestLocalGetCapabilitiesResult_JSONRoundTrip(t *testing.T) {
	original := &LocalGetCapabilitiesResult{
		Version:             "1.0.0",
		DeviceName:          "Pixel 8 Pro",
		SupportedAlgorithms: []string{"ES256", "ES384", "ES512", "RS256", "AES256"},
		StrongBoxAvailable:  true,
		MaxKeys:             256,
		CurrentKeyCount:     12,
		SupportedFormats:    []string{"der", "pem", "ssh", "cose"},
		AttestationSupport:  true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalGetCapabilitiesResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Version, decoded.Version)
	assert.Equal(t, original.DeviceName, decoded.DeviceName)
	assert.Equal(t, original.SupportedAlgorithms, decoded.SupportedAlgorithms)
	assert.Equal(t, original.StrongBoxAvailable, decoded.StrongBoxAvailable)
	assert.Equal(t, original.MaxKeys, decoded.MaxKeys)
	assert.Equal(t, original.CurrentKeyCount, decoded.CurrentKeyCount)
	assert.Equal(t, original.SupportedFormats, decoded.SupportedFormats)
	assert.Equal(t, original.AttestationSupport, decoded.AttestationSupport)
}

func TestFido2CredentialInfo_JSONRoundTrip(t *testing.T) {
	original := &Fido2CredentialInfo{
		CredentialID:    []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		RpID:            "example.com",
		RpName:          "Example",
		UserID:          []byte{0xAA, 0xBB, 0xCC},
		UserName:        "alice@example.com",
		UserDisplayName: "Alice Wonderland",
		IsDiscoverable:  true,
		CreatedAt:       1700000000,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Fido2CredentialInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.CredentialID, decoded.CredentialID)
	assert.Equal(t, original.RpID, decoded.RpID)
	assert.Equal(t, original.RpName, decoded.RpName)
	assert.Equal(t, original.UserID, decoded.UserID)
	assert.Equal(t, original.UserName, decoded.UserName)
	assert.Equal(t, original.UserDisplayName, decoded.UserDisplayName)
	assert.Equal(t, original.IsDiscoverable, decoded.IsDiscoverable)
	assert.Equal(t, original.CreatedAt, decoded.CreatedAt)
}

func TestLocalListFido2CredentialsParams_JSONRoundTrip(t *testing.T) {
	original := &LocalListFido2CredentialsParams{
		RpID: "example.com",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalListFido2CredentialsParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.RpID, decoded.RpID)
}

func TestLocalListFido2CredentialsResult_JSONRoundTrip(t *testing.T) {
	original := &LocalListFido2CredentialsResult{
		Credentials: []Fido2CredentialInfo{
			{
				CredentialID:    []byte{0x01, 0x02},
				RpID:            "example.com",
				RpName:          "Example",
				UserID:          []byte{0xAA},
				UserName:        "alice@example.com",
				UserDisplayName: "Alice",
				IsDiscoverable:  true,
				CreatedAt:       1700000000,
			},
			{
				CredentialID:    []byte{0x03, 0x04},
				RpID:            "example.com",
				RpName:          "Example",
				UserID:          []byte{0xBB},
				UserName:        "bob@example.com",
				UserDisplayName: "Bob",
				IsDiscoverable:  false,
				CreatedAt:       1700001000,
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalListFido2CredentialsResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.Credentials, 2)
	assert.Equal(t, original.Credentials[0], decoded.Credentials[0])
	assert.Equal(t, original.Credentials[1], decoded.Credentials[1])
}

func TestLocalSignFido2AssertionParams_JSONRoundTrip(t *testing.T) {
	original := &LocalSignFido2AssertionParams{
		CredentialID:             []byte{0x01, 0x02, 0x03},
		ClientDataHash:           []byte{0xAA, 0xBB, 0xCC, 0xDD},
		RpID:                     "example.com",
		UserVerificationRequired: true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSignFido2AssertionParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.CredentialID, decoded.CredentialID)
	assert.Equal(t, original.ClientDataHash, decoded.ClientDataHash)
	assert.Equal(t, original.RpID, decoded.RpID)
	assert.Equal(t, original.UserVerificationRequired, decoded.UserVerificationRequired)
}

func TestLocalSignFido2AssertionResult_JSONRoundTrip(t *testing.T) {
	original := &LocalSignFido2AssertionResult{
		AuthenticatorData: []byte{0x49, 0x96, 0x0D, 0xE5},
		Signature:         []byte{0x30, 0x44, 0x02, 0x20},
		UserHandle:        []byte{0xAA, 0xBB},
		SignCount:         42,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalSignFido2AssertionResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.AuthenticatorData, decoded.AuthenticatorData)
	assert.Equal(t, original.Signature, decoded.Signature)
	assert.Equal(t, original.UserHandle, decoded.UserHandle)
	assert.Equal(t, original.SignCount, decoded.SignCount)
}

func TestKeyInfo_JSONRoundTrip(t *testing.T) {
	original := &KeyInfo{
		KeyID:             "key-info-1",
		KeyType:           "symmetric",
		Algorithm:         "AES256",
		KeySizeBits:       256,
		Label:             "My AES Key",
		StrongBoxBacked:   false,
		BiometricRequired: false,
		Exportable:        true,
		Shareable:         true,
		Source:            "xkmsd",
		UseCount:          1000,
		CreatedAt:         1700000000,
		LastUsedAt:        1700099000,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded KeyInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, *original, decoded)
}

func TestLocalBiometricPendingParams_JSONRoundTrip(t *testing.T) {
	original := &LocalBiometricPendingParams{
		Operation:   "sign",
		RPName:      "example.com",
		TimeoutSecs: 30,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalBiometricPendingParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Operation, decoded.Operation)
	assert.Equal(t, original.RPName, decoded.RPName)
	assert.Equal(t, original.TimeoutSecs, decoded.TimeoutSecs)
}

func TestLocalAttestDeviceParams_JSONRoundTrip(t *testing.T) {
	original := &LocalAttestDeviceParams{
		Nonce: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalAttestDeviceParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Nonce, decoded.Nonce)
}

func TestLocalAttestDeviceResult_JSONRoundTrip(t *testing.T) {
	original := &LocalAttestDeviceResult{
		Format:           "android-keystore",
		CertificateChain: [][]byte{{0x30, 0x82}, {0x30, 0x83}},
		SecurityLevel:    "strongbox",
		Nonce:            []byte{0x01, 0x02, 0x03, 0x04},
		BootState:        0,
		DeviceLocked:     true,
		VerifiedBootKey:  []byte{0xAA, 0xBB, 0xCC},
		VerifiedBootHash: []byte{0xDD, 0xEE, 0xFF},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalAttestDeviceResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Format, decoded.Format)
	assert.Equal(t, original.CertificateChain, decoded.CertificateChain)
	assert.Equal(t, original.SecurityLevel, decoded.SecurityLevel)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.BootState, decoded.BootState)
	assert.Equal(t, original.DeviceLocked, decoded.DeviceLocked)
	assert.Equal(t, original.VerifiedBootKey, decoded.VerifiedBootKey)
	assert.Equal(t, original.VerifiedBootHash, decoded.VerifiedBootHash)
}

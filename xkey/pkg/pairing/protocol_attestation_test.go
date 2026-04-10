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

func TestAttestationMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"MethodLocalGetTCGCSRIDevID", MethodLocalGetTCGCSRIDevID, "local.getTCGCSRIDevID"},
		{"MethodLocalActivateCredential", MethodLocalActivateCredential, "local.activateCredential"},
		{"MethodLocalGetAttestationQuote", MethodLocalGetAttestationQuote, "local.getAttestationQuote"},
		{"MethodLocalGetIAKPublicKey", MethodLocalGetIAKPublicKey, "local.getIAKPublicKey"},
		{"MethodLocalStoreEnrollmentCerts", MethodLocalStoreEnrollmentCerts, "local.storeEnrollmentCerts"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	// Verify the total count of attestation method constants is exactly 5.
	assert.Len(t, tests, 5, "expected exactly 5 attestation method constants")
}

func TestIsAttestationMethod(t *testing.T) {
	t.Run("valid attestation methods", func(t *testing.T) {
		validMethods := []string{
			MethodLocalGetTCGCSRIDevID,
			MethodLocalActivateCredential,
			MethodLocalGetAttestationQuote,
			MethodLocalGetIAKPublicKey,
			MethodLocalStoreEnrollmentCerts,
		}
		for _, method := range validMethods {
			assert.True(t, IsAttestationMethod(method), "expected IsAttestationMethod(%q) to return true", method)
		}
	})

	t.Run("invalid or non-attestation methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"local.sign",
			"local.generateKey",
			"local.attestKey",
			"local.attestDevice",
			"remote.attestKey",
			"remote.attestDevice",
			"local.",
			"local",
			"LOCAL.getTCGCSRIDevID",
			"local.GetTCGCSRIDevID",
			"attestation.getTCGCSRIDevID",
			"phone.requestChallenge",
			"nonexistent.method",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsAttestationMethod(method), "expected IsAttestationMethod(%q) to return false", method)
		}
	})
}

func TestAttestationMethodNamesMap(t *testing.T) {
	// Verify the attestationMethodNames map has exactly 5 entries.
	assert.Len(t, attestationMethodNames, 5, "expected exactly 5 entries in attestationMethodNames")

	// Verify all expected keys are present.
	expectedMethods := []string{
		MethodLocalGetTCGCSRIDevID,
		MethodLocalActivateCredential,
		MethodLocalGetAttestationQuote,
		MethodLocalGetIAKPublicKey,
		MethodLocalStoreEnrollmentCerts,
	}
	for _, method := range expectedMethods {
		assert.True(t, attestationMethodNames[method], "expected attestationMethodNames to contain %q", method)
	}
}

func TestLocalGetTCGCSRIDevIDResult_JSONRoundTrip(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		original := &LocalGetTCGCSRIDevIDResult{
			CSR: []byte{0x30, 0x82, 0x01, 0x00, 0x30, 0x81, 0xB0}, // Mock DER-encoded CSR
			EKCert: []byte{
				0x30, 0x82, 0x02, 0x00, // Mock X.509 certificate DER
				0x30, 0x82, 0x01, 0xE9,
			},
			IAKPublicKey:    []byte{0x00, 0x23, 0x00, 0x0B}, // Mock TPM2B_PUBLIC
			IDevIDPublicKey: []byte{0x00, 0x23, 0x00, 0x0B}, // Mock TPM2B_PUBLIC
			PlatformSerial:  "SN123456789",
			PlatformModel:   "Pixel 8 Pro",
			FirmwareVersion: "1.2.3.4",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetTCGCSRIDevIDResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.CSR, decoded.CSR)
		assert.Equal(t, original.EKCert, decoded.EKCert)
		assert.Equal(t, original.IAKPublicKey, decoded.IAKPublicKey)
		assert.Equal(t, original.IDevIDPublicKey, decoded.IDevIDPublicKey)
		assert.Equal(t, original.PlatformSerial, decoded.PlatformSerial)
		assert.Equal(t, original.PlatformModel, decoded.PlatformModel)
		assert.Equal(t, original.FirmwareVersion, decoded.FirmwareVersion)
	})

	t.Run("without optional fields", func(t *testing.T) {
		original := &LocalGetTCGCSRIDevIDResult{
			CSR:             []byte{0x30, 0x82},
			IAKPublicKey:    []byte{0x00, 0x23},
			IDevIDPublicKey: []byte{0x00, 0x23},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		// Verify optional fields are omitted in JSON.
		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "csr")
		assert.Contains(t, raw, "iakPublicKey")
		assert.Contains(t, raw, "idevidPublicKey")
		assert.NotContains(t, raw, "ekCert")
		assert.NotContains(t, raw, "platformSerial")
		assert.NotContains(t, raw, "platformModel")
		assert.NotContains(t, raw, "firmwareVersion")

		var decoded LocalGetTCGCSRIDevIDResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.CSR, decoded.CSR)
		assert.Nil(t, decoded.EKCert)
		assert.Empty(t, decoded.PlatformSerial)
		assert.Empty(t, decoded.PlatformModel)
		assert.Empty(t, decoded.FirmwareVersion)
	})
}

func TestLocalGetTCGCSRIDevIDResult_JSONFieldNames(t *testing.T) {
	result := LocalGetTCGCSRIDevIDResult{
		CSR:             []byte{0x30},
		EKCert:          []byte{0x30},
		IAKPublicKey:    []byte{0x00},
		IDevIDPublicKey: []byte{0x00},
		PlatformSerial:  "SN",
		PlatformModel:   "Model",
		FirmwareVersion: "1.0",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"csr", "ekCert", "iakPublicKey", "idevidPublicKey", "platformSerial", "platformModel", "firmwareVersion"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

func TestLocalActivateCredentialParams_JSONRoundTrip(t *testing.T) {
	original := &LocalActivateCredentialParams{
		CredentialBlob: []byte{
			0x00, 0x20, // TPM2B size
			0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		},
		EncryptedSecret: []byte{
			0x00, 0x80, // TPM2B size
			0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalActivateCredentialParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.CredentialBlob, decoded.CredentialBlob)
	assert.Equal(t, original.EncryptedSecret, decoded.EncryptedSecret)
}

func TestLocalActivateCredentialParams_JSONFieldNames(t *testing.T) {
	params := LocalActivateCredentialParams{
		CredentialBlob:  []byte{0x01},
		EncryptedSecret: []byte{0x02},
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "credentialBlob")
	assert.Contains(t, raw, "encryptedSecret")
}

func TestLocalActivateCredentialParams_EmptyFields(t *testing.T) {
	original := &LocalActivateCredentialParams{}

	data, err := json.Marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var decoded LocalActivateCredentialParams
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Nil(t, decoded.CredentialBlob)
	assert.Nil(t, decoded.EncryptedSecret)
}

func TestLocalActivateCredentialResult_JSONRoundTrip(t *testing.T) {
	original := &LocalActivateCredentialResult{
		DecryptedSecret: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded LocalActivateCredentialResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.DecryptedSecret, decoded.DecryptedSecret)
}

func TestLocalActivateCredentialResult_JSONFieldNames(t *testing.T) {
	result := LocalActivateCredentialResult{
		DecryptedSecret: []byte{0x01, 0x02, 0x03},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "decryptedSecret")
}

func TestLocalGetAttestationQuoteParams_JSONRoundTrip(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		original := &LocalGetAttestationQuoteParams{
			Nonce: []byte{
				0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			},
			PCRIndices: []int{0, 1, 2, 3, 4, 5, 6, 7},
			PCRBank:    "sha256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetAttestationQuoteParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Nonce, decoded.Nonce)
		assert.Equal(t, original.PCRIndices, decoded.PCRIndices)
		assert.Equal(t, original.PCRBank, decoded.PCRBank)
	})

	t.Run("SRTM PCRs 0-7", func(t *testing.T) {
		original := &LocalGetAttestationQuoteParams{
			Nonce:      []byte{0x01, 0x02, 0x03, 0x04},
			PCRIndices: []int{0, 1, 2, 3, 4, 5, 6, 7},
			PCRBank:    "sha256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetAttestationQuoteParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		require.Len(t, decoded.PCRIndices, 8)
		for i := 0; i < 8; i++ {
			assert.Equal(t, i, decoded.PCRIndices[i])
		}
	})

	t.Run("DRTM PCRs 17-22", func(t *testing.T) {
		original := &LocalGetAttestationQuoteParams{
			Nonce:      []byte{0x01, 0x02, 0x03, 0x04},
			PCRIndices: []int{17, 18, 19, 20, 21, 22},
			PCRBank:    "sha256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetAttestationQuoteParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		require.Len(t, decoded.PCRIndices, 6)
		assert.Equal(t, []int{17, 18, 19, 20, 21, 22}, decoded.PCRIndices)
	})

	t.Run("without optional PCRBank", func(t *testing.T) {
		original := &LocalGetAttestationQuoteParams{
			Nonce:      []byte{0x01, 0x02},
			PCRIndices: []int{0, 1, 2},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "nonce")
		assert.Contains(t, raw, "pcrIndices")
		assert.NotContains(t, raw, "pcrBank")

		var decoded LocalGetAttestationQuoteParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.PCRBank)
	})

	t.Run("empty PCR indices", func(t *testing.T) {
		original := &LocalGetAttestationQuoteParams{
			Nonce:      []byte{0x01},
			PCRIndices: []int{},
			PCRBank:    "sha256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetAttestationQuoteParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.PCRIndices)
	})
}

func TestLocalGetAttestationQuoteParams_JSONFieldNames(t *testing.T) {
	params := LocalGetAttestationQuoteParams{
		Nonce:      []byte{0x01},
		PCRIndices: []int{0, 1},
		PCRBank:    "sha256",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "nonce")
	assert.Contains(t, raw, "pcrIndices")
	assert.Contains(t, raw, "pcrBank")
}

func TestLocalGetAttestationQuoteParams_PCRBankVariants(t *testing.T) {
	banks := []string{"sha256", "sha384", "sha512", "sha1"}

	for _, bank := range banks {
		t.Run(bank, func(t *testing.T) {
			original := &LocalGetAttestationQuoteParams{
				Nonce:      []byte{0x01, 0x02, 0x03, 0x04},
				PCRIndices: []int{0},
				PCRBank:    bank,
			}

			data, err := json.Marshal(original)
			require.NoError(t, err)

			var decoded LocalGetAttestationQuoteParams
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, bank, decoded.PCRBank)
		})
	}
}

func TestLocalGetAttestationQuoteResult_JSONRoundTrip(t *testing.T) {
	t.Run("with all fields including event log", func(t *testing.T) {
		original := &LocalGetAttestationQuoteResult{
			Quoted: []byte{
				0xFF, 0x54, 0x43, 0x47, 0x80, 0x17, // Mock TPMS_ATTEST prefix
				0x00, 0x22, 0x00, 0x0B, // Mock TPM2B_DATA
			},
			Signature: []byte{
				0x30, 0x44, 0x02, 0x20, // Mock ECDSA signature
				0xAB, 0xCD, 0xEF, 0x01,
			},
			PCRValues: map[int][]byte{
				0: {
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
				1: {
					0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
					0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
					0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
					0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				},
				7: {
					0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
					0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
					0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
					0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
				},
			},
			EventLog: []byte{0x54, 0x43, 0x47, 0x20, 0x45, 0x56, 0x45, 0x4E, 0x54}, // "TCG EVENT"
			PCRBank:  "sha256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetAttestationQuoteResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Quoted, decoded.Quoted)
		assert.Equal(t, original.Signature, decoded.Signature)
		require.Len(t, decoded.PCRValues, 3)
		assert.Equal(t, original.PCRValues[0], decoded.PCRValues[0])
		assert.Equal(t, original.PCRValues[1], decoded.PCRValues[1])
		assert.Equal(t, original.PCRValues[7], decoded.PCRValues[7])
		assert.Equal(t, original.EventLog, decoded.EventLog)
		assert.Equal(t, original.PCRBank, decoded.PCRBank)
	})

	t.Run("without event log", func(t *testing.T) {
		original := &LocalGetAttestationQuoteResult{
			Quoted:    []byte{0xFF, 0x54, 0x43, 0x47},
			Signature: []byte{0x30, 0x44},
			PCRValues: map[int][]byte{
				0: {0x00, 0x00, 0x00, 0x00},
			},
			PCRBank: "sha256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "quoted")
		assert.Contains(t, raw, "signature")
		assert.Contains(t, raw, "pcrValues")
		assert.Contains(t, raw, "pcrBank")
		assert.NotContains(t, raw, "eventLog")

		var decoded LocalGetAttestationQuoteResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Nil(t, decoded.EventLog)
	})

	t.Run("empty PCR values map", func(t *testing.T) {
		original := &LocalGetAttestationQuoteResult{
			Quoted:    []byte{0x01},
			Signature: []byte{0x02},
			PCRValues: map[int][]byte{},
			PCRBank:   "sha256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetAttestationQuoteResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.PCRValues)
	})
}

func TestLocalGetAttestationQuoteResult_JSONFieldNames(t *testing.T) {
	result := LocalGetAttestationQuoteResult{
		Quoted:    []byte{0x01},
		Signature: []byte{0x02},
		PCRValues: map[int][]byte{0: {0x03}},
		EventLog:  []byte{0x04},
		PCRBank:   "sha256",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"quoted", "signature", "pcrValues", "eventLog", "pcrBank"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

func TestLocalGetIAKPublicKeyResult_JSONRoundTrip(t *testing.T) {
	t.Run("RSA2048 key with all fields", func(t *testing.T) {
		original := &LocalGetIAKPublicKeyResult{
			PublicKey: []byte{
				0x00, 0x23, 0x00, 0x0B, // Mock TPM2B_PUBLIC prefix
				0x00, 0x01, 0x00, 0x00, // Mock RSA public key
			},
			Algorithm:    "RSA2048",
			PublicKeyDER: []byte{0x30, 0x82, 0x01, 0x22}, // Mock PKCS#1 DER
			Name:         []byte{0x00, 0x0B, 0xAA, 0xBB}, // Mock TPM2B_NAME
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetIAKPublicKeyResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.PublicKey, decoded.PublicKey)
		assert.Equal(t, original.Algorithm, decoded.Algorithm)
		assert.Equal(t, original.PublicKeyDER, decoded.PublicKeyDER)
		assert.Equal(t, original.Name, decoded.Name)
	})

	t.Run("ECCP256 key", func(t *testing.T) {
		original := &LocalGetIAKPublicKeyResult{
			PublicKey: []byte{
				0x04, // Uncompressed point indicator
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			},
			Algorithm:    "ECCP256",
			PublicKeyDER: []byte{0x30, 0x59, 0x30, 0x13},
			Name:         []byte{0x00, 0x0B, 0xCC, 0xDD},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetIAKPublicKeyResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, "ECCP256", decoded.Algorithm)
		assert.Equal(t, original.PublicKey, decoded.PublicKey)
	})

	t.Run("without optional fields", func(t *testing.T) {
		original := &LocalGetIAKPublicKeyResult{
			PublicKey: []byte{0x04, 0x01, 0x02},
			Algorithm: "ECCP384",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "publicKey")
		assert.Contains(t, raw, "algorithm")
		assert.NotContains(t, raw, "publicKeyDer")
		assert.NotContains(t, raw, "name")

		var decoded LocalGetIAKPublicKeyResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Nil(t, decoded.PublicKeyDER)
		assert.Nil(t, decoded.Name)
	})
}

func TestLocalGetIAKPublicKeyResult_JSONFieldNames(t *testing.T) {
	result := LocalGetIAKPublicKeyResult{
		PublicKey:    []byte{0x01},
		Algorithm:    "RSA3072",
		PublicKeyDER: []byte{0x02},
		Name:         []byte{0x03},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"publicKey", "algorithm", "publicKeyDer", "name"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q", field)
	}
}

func TestLocalGetIAKPublicKeyResult_AlgorithmVariants(t *testing.T) {
	algorithms := []string{"RSA2048", "RSA3072", "ECCP256", "ECCP384"}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			original := &LocalGetIAKPublicKeyResult{
				PublicKey: []byte{0x01, 0x02, 0x03},
				Algorithm: algo,
			}

			data, err := json.Marshal(original)
			require.NoError(t, err)

			var decoded LocalGetIAKPublicKeyResult
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, algo, decoded.Algorithm)
		})
	}
}

func TestLocalStoreEnrollmentCertsParams_JSONRoundTrip(t *testing.T) {
	t.Run("with certificate chain", func(t *testing.T) {
		original := &LocalStoreEnrollmentCertsParams{
			IAKCert: []byte{
				0x30, 0x82, 0x03, 0x00, // Mock IAK X.509 certificate DER
				0x30, 0x82, 0x02, 0xE8,
			},
			IDevIDCert: []byte{
				0x30, 0x82, 0x03, 0x00, // Mock IDevID X.509 certificate DER
				0x30, 0x82, 0x02, 0xE9,
			},
			Chain: [][]byte{
				{0x30, 0x82, 0x04, 0x00}, // Intermediate CA
				{0x30, 0x82, 0x05, 0x00}, // Root CA
			},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalStoreEnrollmentCertsParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.IAKCert, decoded.IAKCert)
		assert.Equal(t, original.IDevIDCert, decoded.IDevIDCert)
		require.Len(t, decoded.Chain, 2)
		assert.Equal(t, original.Chain[0], decoded.Chain[0])
		assert.Equal(t, original.Chain[1], decoded.Chain[1])
	})

	t.Run("without certificate chain", func(t *testing.T) {
		original := &LocalStoreEnrollmentCertsParams{
			IAKCert:    []byte{0x30, 0x82, 0x03, 0x00},
			IDevIDCert: []byte{0x30, 0x82, 0x03, 0x01},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "iakCert")
		assert.Contains(t, raw, "idevidCert")
		assert.NotContains(t, raw, "chain")

		var decoded LocalStoreEnrollmentCertsParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Nil(t, decoded.Chain)
	})

	t.Run("with empty certificate chain", func(t *testing.T) {
		original := &LocalStoreEnrollmentCertsParams{
			IAKCert:    []byte{0x30, 0x82},
			IDevIDCert: []byte{0x30, 0x82},
			Chain:      [][]byte{},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalStoreEnrollmentCertsParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.Chain)
	})
}

func TestLocalStoreEnrollmentCertsParams_JSONFieldNames(t *testing.T) {
	params := LocalStoreEnrollmentCertsParams{
		IAKCert:    []byte{0x01},
		IDevIDCert: []byte{0x02},
		Chain:      [][]byte{{0x03}},
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "iakCert")
	assert.Contains(t, raw, "idevidCert")
	assert.Contains(t, raw, "chain")
}

func TestLocalStoreEnrollmentCertsResult_JSONRoundTrip(t *testing.T) {
	t.Run("successful storage with fingerprints", func(t *testing.T) {
		original := &LocalStoreEnrollmentCertsResult{
			Stored:                true,
			IAKCertFingerprint:    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
			IDevIDCertFingerprint: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalStoreEnrollmentCertsResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.True(t, decoded.Stored)
		assert.Equal(t, original.IAKCertFingerprint, decoded.IAKCertFingerprint)
		assert.Equal(t, original.IDevIDCertFingerprint, decoded.IDevIDCertFingerprint)
	})

	t.Run("failed storage without fingerprints", func(t *testing.T) {
		original := &LocalStoreEnrollmentCertsResult{
			Stored: false,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "stored")
		assert.NotContains(t, raw, "iakCertFingerprint")
		assert.NotContains(t, raw, "idevidCertFingerprint")

		var decoded LocalStoreEnrollmentCertsResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.False(t, decoded.Stored)
		assert.Empty(t, decoded.IAKCertFingerprint)
		assert.Empty(t, decoded.IDevIDCertFingerprint)
	})
}

func TestLocalStoreEnrollmentCertsResult_JSONFieldNames(t *testing.T) {
	result := LocalStoreEnrollmentCertsResult{
		Stored:                true,
		IAKCertFingerprint:    "abc",
		IDevIDCertFingerprint: "def",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "stored")
	assert.Contains(t, raw, "iakCertFingerprint")
	assert.Contains(t, raw, "idevidCertFingerprint")
}

func TestAttestationTypes_ZeroValues(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
	}{
		{"LocalGetTCGCSRIDevIDResult", &LocalGetTCGCSRIDevIDResult{}},
		{"LocalActivateCredentialParams", &LocalActivateCredentialParams{}},
		{"LocalActivateCredentialResult", &LocalActivateCredentialResult{}},
		{"LocalGetAttestationQuoteParams", &LocalGetAttestationQuoteParams{}},
		{"LocalGetAttestationQuoteResult", &LocalGetAttestationQuoteResult{}},
		{"LocalGetIAKPublicKeyResult", &LocalGetIAKPublicKeyResult{}},
		{"LocalStoreEnrollmentCertsParams", &LocalStoreEnrollmentCertsParams{}},
		{"LocalStoreEnrollmentCertsResult", &LocalStoreEnrollmentCertsResult{}},
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

func TestAttestationTypes_NilValues(t *testing.T) {
	t.Run("nil LocalGetTCGCSRIDevIDResult fields", func(t *testing.T) {
		result := &LocalGetTCGCSRIDevIDResult{
			CSR:             nil,
			EKCert:          nil,
			IAKPublicKey:    nil,
			IDevIDPublicKey: nil,
		}

		data, err := json.Marshal(result)
		require.NoError(t, err)

		var decoded LocalGetTCGCSRIDevIDResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Nil(t, decoded.CSR)
		assert.Nil(t, decoded.EKCert)
		assert.Nil(t, decoded.IAKPublicKey)
		assert.Nil(t, decoded.IDevIDPublicKey)
	})

	t.Run("nil LocalGetAttestationQuoteResult fields", func(t *testing.T) {
		result := &LocalGetAttestationQuoteResult{
			Quoted:    nil,
			Signature: nil,
			PCRValues: nil,
			EventLog:  nil,
			PCRBank:   "",
		}

		data, err := json.Marshal(result)
		require.NoError(t, err)

		var decoded LocalGetAttestationQuoteResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Nil(t, decoded.Quoted)
		assert.Nil(t, decoded.Signature)
		assert.Nil(t, decoded.PCRValues)
		assert.Nil(t, decoded.EventLog)
	})
}

func TestNewRequest_AttestationMethods(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "local getTCGCSRIDevID",
			method: MethodLocalGetTCGCSRIDevID,
			params: nil,
		},
		{
			name:   "local activateCredential",
			method: MethodLocalActivateCredential,
			params: &LocalActivateCredentialParams{
				CredentialBlob:  []byte{0x01, 0x02, 0x03},
				EncryptedSecret: []byte{0x04, 0x05, 0x06},
			},
		},
		{
			name:   "local getAttestationQuote",
			method: MethodLocalGetAttestationQuote,
			params: &LocalGetAttestationQuoteParams{
				Nonce:      []byte{0xDE, 0xAD, 0xBE, 0xEF},
				PCRIndices: []int{0, 1, 2, 3, 4, 5, 6, 7},
				PCRBank:    "sha256",
			},
		},
		{
			name:   "local getIAKPublicKey",
			method: MethodLocalGetIAKPublicKey,
			params: nil,
		},
		{
			name:   "local storeEnrollmentCerts",
			method: MethodLocalStoreEnrollmentCerts,
			params: &LocalStoreEnrollmentCertsParams{
				IAKCert:    []byte{0x30, 0x82, 0x03, 0x00},
				IDevIDCert: []byte{0x30, 0x82, 0x03, 0x01},
				Chain: [][]byte{
					{0x30, 0x82, 0x04, 0x00},
					{0x30, 0x82, 0x05, 0x00},
				},
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

			// Verify IsAttestationMethod returns true for this method.
			assert.True(t, IsAttestationMethod(tt.method))
		})
	}
}

func TestDecodeResult_AttestationResults(t *testing.T) {
	t.Run("LocalGetTCGCSRIDevIDResult", func(t *testing.T) {
		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      200,
			Result: json.RawMessage(`{
				"csr": "MDEyMw==",
				"ekCert": "REVG",
				"iakPublicKey": "R0hJ",
				"idevidPublicKey": "SktM",
				"platformSerial": "SN12345",
				"platformModel": "TestDevice",
				"firmwareVersion": "1.0.0"
			}`),
		}

		result, err := DecodeResult[LocalGetTCGCSRIDevIDResult](resp)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, []byte("0123"), result.CSR)
		assert.Equal(t, []byte("DEF"), result.EKCert)
		assert.Equal(t, []byte("GHI"), result.IAKPublicKey)
		assert.Equal(t, []byte("JKL"), result.IDevIDPublicKey)
		assert.Equal(t, "SN12345", result.PlatformSerial)
		assert.Equal(t, "TestDevice", result.PlatformModel)
		assert.Equal(t, "1.0.0", result.FirmwareVersion)
	})

	t.Run("LocalActivateCredentialResult", func(t *testing.T) {
		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      201,
			Result:  json.RawMessage(`{"decryptedSecret":"c2VjcmV0"}`),
		}

		result, err := DecodeResult[LocalActivateCredentialResult](resp)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, []byte("secret"), result.DecryptedSecret)
	})

	t.Run("LocalGetAttestationQuoteResult", func(t *testing.T) {
		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      202,
			Result: json.RawMessage(`{
				"quoted": "cXVvdGVk",
				"signature": "c2ln",
				"pcrValues": {"0": "AAAA", "7": "Bwc="},
				"eventLog": "ZXZlbnQ=",
				"pcrBank": "sha256"
			}`),
		}

		result, err := DecodeResult[LocalGetAttestationQuoteResult](resp)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, []byte("quoted"), result.Quoted)
		assert.Equal(t, []byte("sig"), result.Signature)
		require.Len(t, result.PCRValues, 2)
		assert.Equal(t, []byte("event"), result.EventLog)
		assert.Equal(t, "sha256", result.PCRBank)
	})

	t.Run("LocalGetIAKPublicKeyResult", func(t *testing.T) {
		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      203,
			Result: json.RawMessage(`{
				"publicKey": "cHVia2V5",
				"algorithm": "ECCP256",
				"publicKeyDer": "ZGVy",
				"name": "bmFtZQ=="
			}`),
		}

		result, err := DecodeResult[LocalGetIAKPublicKeyResult](resp)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, []byte("pubkey"), result.PublicKey)
		assert.Equal(t, "ECCP256", result.Algorithm)
		assert.Equal(t, []byte("der"), result.PublicKeyDER)
		assert.Equal(t, []byte("name"), result.Name)
	})

	t.Run("LocalStoreEnrollmentCertsResult", func(t *testing.T) {
		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      204,
			Result: json.RawMessage(`{
				"stored": true,
				"iakCertFingerprint": "abcd1234",
				"idevidCertFingerprint": "efgh5678"
			}`),
		}

		result, err := DecodeResult[LocalStoreEnrollmentCertsResult](resp)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Stored)
		assert.Equal(t, "abcd1234", result.IAKCertFingerprint)
		assert.Equal(t, "efgh5678", result.IDevIDCertFingerprint)
	})
}

func TestDecodeResult_AttestationWithRPCError(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      300,
		Error: &RPCError{
			Code:    ErrorCodeInternalError,
			Message: "TPM2 operation failed",
		},
	}

	result, err := DecodeResult[LocalActivateCredentialResult](resp)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "TPM2 operation failed", err.Error())
}

func TestDecodeResult_AttestationInvalidJSON(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      301,
		Result:  json.RawMessage(`{invalid json`),
	}

	result, err := DecodeResult[LocalGetTCGCSRIDevIDResult](resp)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestPCRValuesMap_JSONEncoding(t *testing.T) {
	// Test that map[int][]byte encodes/decodes correctly with JSON.
	// JSON keys must be strings, so int keys get converted.
	original := map[int][]byte{
		0:  {0x00, 0x00, 0x00, 0x00},
		1:  {0x01, 0x01, 0x01, 0x01},
		7:  {0x07, 0x07, 0x07, 0x07},
		17: {0x11, 0x11, 0x11, 0x11},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded map[int][]byte
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded, 4)
	assert.Equal(t, original[0], decoded[0])
	assert.Equal(t, original[1], decoded[1])
	assert.Equal(t, original[7], decoded[7])
	assert.Equal(t, original[17], decoded[17])
}

func TestCertificateChainArray_JSONEncoding(t *testing.T) {
	// Test that [][]byte (certificate chain) encodes/decodes correctly.
	original := [][]byte{
		{0x30, 0x82, 0x01, 0x00}, // Leaf cert
		{0x30, 0x82, 0x02, 0x00}, // Intermediate
		{0x30, 0x82, 0x03, 0x00}, // Root
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded [][]byte
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded, 3)
	assert.Equal(t, original[0], decoded[0])
	assert.Equal(t, original[1], decoded[1])
	assert.Equal(t, original[2], decoded[2])
}

func TestAttestationMethodsNotInLocalMethods(t *testing.T) {
	// Verify that attestation methods are NOT in localMethodNames by default.
	// The attestation methods are separate from the core local.* methods
	// and have their own attestationMethodNames map.
	attestationMethods := []string{
		MethodLocalGetTCGCSRIDevID,
		MethodLocalActivateCredential,
		MethodLocalGetAttestationQuote,
		MethodLocalGetIAKPublicKey,
		MethodLocalStoreEnrollmentCerts,
	}

	for _, method := range attestationMethods {
		// These should NOT be in localMethodNames since they're in attestationMethodNames
		isLocal := IsLocalMethod(method)
		isAttestation := IsAttestationMethod(method)

		// Attestation methods should return true for IsAttestationMethod
		assert.True(t, isAttestation, "expected IsAttestationMethod(%q) to return true", method)

		// Note: Based on the current implementation, attestation methods are NOT
		// in localMethodNames, so IsLocalMethod should return false for them
		assert.False(t, isLocal, "expected IsLocalMethod(%q) to return false (attestation methods are separate)", method)
	}
}

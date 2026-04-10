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

func TestIDevIDMethodConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"MethodLocalGetCABundle", MethodLocalGetCABundle, "local.getCABundle"},
		{"MethodLocalGetIDevIDCertificate", MethodLocalGetIDevIDCertificate, "local.getIDevIDCertificate"},
		{"MethodLocalRequestIDevIDIssuance", MethodLocalRequestIDevIDIssuance, "local.requestIDevIDIssuance"},
		{"MethodLocalGenerateIDevIDCSR", MethodLocalGenerateIDevIDCSR, "local.generateIDevIDCSR"},
		{"MethodLocalStoreIDevIDCertificate", MethodLocalStoreIDevIDCertificate, "local.storeIDevIDCertificate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}

	// Verify the total count of IDevID methods is exactly 5.
	assert.Len(t, tests, 5, "expected exactly 5 IDevID method constants")
}

func TestIsIDevIDMethod(t *testing.T) {
	t.Run("valid IDevID methods", func(t *testing.T) {
		validMethods := []string{
			MethodLocalGetCABundle,
			MethodLocalGetIDevIDCertificate,
			MethodLocalRequestIDevIDIssuance,
			MethodLocalGenerateIDevIDCSR,
			MethodLocalStoreIDevIDCertificate,
		}
		for _, method := range validMethods {
			assert.True(t, IsIDevIDMethod(method), "expected IsIDevIDMethod(%q) to return true", method)
		}
	})

	t.Run("invalid methods", func(t *testing.T) {
		invalidMethods := []string{
			"",
			"local.sign",
			"local.generateKey",
			"remote.sign",
			"getCABundle",
			"local.getcabundle",
			"LOCAL.getCABundle",
			"local.GetCABundle",
			"idevid.getCABundle",
			"phone.requestChallenge",
			"local.",
			"local",
			"nonexistent",
		}
		for _, method := range invalidMethods {
			assert.False(t, IsIDevIDMethod(method), "expected IsIDevIDMethod(%q) to return false", method)
		}
	})
}

func TestIDevIDMethodsRegisteredInLocalMethods(t *testing.T) {
	// IDevID methods are registered in localMethodNames via init().
	// Verify that IsLocalMethod returns true for all IDevID methods.
	idevidMethods := []string{
		MethodLocalGetCABundle,
		MethodLocalGetIDevIDCertificate,
		MethodLocalRequestIDevIDIssuance,
		MethodLocalGenerateIDevIDCSR,
		MethodLocalStoreIDevIDCertificate,
	}

	for _, method := range idevidMethods {
		assert.True(t, IsLocalMethod(method), "expected IsLocalMethod(%q) to return true for IDevID method", method)
	}
}

func TestLocalGetCABundleParams_JSONRoundTrip(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		original := &LocalGetCABundleParams{
			IncludeRoot: true,
			Format:      "pem",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetCABundleParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.IncludeRoot, decoded.IncludeRoot)
		assert.Equal(t, original.Format, decoded.Format)
	})

	t.Run("omitempty fields excluded", func(t *testing.T) {
		original := &LocalGetCABundleParams{}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		// Both fields have omitempty, so they should be excluded when zero.
		assert.NotContains(t, raw, "includeRoot")
		assert.NotContains(t, raw, "format")
	})

	t.Run("der format", func(t *testing.T) {
		original := &LocalGetCABundleParams{
			IncludeRoot: false,
			Format:      "der",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetCABundleParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.False(t, decoded.IncludeRoot)
		assert.Equal(t, "der", decoded.Format)
	})
}

func TestLocalGetCABundleParams_JSONFieldNames(t *testing.T) {
	params := LocalGetCABundleParams{
		IncludeRoot: true,
		Format:      "pem",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "includeRoot")
	assert.Contains(t, raw, "format")
}

func TestLocalGetCABundleResult_JSONRoundTrip(t *testing.T) {
	t.Run("with PEM bundle and certificates", func(t *testing.T) {
		original := &LocalGetCABundleResult{
			BundlePEM: []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"),
			Certificates: [][]byte{
				{0x30, 0x82, 0x01, 0x00}, // Mock DER cert 1
				{0x30, 0x82, 0x02, 0x00}, // Mock DER cert 2
			},
			Count:       2,
			RootSubject: "CN=Root CA,O=Test Org",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetCABundleResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.BundlePEM, decoded.BundlePEM)
		require.Len(t, decoded.Certificates, 2)
		assert.Equal(t, original.Certificates[0], decoded.Certificates[0])
		assert.Equal(t, original.Certificates[1], decoded.Certificates[1])
		assert.Equal(t, original.Count, decoded.Count)
		assert.Equal(t, original.RootSubject, decoded.RootSubject)
	})

	t.Run("without optional fields", func(t *testing.T) {
		original := &LocalGetCABundleResult{
			Certificates: [][]byte{{0x30, 0x82}},
			Count:        1,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "bundlePem")
		assert.NotContains(t, raw, "rootSubject")

		var decoded LocalGetCABundleResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Nil(t, decoded.BundlePEM)
		assert.Empty(t, decoded.RootSubject)
		assert.Equal(t, 1, decoded.Count)
	})

	t.Run("empty certificates", func(t *testing.T) {
		original := &LocalGetCABundleResult{
			Certificates: [][]byte{},
			Count:        0,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetCABundleResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.Certificates)
		assert.Equal(t, 0, decoded.Count)
	})
}

func TestLocalGetCABundleResult_JSONFieldNames(t *testing.T) {
	result := LocalGetCABundleResult{
		BundlePEM:    []byte("pem-data"),
		Certificates: [][]byte{{0x01}},
		Count:        1,
		RootSubject:  "CN=Root",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"bundlePem", "certificates", "count", "rootSubject"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q to be present", field)
	}
}

func TestLocalGetIDevIDCertificateParams_JSONRoundTrip(t *testing.T) {
	t.Run("with nonce", func(t *testing.T) {
		original := &LocalGetIDevIDCertificateParams{
			Nonce: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetIDevIDCertificateParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Nonce, decoded.Nonce)
	})

	t.Run("without nonce", func(t *testing.T) {
		original := &LocalGetIDevIDCertificateParams{}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "nonce")
	})
}

func TestLocalGetIDevIDCertificateResult_JSONRoundTrip(t *testing.T) {
	t.Run("has certificate with full chain", func(t *testing.T) {
		original := &LocalGetIDevIDCertificateResult{
			HasCertificate: true,
			CertificateChain: [][]byte{
				{0x30, 0x82, 0x01, 0x00}, // leaf
				{0x30, 0x82, 0x02, 0x00}, // intermediate
				{0x30, 0x82, 0x03, 0x00}, // root
			},
			Nonce: []byte{0x01, 0x02, 0x03, 0x04},
			CertificateInfo: &IDevIDCertificateInfo{
				SerialNumber:       "ABC123",
				Issuer:             "CN=Test CA",
				Subject:            "CN=Device001",
				NotBefore:          1700000000,
				NotAfter:           1731536000,
				Algorithm:          "ECDSA-SHA256",
				PublicKeyAlgorithm: "ECDSA",
				KeySizeBits:        256,
				Fingerprint:        "aabbccdd...",
				IsCA:               false,
				KeyUsage:           []string{"digitalSignature"},
				ExtKeyUsage:        []string{"clientAuth"},
				HardwareSerial:     "HW-001",
			},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetIDevIDCertificateResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.True(t, decoded.HasCertificate)
		require.Len(t, decoded.CertificateChain, 3)
		assert.Equal(t, original.CertificateChain[0], decoded.CertificateChain[0])
		assert.Equal(t, original.Nonce, decoded.Nonce)
		require.NotNil(t, decoded.CertificateInfo)
		assert.Equal(t, original.CertificateInfo.SerialNumber, decoded.CertificateInfo.SerialNumber)
		assert.Equal(t, original.CertificateInfo.Subject, decoded.CertificateInfo.Subject)
		assert.Equal(t, original.CertificateInfo.HardwareSerial, decoded.CertificateInfo.HardwareSerial)
	})

	t.Run("no certificate", func(t *testing.T) {
		original := &LocalGetIDevIDCertificateResult{
			HasCertificate: false,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGetIDevIDCertificateResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.False(t, decoded.HasCertificate)
		assert.Nil(t, decoded.CertificateChain)
		assert.Nil(t, decoded.CertificateInfo)
	})
}

func TestLocalGetIDevIDCertificateResult_JSONFieldNames(t *testing.T) {
	result := LocalGetIDevIDCertificateResult{
		HasCertificate:   true,
		CertificateChain: [][]byte{{0x01}},
		Nonce:            []byte{0x02},
		CertificateInfo:  &IDevIDCertificateInfo{SerialNumber: "SN"},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"hasCertificate", "certificateChain", "nonce", "certificateInfo"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q to be present", field)
	}
}

func TestLocalRequestIDevIDIssuanceParams_JSONRoundTrip(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		original := &LocalRequestIDevIDIssuanceParams{
			CSR:             []byte{0x30, 0x82, 0x01, 0x00},
			CSRFormat:       "pkcs10",
			AttestationData: []byte{0xFF, 0x54, 0x43, 0x47},
			ValidityDays:    365,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalRequestIDevIDIssuanceParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.CSR, decoded.CSR)
		assert.Equal(t, original.CSRFormat, decoded.CSRFormat)
		assert.Equal(t, original.AttestationData, decoded.AttestationData)
		assert.Equal(t, original.ValidityDays, decoded.ValidityDays)
	})

	t.Run("tcg-csr-idevid format", func(t *testing.T) {
		original := &LocalRequestIDevIDIssuanceParams{
			CSR:       []byte{0x30, 0x82},
			CSRFormat: "tcg-csr-idevid",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalRequestIDevIDIssuanceParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, "tcg-csr-idevid", decoded.CSRFormat)
	})

	t.Run("optional fields omitted", func(t *testing.T) {
		original := &LocalRequestIDevIDIssuanceParams{
			CSR: []byte{0x30, 0x82},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "csr")
		assert.NotContains(t, raw, "csrFormat")
		assert.NotContains(t, raw, "attestationData")
		assert.NotContains(t, raw, "validityDays")
	})
}

func TestLocalRequestIDevIDIssuanceParams_JSONFieldNames(t *testing.T) {
	params := LocalRequestIDevIDIssuanceParams{
		CSR:             []byte{0x01},
		CSRFormat:       "pkcs10",
		AttestationData: []byte{0x02},
		ValidityDays:    365,
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"csr", "csrFormat", "attestationData", "validityDays"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q to be present", field)
	}
}

func TestLocalRequestIDevIDIssuanceResult_JSONRoundTrip(t *testing.T) {
	t.Run("successful issuance", func(t *testing.T) {
		original := &LocalRequestIDevIDIssuanceResult{
			Issued:      true,
			Certificate: []byte{0x30, 0x82, 0x01, 0x00},
			CertificateChain: [][]byte{
				{0x30, 0x82, 0x01, 0x00}, // leaf
				{0x30, 0x82, 0x02, 0x00}, // intermediate
				{0x30, 0x82, 0x03, 0x00}, // root
			},
			CertificateInfo: &IDevIDCertificateInfo{
				SerialNumber: "NEW001",
				Subject:      "CN=Device",
				NotBefore:    1700000000,
				NotAfter:     1731536000,
			},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalRequestIDevIDIssuanceResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.True(t, decoded.Issued)
		assert.Equal(t, original.Certificate, decoded.Certificate)
		require.Len(t, decoded.CertificateChain, 3)
		require.NotNil(t, decoded.CertificateInfo)
		assert.Equal(t, "NEW001", decoded.CertificateInfo.SerialNumber)
	})

	t.Run("failed issuance", func(t *testing.T) {
		original := &LocalRequestIDevIDIssuanceResult{
			Issued:       false,
			ErrorCode:    "INVALID_CSR",
			ErrorMessage: "CSR signature verification failed",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalRequestIDevIDIssuanceResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.False(t, decoded.Issued)
		assert.Equal(t, "INVALID_CSR", decoded.ErrorCode)
		assert.Equal(t, "CSR signature verification failed", decoded.ErrorMessage)
		assert.Nil(t, decoded.Certificate)
		assert.Nil(t, decoded.CertificateChain)
	})
}

func TestLocalRequestIDevIDIssuanceResult_JSONFieldNames(t *testing.T) {
	result := LocalRequestIDevIDIssuanceResult{
		Issued:           true,
		Certificate:      []byte{0x01},
		CertificateChain: [][]byte{{0x02}},
		CertificateInfo:  &IDevIDCertificateInfo{SerialNumber: "SN"},
		ErrorCode:        "NONE",
		ErrorMessage:     "success",
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"issued", "certificate", "certificateChain", "certificateInfo", "errorCode", "errorMessage"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q to be present", field)
	}
}

func TestLocalGenerateIDevIDCSRParams_JSONRoundTrip(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		original := &LocalGenerateIDevIDCSRParams{
			Backend:   "tpm2",
			KeyID:     "idevid-key-001",
			Algorithm: "ES256",
			Subject: &IDevIDSubject{
				CommonName:         "Device-001",
				Organization:       "Test Org",
				OrganizationalUnit: "IT Department",
				SerialNumber:       "HW-SERIAL-001",
				Country:            "US",
				Locality:           "San Francisco",
				Province:           "California",
			},
			CSRFormat: "pkcs10",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGenerateIDevIDCSRParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Backend, decoded.Backend)
		assert.Equal(t, original.KeyID, decoded.KeyID)
		assert.Equal(t, original.Algorithm, decoded.Algorithm)
		assert.Equal(t, original.CSRFormat, decoded.CSRFormat)
		require.NotNil(t, decoded.Subject)
		assert.Equal(t, original.Subject.CommonName, decoded.Subject.CommonName)
		assert.Equal(t, original.Subject.SerialNumber, decoded.Subject.SerialNumber)
		assert.Equal(t, original.Subject.Country, decoded.Subject.Country)
	})

	t.Run("minimal fields", func(t *testing.T) {
		original := &LocalGenerateIDevIDCSRParams{
			Algorithm: "ES256",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "backend")
		assert.NotContains(t, raw, "keyId")
		assert.NotContains(t, raw, "subject")
		assert.NotContains(t, raw, "csrFormat")

		var decoded LocalGenerateIDevIDCSRParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Empty(t, decoded.Backend)
		assert.Empty(t, decoded.KeyID)
		assert.Nil(t, decoded.Subject)
	})

	t.Run("tcg-csr-idevid format", func(t *testing.T) {
		original := &LocalGenerateIDevIDCSRParams{
			Backend:   "tpm2",
			Algorithm: "ES256",
			CSRFormat: "tcg-csr-idevid",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGenerateIDevIDCSRParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, "tcg-csr-idevid", decoded.CSRFormat)
	})
}

func TestLocalGenerateIDevIDCSRParams_JSONFieldNames(t *testing.T) {
	params := LocalGenerateIDevIDCSRParams{
		Backend:   "tpm2",
		KeyID:     "key1",
		Algorithm: "ES256",
		Subject:   &IDevIDSubject{CommonName: "Test"},
		CSRFormat: "pkcs10",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"backend", "keyId", "algorithm", "subject", "csrFormat"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q to be present", field)
	}
}

func TestLocalGenerateIDevIDCSRResult_JSONRoundTrip(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		original := &LocalGenerateIDevIDCSRResult{
			CSR:       []byte{0x30, 0x82, 0x01, 0x00},
			CSRFormat: "pkcs10",
			KeyID:     "idevid-key-001",
			Backend:   "tpm2",
			Algorithm: "ES256",
			PublicKey: []byte{0x04, 0x01, 0x02, 0x03},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalGenerateIDevIDCSRResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.CSR, decoded.CSR)
		assert.Equal(t, original.CSRFormat, decoded.CSRFormat)
		assert.Equal(t, original.KeyID, decoded.KeyID)
		assert.Equal(t, original.Backend, decoded.Backend)
		assert.Equal(t, original.Algorithm, decoded.Algorithm)
		assert.Equal(t, original.PublicKey, decoded.PublicKey)
	})

	t.Run("without public key", func(t *testing.T) {
		original := &LocalGenerateIDevIDCSRResult{
			CSR:       []byte{0x30, 0x82},
			CSRFormat: "tcg-csr-idevid",
			KeyID:     "key1",
			Backend:   "software",
			Algorithm: "RS2048",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "publicKey")

		var decoded LocalGenerateIDevIDCSRResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Nil(t, decoded.PublicKey)
	})
}

func TestLocalGenerateIDevIDCSRResult_JSONFieldNames(t *testing.T) {
	result := LocalGenerateIDevIDCSRResult{
		CSR:       []byte{0x01},
		CSRFormat: "pkcs10",
		KeyID:     "k1",
		Backend:   "tpm2",
		Algorithm: "ES256",
		PublicKey: []byte{0x02},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"csr", "csrFormat", "keyId", "backend", "algorithm", "publicKey"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q to be present", field)
	}
}

func TestLocalStoreIDevIDCertificateParams_JSONRoundTrip(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		original := &LocalStoreIDevIDCertificateParams{
			Certificate: []byte{0x30, 0x82, 0x01, 0x00},
			Chain: [][]byte{
				{0x30, 0x82, 0x02, 0x00}, // intermediate
				{0x30, 0x82, 0x03, 0x00}, // root
			},
			KeyID:   "idevid-key-001",
			Backend: "tpm2",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalStoreIDevIDCertificateParams
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Certificate, decoded.Certificate)
		require.Len(t, decoded.Chain, 2)
		assert.Equal(t, original.Chain[0], decoded.Chain[0])
		assert.Equal(t, original.Chain[1], decoded.Chain[1])
		assert.Equal(t, original.KeyID, decoded.KeyID)
		assert.Equal(t, original.Backend, decoded.Backend)
	})

	t.Run("without chain", func(t *testing.T) {
		original := &LocalStoreIDevIDCertificateParams{
			Certificate: []byte{0x30, 0x82},
			KeyID:       "key1",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "chain")
		assert.NotContains(t, raw, "backend")
	})
}

func TestLocalStoreIDevIDCertificateParams_JSONFieldNames(t *testing.T) {
	params := LocalStoreIDevIDCertificateParams{
		Certificate: []byte{0x01},
		Chain:       [][]byte{{0x02}},
		KeyID:       "k1",
		Backend:     "tpm2",
	}

	data, err := json.Marshal(params)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"certificate", "chain", "keyId", "backend"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q to be present", field)
	}
}

func TestLocalStoreIDevIDCertificateResult_JSONRoundTrip(t *testing.T) {
	t.Run("successfully stored", func(t *testing.T) {
		original := &LocalStoreIDevIDCertificateResult{
			Stored: true,
			CertificateInfo: &IDevIDCertificateInfo{
				SerialNumber: "STORED001",
				Subject:      "CN=Device",
				NotBefore:    1700000000,
				NotAfter:     1731536000,
			},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalStoreIDevIDCertificateResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.True(t, decoded.Stored)
		require.NotNil(t, decoded.CertificateInfo)
		assert.Equal(t, "STORED001", decoded.CertificateInfo.SerialNumber)
	})

	t.Run("not stored", func(t *testing.T) {
		original := &LocalStoreIDevIDCertificateResult{
			Stored: false,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded LocalStoreIDevIDCertificateResult
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.False(t, decoded.Stored)
		assert.Nil(t, decoded.CertificateInfo)
	})
}

func TestLocalStoreIDevIDCertificateResult_JSONFieldNames(t *testing.T) {
	result := LocalStoreIDevIDCertificateResult{
		Stored:          true,
		CertificateInfo: &IDevIDCertificateInfo{SerialNumber: "SN"},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{"stored", "certificateInfo"}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q to be present", field)
	}
}

func TestIDevIDCertificateInfo_JSONRoundTrip(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		original := &IDevIDCertificateInfo{
			SerialNumber:       "ABCDEF123456",
			Issuer:             "CN=Test CA,O=Test Org",
			Subject:            "CN=Device001,O=Test Org",
			NotBefore:          1700000000,
			NotAfter:           1731536000,
			Algorithm:          "ECDSA-SHA256",
			PublicKeyAlgorithm: "ECDSA",
			KeySizeBits:        256,
			Fingerprint:        "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
			IsCA:               false,
			KeyUsage:           []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsage:        []string{"clientAuth", "serverAuth"},
			HardwareSerial:     "HW-DEVICE-001",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded IDevIDCertificateInfo
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.SerialNumber, decoded.SerialNumber)
		assert.Equal(t, original.Issuer, decoded.Issuer)
		assert.Equal(t, original.Subject, decoded.Subject)
		assert.Equal(t, original.NotBefore, decoded.NotBefore)
		assert.Equal(t, original.NotAfter, decoded.NotAfter)
		assert.Equal(t, original.Algorithm, decoded.Algorithm)
		assert.Equal(t, original.PublicKeyAlgorithm, decoded.PublicKeyAlgorithm)
		assert.Equal(t, original.KeySizeBits, decoded.KeySizeBits)
		assert.Equal(t, original.Fingerprint, decoded.Fingerprint)
		assert.Equal(t, original.IsCA, decoded.IsCA)
		assert.Equal(t, original.KeyUsage, decoded.KeyUsage)
		assert.Equal(t, original.ExtKeyUsage, decoded.ExtKeyUsage)
		assert.Equal(t, original.HardwareSerial, decoded.HardwareSerial)
	})

	t.Run("CA certificate", func(t *testing.T) {
		original := &IDevIDCertificateInfo{
			SerialNumber:       "CA001",
			Issuer:             "CN=Root CA",
			Subject:            "CN=Root CA",
			NotBefore:          1700000000,
			NotAfter:           1731536000,
			Algorithm:          "RSA-SHA256",
			PublicKeyAlgorithm: "RSA",
			KeySizeBits:        4096,
			Fingerprint:        "fingerprint-hash",
			IsCA:               true,
			KeyUsage:           []string{"keyCertSign", "cRLSign"},
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded IDevIDCertificateInfo
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.True(t, decoded.IsCA)
		assert.Equal(t, 4096, decoded.KeySizeBits)
		assert.Contains(t, decoded.KeyUsage, "keyCertSign")
	})

	t.Run("minimal fields", func(t *testing.T) {
		original := &IDevIDCertificateInfo{
			SerialNumber: "SN",
			Issuer:       "Issuer",
			Subject:      "Subject",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		// Fields without omitempty are always present.
		assert.Contains(t, raw, "serialNumber")
		assert.Contains(t, raw, "issuer")
		assert.Contains(t, raw, "subject")
		// These should be present but with zero values.
		assert.Contains(t, raw, "notBefore")
		assert.Contains(t, raw, "notAfter")
		// Optional fields should be omitted.
		assert.NotContains(t, raw, "keyUsage")
		assert.NotContains(t, raw, "extKeyUsage")
		assert.NotContains(t, raw, "hardwareSerial")
	})
}

func TestIDevIDCertificateInfo_JSONFieldNames(t *testing.T) {
	info := IDevIDCertificateInfo{
		SerialNumber:       "SN",
		Issuer:             "Issuer",
		Subject:            "Subject",
		NotBefore:          1700000000,
		NotAfter:           1731536000,
		Algorithm:          "ECDSA-SHA256",
		PublicKeyAlgorithm: "ECDSA",
		KeySizeBits:        256,
		Fingerprint:        "fp",
		IsCA:               true,
		KeyUsage:           []string{"sign"},
		ExtKeyUsage:        []string{"client"},
		HardwareSerial:     "HW",
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"serialNumber", "issuer", "subject", "notBefore", "notAfter",
		"algorithm", "publicKeyAlgorithm", "keySizeBits", "fingerprint",
		"isCa", "keyUsage", "extKeyUsage", "hardwareSerial",
	}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q to be present", field)
	}
}

func TestIDevIDSubject_JSONRoundTrip(t *testing.T) {
	t.Run("all fields set", func(t *testing.T) {
		original := &IDevIDSubject{
			CommonName:         "Device-001",
			Organization:       "Test Organization",
			OrganizationalUnit: "IT Security",
			SerialNumber:       "HW-SERIAL-12345",
			Country:            "US",
			Locality:           "San Francisco",
			Province:           "California",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var decoded IDevIDSubject
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.CommonName, decoded.CommonName)
		assert.Equal(t, original.Organization, decoded.Organization)
		assert.Equal(t, original.OrganizationalUnit, decoded.OrganizationalUnit)
		assert.Equal(t, original.SerialNumber, decoded.SerialNumber)
		assert.Equal(t, original.Country, decoded.Country)
		assert.Equal(t, original.Locality, decoded.Locality)
		assert.Equal(t, original.Province, decoded.Province)
	})

	t.Run("minimal fields", func(t *testing.T) {
		original := &IDevIDSubject{
			CommonName: "Device-001",
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.Contains(t, raw, "commonName")
		assert.NotContains(t, raw, "organization")
		assert.NotContains(t, raw, "organizationalUnit")
		assert.NotContains(t, raw, "serialNumber")
		assert.NotContains(t, raw, "country")
		assert.NotContains(t, raw, "locality")
		assert.NotContains(t, raw, "province")
	})

	t.Run("empty subject", func(t *testing.T) {
		original := &IDevIDSubject{}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		// All fields have omitempty, so empty struct produces {}.
		assert.Empty(t, raw)
	})
}

func TestIDevIDSubject_JSONFieldNames(t *testing.T) {
	subject := IDevIDSubject{
		CommonName:         "CN",
		Organization:       "O",
		OrganizationalUnit: "OU",
		SerialNumber:       "SN",
		Country:            "C",
		Locality:           "L",
		Province:           "ST",
	}

	data, err := json.Marshal(subject)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	expectedFields := []string{
		"commonName", "organization", "organizationalUnit",
		"serialNumber", "country", "locality", "province",
	}
	for _, field := range expectedFields {
		assert.Contains(t, raw, field, "expected JSON field %q to be present", field)
	}
}

func TestIDevIDTypes_ZeroValues(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
	}{
		{"LocalGetCABundleParams", &LocalGetCABundleParams{}},
		{"LocalGetCABundleResult", &LocalGetCABundleResult{}},
		{"LocalGetIDevIDCertificateParams", &LocalGetIDevIDCertificateParams{}},
		{"LocalGetIDevIDCertificateResult", &LocalGetIDevIDCertificateResult{}},
		{"LocalRequestIDevIDIssuanceParams", &LocalRequestIDevIDIssuanceParams{}},
		{"LocalRequestIDevIDIssuanceResult", &LocalRequestIDevIDIssuanceResult{}},
		{"LocalGenerateIDevIDCSRParams", &LocalGenerateIDevIDCSRParams{}},
		{"LocalGenerateIDevIDCSRResult", &LocalGenerateIDevIDCSRResult{}},
		{"LocalStoreIDevIDCertificateParams", &LocalStoreIDevIDCertificateParams{}},
		{"LocalStoreIDevIDCertificateResult", &LocalStoreIDevIDCertificateResult{}},
		{"IDevIDCertificateInfo", &IDevIDCertificateInfo{}},
		{"IDevIDSubject", &IDevIDSubject{}},
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

func TestIDevIDTypes_NilFields(t *testing.T) {
	t.Run("LocalGetIDevIDCertificateResult with nil CertificateInfo", func(t *testing.T) {
		original := &LocalGetIDevIDCertificateResult{
			HasCertificate:   false,
			CertificateChain: nil,
			CertificateInfo:  nil,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "certificateChain")
		assert.NotContains(t, raw, "certificateInfo")
	})

	t.Run("LocalGenerateIDevIDCSRParams with nil Subject", func(t *testing.T) {
		original := &LocalGenerateIDevIDCSRParams{
			Algorithm: "ES256",
			Subject:   nil,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "subject")
	})

	t.Run("LocalRequestIDevIDIssuanceResult with nil CertificateInfo", func(t *testing.T) {
		original := &LocalRequestIDevIDIssuanceResult{
			Issued:          false,
			CertificateInfo: nil,
		}

		data, err := json.Marshal(original)
		require.NoError(t, err)

		var raw map[string]interface{}
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err)

		assert.NotContains(t, raw, "certificateInfo")
	})
}

func TestNewRequest_IDevIDMethods(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params interface{}
	}{
		{
			name:   "local.getCABundle",
			method: MethodLocalGetCABundle,
			params: &LocalGetCABundleParams{
				IncludeRoot: true,
				Format:      "pem",
			},
		},
		{
			name:   "local.getIDevIDCertificate",
			method: MethodLocalGetIDevIDCertificate,
			params: &LocalGetIDevIDCertificateParams{
				Nonce: []byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name:   "local.requestIDevIDIssuance",
			method: MethodLocalRequestIDevIDIssuance,
			params: &LocalRequestIDevIDIssuanceParams{
				CSR:          []byte{0x30, 0x82},
				CSRFormat:    "pkcs10",
				ValidityDays: 365,
			},
		},
		{
			name:   "local.generateIDevIDCSR",
			method: MethodLocalGenerateIDevIDCSR,
			params: &LocalGenerateIDevIDCSRParams{
				Backend:   "tpm2",
				Algorithm: "ES256",
				Subject: &IDevIDSubject{
					CommonName:   "Device001",
					Organization: "Test Org",
				},
			},
		},
		{
			name:   "local.storeIDevIDCertificate",
			method: MethodLocalStoreIDevIDCertificate,
			params: &LocalStoreIDevIDCertificateParams{
				Certificate: []byte{0x30, 0x82},
				KeyID:       "key1",
				Backend:     "tpm2",
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

func TestDecodeResult_IDevIDResults(t *testing.T) {
	t.Run("LocalGetCABundleResult", func(t *testing.T) {
		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      200,
			Result: json.RawMessage(`{
				"bundlePem": "LS0tLS1CRUdJTi==",
				"certificates": ["MIIB"],
				"count": 1,
				"rootSubject": "CN=Root CA"
			}`),
		}

		result, err := DecodeResult[LocalGetCABundleResult](resp)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, 1, result.Count)
		assert.Equal(t, "CN=Root CA", result.RootSubject)
	})

	t.Run("LocalGetIDevIDCertificateResult", func(t *testing.T) {
		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      201,
			Result: json.RawMessage(`{
				"hasCertificate": true,
				"certificateChain": ["AQID", "BAUG"],
				"certificateInfo": {
					"serialNumber": "SN001",
					"issuer": "CN=CA",
					"subject": "CN=Device"
				}
			}`),
		}

		result, err := DecodeResult[LocalGetIDevIDCertificateResult](resp)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.HasCertificate)
		require.Len(t, result.CertificateChain, 2)
		require.NotNil(t, result.CertificateInfo)
		assert.Equal(t, "SN001", result.CertificateInfo.SerialNumber)
	})

	t.Run("LocalRequestIDevIDIssuanceResult", func(t *testing.T) {
		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      202,
			Result: json.RawMessage(`{
				"issued": true,
				"certificate": "AQID",
				"certificateChain": ["AQID", "BAUG", "BwgJ"]
			}`),
		}

		result, err := DecodeResult[LocalRequestIDevIDIssuanceResult](resp)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Issued)
		assert.Equal(t, []byte{0x01, 0x02, 0x03}, result.Certificate)
		require.Len(t, result.CertificateChain, 3)
	})

	t.Run("LocalGenerateIDevIDCSRResult", func(t *testing.T) {
		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      203,
			Result: json.RawMessage(`{
				"csr": "AQID",
				"csrFormat": "pkcs10",
				"keyId": "key-001",
				"backend": "tpm2",
				"algorithm": "ES256"
			}`),
		}

		result, err := DecodeResult[LocalGenerateIDevIDCSRResult](resp)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, []byte{0x01, 0x02, 0x03}, result.CSR)
		assert.Equal(t, "pkcs10", result.CSRFormat)
		assert.Equal(t, "key-001", result.KeyID)
		assert.Equal(t, "tpm2", result.Backend)
		assert.Equal(t, "ES256", result.Algorithm)
	})

	t.Run("LocalStoreIDevIDCertificateResult", func(t *testing.T) {
		resp := &Response{
			JSONRPC: JSONRPCVersion,
			ID:      204,
			Result:  json.RawMessage(`{"stored": true}`),
		}

		result, err := DecodeResult[LocalStoreIDevIDCertificateResult](resp)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, result.Stored)
	})
}

func TestDecodeResult_IDevIDResultWithRPCError(t *testing.T) {
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		ID:      205,
		Error: &RPCError{
			Code:    ErrorCodeInvalidParams,
			Message: "invalid CSR format",
		},
	}

	result, err := DecodeResult[LocalRequestIDevIDIssuanceResult](resp)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "invalid CSR format", err.Error())
}

func TestIDevIDMethodNamesMapContainsAllMethods(t *testing.T) {
	// Verify the idevidMethodNames map contains exactly the expected methods.
	expectedMethods := []string{
		MethodLocalGetCABundle,
		MethodLocalGetIDevIDCertificate,
		MethodLocalRequestIDevIDIssuance,
		MethodLocalGenerateIDevIDCSR,
		MethodLocalStoreIDevIDCertificate,
	}

	for _, method := range expectedMethods {
		assert.True(t, IsIDevIDMethod(method), "expected idevidMethodNames to contain %q", method)
	}

	// Verify the count matches.
	count := 0
	for _, method := range expectedMethods {
		if IsIDevIDMethod(method) {
			count++
		}
	}
	assert.Equal(t, 5, count, "expected exactly 5 IDevID methods")
}

func TestIDevIDCertificateInfo_KeyUsageVariations(t *testing.T) {
	tests := []struct {
		name        string
		keyUsage    []string
		extKeyUsage []string
	}{
		{
			name:        "digital signature only",
			keyUsage:    []string{"digitalSignature"},
			extKeyUsage: nil,
		},
		{
			name:        "CA certificate",
			keyUsage:    []string{"keyCertSign", "cRLSign"},
			extKeyUsage: nil,
		},
		{
			name:        "TLS client",
			keyUsage:    []string{"digitalSignature", "keyEncipherment"},
			extKeyUsage: []string{"clientAuth"},
		},
		{
			name:        "TLS server",
			keyUsage:    []string{"digitalSignature", "keyEncipherment"},
			extKeyUsage: []string{"serverAuth"},
		},
		{
			name:        "code signing",
			keyUsage:    []string{"digitalSignature"},
			extKeyUsage: []string{"codeSigning"},
		},
		{
			name:        "multiple ext key usage",
			keyUsage:    []string{"digitalSignature"},
			extKeyUsage: []string{"clientAuth", "serverAuth", "emailProtection"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := &IDevIDCertificateInfo{
				SerialNumber: "SN",
				Issuer:       "CN=CA",
				Subject:      "CN=Device",
				KeyUsage:     tt.keyUsage,
				ExtKeyUsage:  tt.extKeyUsage,
			}

			data, err := json.Marshal(original)
			require.NoError(t, err)

			var decoded IDevIDCertificateInfo
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.keyUsage, decoded.KeyUsage)
			assert.Equal(t, tt.extKeyUsage, decoded.ExtKeyUsage)
		})
	}
}

func TestIDevIDCertificateInfo_AlgorithmVariations(t *testing.T) {
	tests := []struct {
		name               string
		algorithm          string
		publicKeyAlgorithm string
		keySizeBits        int
	}{
		{"ECDSA P-256", "ECDSA-SHA256", "ECDSA", 256},
		{"ECDSA P-384", "ECDSA-SHA384", "ECDSA", 384},
		{"ECDSA P-521", "ECDSA-SHA512", "ECDSA", 521},
		{"RSA 2048", "RSA-SHA256", "RSA", 2048},
		{"RSA 3072", "RSA-SHA256", "RSA", 3072},
		{"RSA 4096", "RSA-SHA384", "RSA", 4096},
		{"Ed25519", "Ed25519", "Ed25519", 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := &IDevIDCertificateInfo{
				SerialNumber:       "SN",
				Issuer:             "CN=CA",
				Subject:            "CN=Device",
				Algorithm:          tt.algorithm,
				PublicKeyAlgorithm: tt.publicKeyAlgorithm,
				KeySizeBits:        tt.keySizeBits,
			}

			data, err := json.Marshal(original)
			require.NoError(t, err)

			var decoded IDevIDCertificateInfo
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.algorithm, decoded.Algorithm)
			assert.Equal(t, tt.publicKeyAlgorithm, decoded.PublicKeyAlgorithm)
			assert.Equal(t, tt.keySizeBits, decoded.KeySizeBits)
		})
	}
}

func TestLocalGenerateIDevIDCSRParams_AlgorithmVariations(t *testing.T) {
	algorithms := []string{
		"ES256",
		"ES384",
		"ES512",
		"RS2048",
		"RS3072",
		"RS4096",
	}

	for _, algo := range algorithms {
		t.Run(algo, func(t *testing.T) {
			original := &LocalGenerateIDevIDCSRParams{
				Algorithm: algo,
				Backend:   "tpm2",
			}

			data, err := json.Marshal(original)
			require.NoError(t, err)

			var decoded LocalGenerateIDevIDCSRParams
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, algo, decoded.Algorithm)
		})
	}
}

func TestLocalRequestIDevIDIssuanceParams_ValidityDaysVariations(t *testing.T) {
	validityOptions := []int{
		30,   // 1 month
		90,   // 3 months
		365,  // 1 year
		730,  // 2 years
		1095, // 3 years
		3650, // 10 years
	}

	for _, days := range validityOptions {
		t.Run("validity_"+string(rune(days)), func(t *testing.T) {
			original := &LocalRequestIDevIDIssuanceParams{
				CSR:          []byte{0x30, 0x82},
				ValidityDays: days,
			}

			data, err := json.Marshal(original)
			require.NoError(t, err)

			var decoded LocalRequestIDevIDIssuanceParams
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, days, decoded.ValidityDays)
		})
	}
}

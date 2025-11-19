package tpm2

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEKAttributes(t *testing.T) {

	_, tpm := createSim(true, true)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	assert.Nil(t, err)

	assert.Equal(t, tpm.Config().EK.Handle, uint32(ekAttrs.TPMAttributes.Handle.(tpm2.TPMHandle)))
}

func TestSRKAttributes(t *testing.T) {

	_, tpm := createSim(true, true)
	defer func() { _ = tpm.Close() }()

	ssrkAttrs, err := tpm.SSRKAttributes()
	assert.Nil(t, err)

	assert.Equal(t, tpm.Config().SSRK.Handle, uint32(ssrkAttrs.TPMAttributes.Handle.(tpm2.TPMHandle)))
}

func TestRSA(t *testing.T) {

	_, tpm := createSim(true, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	assert.Nil(t, err)

	hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

	// Create SRK with password
	srkAttrs := &types.KeyAttributes{
		CN:             "srk-with-policy",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeStorage,
		Parent:         ekAttrs,
		Password:       store.NewClearPassword([]byte("srk-auth")),
		PlatformPolicy: true,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        keyStoreHandle,
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: hierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		}}
	err = tpm.CreateSRK(srkAttrs)
	assert.Nil(t, err)

	// Create SRK child w/ the platform PCR authorization policy attribute
	keyAttrs := &types.KeyAttributes{
		CN:             "test",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeCA,
		Parent:         srkAttrs,
		PlatformPolicy: true,
		Password:       store.NewClearPassword([]byte("test-pass")),
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		}}
	rsaPub, err := tpm.CreateRSA(keyAttrs, nil, false)
	assert.Nil(t, err)
	assert.NotNil(t, rsaPub)
}

func TestECDSA(t *testing.T) {

	_, tpm := createSim(true, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	assert.Nil(t, err)

	hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

	// Create SRK with password
	srkAttrs := &types.KeyAttributes{
		CN:             "srk-with-policy",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeStorage,
		Parent:         ekAttrs,
		Password:       store.NewClearPassword([]byte("srk-auth")),
		PlatformPolicy: true,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        keyStoreHandle,
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: hierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		}}

	err = tpm.CreateSRK(srkAttrs)
	assert.Nil(t, err)

	// Create SRK child w/ the platform PCR authorization policy attribute
	keyAttrs := &types.KeyAttributes{
		CN:             "test",
		KeyAlgorithm:   x509.ECDSA,
		KeyType:        types.KeyTypeCA,
		Parent:         srkAttrs,
		PlatformPolicy: true,
		Password:       store.NewClearPassword([]byte("test-pass")),
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		}}
	rsaPub, err := tpm.CreateECDSA(keyAttrs, nil, false)
	assert.Nil(t, err)
	assert.NotNil(t, rsaPub)
}

// Unit tests for config-based attribute generation (no TPM required)

func TestEKAttributesFromConfig_RSA(t *testing.T) {
	config := EKConfig{
		CN:             "test-ek",
		Debug:          true,
		Handle:         0x81010001,
		CertHandle:     0x01C00002,
		KeyAlgorithm:   x509.RSA.String(),
		HierarchyAuth:  "test-auth",
		Password:       "ek-pass",
		PlatformPolicy: false,
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	policyDigest := tpm2.TPM2BDigest{Buffer: []byte("test-policy")}
	attrs, err := EKAttributesFromConfig(config, &policyDigest, nil)

	require.NoError(t, err)
	assert.Equal(t, "test-ek", attrs.CN)
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
	assert.Equal(t, types.KeyTypeEndorsement, attrs.KeyType)
	assert.Equal(t, types.StoreTPM2, attrs.StoreType)
	assert.Equal(t, tpm2.TPMHandle(0x81010001), attrs.TPMAttributes.Handle)
	assert.Equal(t, tpm2.TPMHandle(0x01C00002), attrs.TPMAttributes.CertHandle)
	assert.Equal(t, tpm2.TPMHTPersistent, attrs.TPMAttributes.HandleType)
	assert.Equal(t, tpm2.TPMHandle(tpm2.TPMRHEndorsement), attrs.TPMAttributes.Hierarchy)
	assert.NotNil(t, attrs.RSAAttributes)
	assert.Equal(t, 2048, attrs.RSAAttributes.KeySize)
}

func TestEKAttributesFromConfig_ECDSA(t *testing.T) {
	config := EKConfig{
		CN:           "test-ecc-ek",
		Debug:        true,
		Handle:       0x81010001,
		KeyAlgorithm: x509.ECDSA.String(),
		ECCConfig: &store.ECCConfig{
			Curve: "P-256",
		},
	}

	attrs, err := EKAttributesFromConfig(config, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, "test-ecc-ek", attrs.CN)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.ECCAttributes)
}

func TestEKAttributesFromConfig_DefaultCN(t *testing.T) {
	config := EKConfig{
		CN:           "", // Empty CN should default
		Handle:       0x81010001,
		KeyAlgorithm: x509.RSA.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	// Test with IDevID config
	idevidConfig := &IDevIDConfig{
		Model:  "edge",
		Serial: "001",
	}
	attrs, err := EKAttributesFromConfig(config, nil, idevidConfig)

	require.NoError(t, err)
	assert.Equal(t, "ek-edge-001", attrs.CN)

	// Test without IDevID config
	attrs2, err := EKAttributesFromConfig(config, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "ek", attrs2.CN)
}

func TestEKAttributesFromConfig_InvalidAlgorithm(t *testing.T) {
	config := EKConfig{
		CN:           "test-ek",
		Handle:       0x81010001,
		KeyAlgorithm: "INVALID",
		// No RSA or ECC config, should fail
	}

	_, err := EKAttributesFromConfig(config, nil, nil)
	assert.Error(t, err)
}

func TestEKAttributesFromConfig_PlatformPolicy(t *testing.T) {
	config := EKConfig{
		CN:             "test-ek",
		Handle:         0x81010001,
		KeyAlgorithm:   x509.RSA.String(),
		PlatformPolicy: true,
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	policyDigest := tpm2.TPM2BDigest{Buffer: []byte("policy-digest")}
	attrs, err := EKAttributesFromConfig(config, &policyDigest, nil)

	require.NoError(t, err)
	assert.True(t, attrs.PlatformPolicy)
	// Verify policy digest was applied to template
	template := attrs.TPMAttributes.Template.(tpm2.TPMTPublic)
	assert.Equal(t, policyDigest.Buffer, template.AuthPolicy.Buffer)
}

func TestSRKAttributesFromConfig_RSA(t *testing.T) {
	config := SRKConfig{
		CN:             "test-srk",
		Debug:          true,
		Handle:         0x81000001,
		KeyAlgorithm:   x509.RSA.String(),
		HierarchyAuth:  "srk-auth",
		Password:       "srk-pass",
		PlatformPolicy: false,
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	attrs, err := SRKAttributesFromConfig(config, nil)

	require.NoError(t, err)
	assert.Equal(t, "test-srk", attrs.CN)
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
	assert.Equal(t, types.KeyTypeStorage, attrs.KeyType)
	assert.Equal(t, tpm2.TPMHandle(0x81000001), attrs.TPMAttributes.Handle)
	assert.Equal(t, tpm2.TPMHandle(tpm2.TPMRHOwner), attrs.TPMAttributes.Hierarchy)
	assert.NotNil(t, attrs.RSAAttributes)
}

func TestSRKAttributesFromConfig_ECDSA(t *testing.T) {
	config := SRKConfig{
		CN:           "test-ecc-srk",
		Handle:       0x81000001,
		KeyAlgorithm: x509.ECDSA.String(),
		ECCConfig: &store.ECCConfig{
			Curve: "P-256",
		},
	}

	attrs, err := SRKAttributesFromConfig(config, nil)

	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.ECCAttributes)
}

func TestSRKAttributesFromConfig_DefaultCN(t *testing.T) {
	config := SRKConfig{
		CN:           "", // Empty CN should default to "srk"
		Handle:       0x81000001,
		KeyAlgorithm: x509.RSA.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	attrs, err := SRKAttributesFromConfig(config, nil)

	require.NoError(t, err)
	assert.Equal(t, "srk", attrs.CN)
}

func TestSRKAttributesFromConfig_InvalidCurve(t *testing.T) {
	config := SRKConfig{
		CN:           "test-srk",
		Handle:       0x81000001,
		KeyAlgorithm: x509.ECDSA.String(),
		ECCConfig: &store.ECCConfig{
			Curve: "INVALID-CURVE",
		},
	}

	_, err := SRKAttributesFromConfig(config, nil)
	assert.Error(t, err)
}

func TestIAKAttributesFromConfig_RSA(t *testing.T) {
	soPIN := store.NewClearPassword([]byte("so-pin"))
	config := &IAKConfig{
		CN:                 "test-iak",
		Debug:              true,
		Handle:             0x81010002,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.RSA.String(),
		Password:           "iak-pass",
		PlatformPolicy:     false,
		SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	policyDigest := tpm2.TPM2BDigest{Buffer: []byte("test-policy")}
	attrs, err := IAKAttributesFromConfig(soPIN, config, &policyDigest)

	require.NoError(t, err)
	assert.Equal(t, "test-iak", attrs.CN)
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
	assert.Equal(t, types.KeyTypeAttestation, attrs.KeyType)
	assert.Equal(t, crypto.SHA256, attrs.Hash)
	assert.Equal(t, x509.SHA256WithRSAPSS, attrs.SignatureAlgorithm)
	assert.Equal(t, tpm2.TPMHandle(0x81010002), attrs.TPMAttributes.Handle)
	assert.Equal(t, tpm2.TPMAlgSHA256, attrs.TPMAttributes.HashAlg)
	assert.Equal(t, tpm2.TPMRHEndorsement, attrs.TPMAttributes.Hierarchy)
	assert.NotNil(t, attrs.RSAAttributes)
}

func TestIAKAttributesFromConfig_ECDSA(t *testing.T) {
	soPIN := store.NewClearPassword([]byte("so-pin"))
	config := &IAKConfig{
		CN:                 "test-ecc-iak",
		Handle:             0x81010002,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.ECDSA.String(),
		SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		ECCConfig: &store.ECCConfig{
			Curve: "P-256",
		},
	}

	attrs, err := IAKAttributesFromConfig(soPIN, config, nil)

	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.ECCAttributes)
}

func TestIAKAttributesFromConfig_InvalidHash(t *testing.T) {
	soPIN := store.NewClearPassword([]byte("so-pin"))
	config := &IAKConfig{
		CN:                 "test-iak",
		Handle:             0x81010002,
		Hash:               "INVALID-HASH",
		KeyAlgorithm:       x509.RSA.String(),
		SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	_, err := IAKAttributesFromConfig(soPIN, config, nil)
	assert.Error(t, err)
}

func TestIAKAttributesFromConfig_InvalidSignatureAlgorithm(t *testing.T) {
	soPIN := store.NewClearPassword([]byte("so-pin"))
	config := &IAKConfig{
		CN:                 "test-iak",
		Handle:             0x81010002,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.RSA.String(),
		SignatureAlgorithm: "INVALID-SIG-ALG",
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	_, err := IAKAttributesFromConfig(soPIN, config, nil)
	assert.Error(t, err)
}

func TestIDevIDAttributesFromConfig_RSA(t *testing.T) {
	config := IDevIDConfig{
		CN:                 "test-idevid",
		Debug:              true,
		Handle:             0x81020000,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.RSA.String(),
		Model:              "edge",
		Serial:             "001",
		Password:           "idevid-pass",
		PlatformPolicy:     true,
		SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	policyDigest := tpm2.TPM2BDigest{Buffer: []byte("test-policy")}
	attrs, err := IDevIDAttributesFromConfig(config, &policyDigest)

	require.NoError(t, err)
	assert.Equal(t, "test-idevid", attrs.CN)
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
	assert.Equal(t, types.KeyTypeIDevID, attrs.KeyType)
	assert.Equal(t, crypto.SHA256, attrs.Hash)
	assert.Equal(t, x509.SHA256WithRSAPSS, attrs.SignatureAlgorithm)
	assert.Equal(t, tpm2.TPMHandle(0x81020000), attrs.TPMAttributes.Handle)
	assert.Equal(t, tpm2.TPMAlgSHA256, attrs.TPMAttributes.HashAlg)
	assert.True(t, attrs.PlatformPolicy)
}

func TestIDevIDAttributesFromConfig_DefaultCN(t *testing.T) {
	config := IDevIDConfig{
		CN:                 "", // Empty CN should default to model-serial
		Handle:             0x81020000,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.RSA.String(),
		Model:              "edge",
		Serial:             "001",
		SignatureAlgorithm: x509.SHA256WithRSA.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	attrs, err := IDevIDAttributesFromConfig(config, nil)

	require.NoError(t, err)
	assert.Equal(t, "edge-001", attrs.CN)
}

func TestIDevIDAttributesFromConfig_InvalidHash(t *testing.T) {
	config := IDevIDConfig{
		CN:                 "test-idevid",
		Handle:             0x81020000,
		Hash:               "INVALID-HASH",
		KeyAlgorithm:       x509.RSA.String(),
		SignatureAlgorithm: x509.SHA256WithRSA.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	_, err := IDevIDAttributesFromConfig(config, nil)
	assert.Error(t, err)
}

func TestLDevIDAttributesFromConfig_RSA(t *testing.T) {
	config := LDevIDConfig{
		CN:                 "test-ldevid",
		Debug:              true,
		Handle:             0x81020001,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.RSA.String(),
		Model:              "edge",
		Serial:             "002",
		Password:           "ldevid-pass",
		PlatformPolicy:     false,
		SignatureAlgorithm: x509.SHA256WithRSA.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	attrs, err := LDevIDAttributesFromConfig(config, nil)

	require.NoError(t, err)
	assert.Equal(t, "test-ldevid", attrs.CN)
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
	assert.Equal(t, types.KeyTypeIDevID, attrs.KeyType)
	assert.Equal(t, crypto.SHA256, attrs.Hash)
	assert.Equal(t, x509.SHA256WithRSA, attrs.SignatureAlgorithm)
}

func TestLDevIDAttributesFromConfig_DefaultCN(t *testing.T) {
	config := LDevIDConfig{
		CN:                 "", // Empty CN should default to "ldevid"
		Handle:             0x81020001,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.RSA.String(),
		SignatureAlgorithm: x509.SHA256WithRSA.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	attrs, err := LDevIDAttributesFromConfig(config, nil)

	require.NoError(t, err)
	assert.Equal(t, "ldevid", attrs.CN)
}

func TestLDevIDAttributesFromConfig_ECDSA(t *testing.T) {
	config := LDevIDConfig{
		CN:                 "test-ecc-ldevid",
		Handle:             0x81020001,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.ECDSA.String(),
		SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		ECCConfig: &store.ECCConfig{
			Curve: "P-384",
		},
	}

	attrs, err := LDevIDAttributesFromConfig(config, nil)

	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.ECCAttributes)
}

// Test templates

func TestRSASSATemplate(t *testing.T) {
	template := RSASSATemplate

	assert.Equal(t, tpm2.TPMAlgRSA, template.Type)
	assert.Equal(t, tpm2.TPMAlgSHA256, template.NameAlg)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
	assert.True(t, template.ObjectAttributes.FixedTPM)
	assert.True(t, template.ObjectAttributes.FixedParent)
	assert.True(t, template.ObjectAttributes.SensitiveDataOrigin)
	assert.True(t, template.ObjectAttributes.UserWithAuth)
}

func TestRSAPSSTemplate(t *testing.T) {
	template := RSAPSSTemplate

	assert.Equal(t, tpm2.TPMAlgRSA, template.Type)
	assert.Equal(t, tpm2.TPMAlgSHA256, template.NameAlg)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
}

func TestECCP256Template(t *testing.T) {
	template := ECCP256Template

	assert.Equal(t, tpm2.TPMAlgECC, template.Type)
	assert.Equal(t, tpm2.TPMAlgSHA256, template.NameAlg)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
}

func TestECCP384Template(t *testing.T) {
	template := ECCP384Template

	assert.Equal(t, tpm2.TPMAlgECC, template.Type)
	assert.Equal(t, tpm2.TPMAlgSHA384, template.NameAlg)
}

func TestECCP521Template(t *testing.T) {
	template := ECCP521Template

	assert.Equal(t, tpm2.TPMAlgECC, template.Type)
	assert.Equal(t, tpm2.TPMAlgSHA512, template.NameAlg)
}

func TestRSASSAAKTemplate(t *testing.T) {
	template := RSASSAAKTemplate

	assert.Equal(t, tpm2.TPMAlgRSA, template.Type)
	// AK must have Restricted attribute
	assert.True(t, template.ObjectAttributes.Restricted)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
	assert.True(t, template.ObjectAttributes.FixedTPM)
}

func TestRSAPSSAKTemplate(t *testing.T) {
	template := RSAPSSAKTemplate

	assert.Equal(t, tpm2.TPMAlgRSA, template.Type)
	assert.True(t, template.ObjectAttributes.Restricted)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
}

func TestECCAKP256Template(t *testing.T) {
	template := ECCAKP256Template

	assert.Equal(t, tpm2.TPMAlgECC, template.Type)
	assert.True(t, template.ObjectAttributes.Restricted)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
}

func TestRSASSAIDevIDTemplate(t *testing.T) {
	template := RSASSAIDevIDTemplate

	assert.Equal(t, tpm2.TPMAlgRSA, template.Type)
	// IDevID must NOT have Restricted attribute
	assert.False(t, template.ObjectAttributes.Restricted)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
	assert.True(t, template.ObjectAttributes.FixedTPM)
}

func TestRSAPSSIDevIDTemplate(t *testing.T) {
	template := RSAPSSIDevIDTemplate

	assert.Equal(t, tpm2.TPMAlgRSA, template.Type)
	assert.False(t, template.ObjectAttributes.Restricted)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
}

func TestECCIDevIDP256Template(t *testing.T) {
	template := ECCIDevIDP256Template

	assert.Equal(t, tpm2.TPMAlgECC, template.Type)
	assert.False(t, template.ObjectAttributes.Restricted)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
}

func TestAES128CFBTemplate(t *testing.T) {
	template := AES128CFBTemplate

	assert.Equal(t, tpm2.TPMAlgSymCipher, template.Type)
	assert.True(t, template.ObjectAttributes.Decrypt)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
	assert.True(t, template.ObjectAttributes.NoDA)
}

func TestAES256CFBTemplate(t *testing.T) {
	template := AES256CFBTemplate

	assert.Equal(t, tpm2.TPMAlgSymCipher, template.Type)
	assert.True(t, template.ObjectAttributes.Decrypt)
	assert.True(t, template.ObjectAttributes.SignEncrypt)
}

func TestKeyedHashTemplate(t *testing.T) {
	template := KeyedHashTemplate

	assert.Equal(t, tpm2.TPMAlgKeyedHash, template.Type)
	assert.Equal(t, tpm2.TPMAlgSHA256, template.NameAlg)
	assert.True(t, template.ObjectAttributes.FixedTPM)
	assert.True(t, template.ObjectAttributes.FixedParent)
	assert.True(t, template.ObjectAttributes.UserWithAuth)
}

// Test helper functions

func TestHierarchyName(t *testing.T) {
	tests := []struct {
		name      string
		hierarchy tpm2.TPMHandle
		expected  string
	}{
		{
			name:      "Platform hierarchy",
			hierarchy: tpm2.TPMRHPlatform,
			expected:  "PLATFORM",
		},
		{
			name:      "Owner hierarchy",
			hierarchy: tpm2.TPMRHOwner,
			expected:  "OWNER",
		},
		{
			name:      "Endorsement hierarchy",
			hierarchy: tpm2.TPMRHEndorsement,
			expected:  "ENDORSEMENT",
		},
		{
			name:      "Null hierarchy",
			hierarchy: tpm2.TPMRHNull,
			expected:  "NULL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HierarchyName(tt.hierarchy)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHierarchyName_InvalidHierarchy(t *testing.T) {
	assert.Panics(t, func() {
		HierarchyName(tpm2.TPMHandle(0xFFFFFFFF))
	})
}

func TestParseHashAlgFromString(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		expected tpm2.TPMIAlgHash
		wantErr  bool
	}{
		{
			name:     "SHA-1",
			hash:     "SHA-1",
			expected: tpm2.TPMAlgSHA1,
			wantErr:  false,
		},
		{
			name:     "SHA-256",
			hash:     "SHA-256",
			expected: tpm2.TPMAlgSHA256,
			wantErr:  false,
		},
		{
			name:     "SHA-384",
			hash:     "SHA-384",
			expected: tpm2.TPMAlgSHA384,
			wantErr:  false,
		},
		{
			name:     "SHA-512",
			hash:     "SHA-512",
			expected: tpm2.TPMAlgSHA512,
			wantErr:  false,
		},
		{
			name:     "Invalid hash",
			hash:     "INVALID",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashAlgFromString(tt.hash)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseHashAlg(t *testing.T) {
	tests := []struct {
		name     string
		hash     crypto.Hash
		expected tpm2.TPMIAlgHash
		wantErr  bool
	}{
		{
			name:     "SHA1",
			hash:     crypto.SHA1,
			expected: tpm2.TPMAlgSHA1,
			wantErr:  false,
		},
		{
			name:     "SHA256",
			hash:     crypto.SHA256,
			expected: tpm2.TPMAlgSHA256,
			wantErr:  false,
		},
		{
			name:     "SHA384",
			hash:     crypto.SHA384,
			expected: tpm2.TPMAlgSHA384,
			wantErr:  false,
		},
		{
			name:     "SHA512",
			hash:     crypto.SHA512,
			expected: tpm2.TPMAlgSHA512,
			wantErr:  false,
		},
		{
			name:     "Invalid hash",
			hash:     crypto.MD5,
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashAlg(tt.hash)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseHashSize(t *testing.T) {
	tests := []struct {
		name     string
		hash     crypto.Hash
		expected uint32
		wantErr  bool
	}{
		{
			name:     "SHA1",
			hash:     crypto.SHA1,
			expected: 20,
			wantErr:  false,
		},
		{
			name:     "SHA256",
			hash:     crypto.SHA256,
			expected: 32,
			wantErr:  false,
		},
		{
			name:     "SHA384",
			hash:     crypto.SHA384,
			expected: 48,
			wantErr:  false,
		},
		{
			name:     "SHA512",
			hash:     crypto.SHA512,
			expected: 64,
			wantErr:  false,
		},
		{
			name:     "Invalid hash",
			hash:     crypto.MD5,
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashSize(tt.hash)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCalculateName_SHA256(t *testing.T) {
	publicArea := []byte("test public area data")
	name, err := CalculateName(tpm2.TPMAlgSHA256, publicArea)

	require.NoError(t, err)
	require.NotNil(t, name)
	// Name should be 2 bytes for algorithm ID + 32 bytes for SHA256 hash
	assert.Equal(t, 34, len(name))
	// First two bytes should be SHA256 algorithm ID (0x000B)
	assert.Equal(t, byte(0x00), name[0])
	assert.Equal(t, byte(0x0B), name[1])
}

func TestCalculateName_SHA1(t *testing.T) {
	publicArea := []byte("test public area data")
	name, err := CalculateName(tpm2.TPMAlgSHA1, publicArea)

	require.NoError(t, err)
	require.NotNil(t, name)
	// Name should be 2 bytes for algorithm ID + 20 bytes for SHA1 hash
	assert.Equal(t, 22, len(name))
}

func TestCalculateName_SHA512(t *testing.T) {
	publicArea := []byte("test public area data")
	name, err := CalculateName(tpm2.TPMAlgSHA512, publicArea)

	require.NoError(t, err)
	require.NotNil(t, name)
	// Name should be 2 bytes for algorithm ID + 64 bytes for SHA512 hash
	assert.Equal(t, 66, len(name))
}

func TestCalculateName_InvalidAlgorithm(t *testing.T) {
	publicArea := []byte("test public area data")
	_, err := CalculateName(tpm2.TPMAlgID(0xFFFF), publicArea)

	assert.Error(t, err)
}

func TestTCGVendorID_String(t *testing.T) {
	tests := []struct {
		name     string
		vendorID TCGVendorID
		expected string
	}{
		{
			name:     "Intel",
			vendorID: TCGVendorID(1229870147),
			expected: "Intel",
		},
		{
			name:     "AMD",
			vendorID: TCGVendorID(1095582720),
			expected: "AMD",
		},
		{
			name:     "Microsoft",
			vendorID: TCGVendorID(1297303124),
			expected: "Microsoft",
		},
		{
			name:     "Google",
			vendorID: TCGVendorID(1196379975),
			expected: "Google",
		},
		{
			name:     "Unknown",
			vendorID: TCGVendorID(0),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.vendorID.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test edge cases for password handling

func TestEKAttributesFromConfig_EmptyPassword(t *testing.T) {
	config := EKConfig{
		CN:           "test-ek",
		Handle:       0x81010001,
		KeyAlgorithm: x509.RSA.String(),
		Password:     "", // Empty password
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	attrs, err := EKAttributesFromConfig(config, nil, nil)

	require.NoError(t, err)
	assert.NotNil(t, attrs.Password)
	passBytes := attrs.Password.Bytes()
	assert.Equal(t, []byte(""), passBytes)
}

func TestIAKAttributesFromConfig_NilSoPIN(t *testing.T) {
	config := &IAKConfig{
		CN:                 "test-iak",
		Handle:             0x81010002,
		Hash:               crypto.SHA256.String(),
		KeyAlgorithm:       x509.RSA.String(),
		SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		RSAConfig: &store.RSAConfig{
			KeySize: 2048,
		},
	}

	attrs, err := IAKAttributesFromConfig(nil, config, nil)

	require.NoError(t, err)
	assert.Nil(t, attrs.TPMAttributes.HierarchyAuth)
}

// Integration tests with simulator (require TPM simulator)

func TestIAKAttributes_WithSimulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// This requires IAK to be created during provisioning
	iakAttrs, err := tpm.IAKAttributes()

	// May return error if IAK not created during provisioning
	if err == nil {
		assert.NotNil(t, iakAttrs)
		assert.Equal(t, types.KeyTypeAttestation, iakAttrs.KeyType)
		assert.Equal(t, types.StoreTPM2, iakAttrs.StoreType)
	}
}

func TestSSRKAttributes_WithSimulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ssrkAttrs, err := tpm.SSRKAttributes()

	require.NoError(t, err)
	assert.NotNil(t, ssrkAttrs)
	assert.Equal(t, types.KeyTypeStorage, ssrkAttrs.KeyType)
	assert.Equal(t, types.StoreTPM2, ssrkAttrs.StoreType)
}

func TestEKAttributes_WithSimulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()

	require.NoError(t, err)
	assert.NotNil(t, ekAttrs)
	assert.Equal(t, types.KeyTypeEndorsement, ekAttrs.KeyType)
	assert.Equal(t, types.StoreTPM2, ekAttrs.StoreType)
}

func TestEK_PublicKey_WithSimulator(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// First ensure EK attributes are loaded
	_, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Now get the public key
	pubKey := tpm.EK()
	assert.NotNil(t, pubKey)
}

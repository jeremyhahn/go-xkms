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

func TestPCRBankAlgoString(t *testing.T) {
	tests := []struct {
		name     string
		algo     PCRBankAlgo
		expected string
	}{
		{
			name:     "sha1 algorithm",
			algo:     PCRBankAlgo("sha1"),
			expected: "sha1",
		},
		{
			name:     "sha256 algorithm",
			algo:     PCRBankAlgo("sha256"),
			expected: "sha256",
		},
		{
			name:     "sha384 algorithm",
			algo:     PCRBankAlgo("sha384"),
			expected: "sha384",
		},
		{
			name:     "sha512 algorithm",
			algo:     PCRBankAlgo("sha512"),
			expected: "sha512",
		},
		{
			name:     "empty string",
			algo:     PCRBankAlgo(""),
			expected: "",
		},
		{
			name:     "custom value",
			algo:     PCRBankAlgo("custom"),
			expected: "custom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.algo.String()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseHierarchyComprehensive(t *testing.T) {
	tests := []struct {
		name          string
		hierarchyType string
		expected      tpm2.TPMIRHHierarchy
		expectError   bool
	}{
		{
			name:          "endorsement hierarchy",
			hierarchyType: "ENDORSEMENT",
			expected:      tpm2.TPMRHEndorsement,
			expectError:   false,
		},
		{
			name:          "owner hierarchy",
			hierarchyType: "OWNER",
			expected:      tpm2.TPMRHOwner,
			expectError:   false,
		},
		{
			name:          "platform hierarchy",
			hierarchyType: "PLATFORM",
			expected:      tpm2.TPMRHPlatform,
			expectError:   false,
		},
		{
			name:          "lowercase endorsement fails",
			hierarchyType: "endorsement",
			expected:      0,
			expectError:   true,
		},
		{
			name:          "invalid hierarchy type",
			hierarchyType: "INVALID",
			expected:      0,
			expectError:   true,
		},
		{
			name:          "empty string",
			hierarchyType: "",
			expected:      0,
			expectError:   true,
		},
		{
			name:          "null hierarchy",
			hierarchyType: "NULL",
			expected:      0,
			expectError:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseHierarchy(tc.hierarchyType)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidHierarchyType, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseIdentityProvisioningStrategyComprehensive(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		expected EnrollmentStrategy
	}{
		{
			name:     "IAK strategy",
			strategy: string(EnrollmentStrategyIAK),
			expected: EnrollmentStrategyIAK,
		},
		{
			name:     "IAK_IDEVID_SINGLE_PASS strategy",
			strategy: string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS),
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "unknown strategy defaults to single pass",
			strategy: "unknown",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
		{
			name:     "empty string defaults to single pass",
			strategy: "",
			expected: EnrollmentStrategyIAK_IDEVID_SINGLE_PASS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tc.strategy)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParsePCRBankAlgIDComprehensive(t *testing.T) {
	tests := []struct {
		name        string
		pcrBank     string
		expected    tpm2.TPMAlgID
		expectError bool
	}{
		{
			name:        "sha1 lowercase",
			pcrBank:     "sha1",
			expected:    tpm2.TPMAlgSHA1,
			expectError: false,
		},
		{
			name:        "sha256 lowercase",
			pcrBank:     "sha256",
			expected:    tpm2.TPMAlgSHA256,
			expectError: false,
		},
		{
			name:        "sha384 lowercase",
			pcrBank:     "sha384",
			expected:    tpm2.TPMAlgSHA384,
			expectError: false,
		},
		{
			name:        "sha512 lowercase",
			pcrBank:     "sha512",
			expected:    tpm2.TPMAlgSHA512,
			expectError: false,
		},
		{
			name:        "SHA1 uppercase converts to lowercase",
			pcrBank:     "SHA1",
			expected:    tpm2.TPMAlgSHA1,
			expectError: false,
		},
		{
			name:        "SHA256 uppercase converts to lowercase",
			pcrBank:     "SHA256",
			expected:    tpm2.TPMAlgSHA256,
			expectError: false,
		},
		{
			name:        "invalid pcr bank",
			pcrBank:     "invalid",
			expected:    0,
			expectError: true,
		},
		{
			name:        "empty string",
			pcrBank:     "",
			expected:    0,
			expectError: true,
		},
		{
			name:        "sha3-256 not supported as pcr bank",
			pcrBank:     "sha3-256",
			expected:    0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParsePCRBankAlgID(tc.pcrBank)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidPCRBankType, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParsePCRBankCryptoHash(t *testing.T) {
	tests := []struct {
		name        string
		pcrBank     string
		expected    crypto.Hash
		expectError bool
	}{
		{
			name:        "sha1 maps to crypto.SHA1",
			pcrBank:     "sha1",
			expected:    crypto.SHA1,
			expectError: false,
		},
		{
			name:        "sha256 maps to crypto.SHA256",
			pcrBank:     "sha256",
			expected:    crypto.SHA256,
			expectError: false,
		},
		{
			name:        "sha384 maps to crypto.SHA3_384",
			pcrBank:     "sha384",
			expected:    crypto.SHA3_384,
			expectError: false,
		},
		{
			name:        "sha512 maps to crypto.SHA512",
			pcrBank:     "sha512",
			expected:    crypto.SHA512,
			expectError: false,
		},
		{
			name:        "uppercase SHA256 works",
			pcrBank:     "SHA256",
			expected:    crypto.SHA256,
			expectError: false,
		},
		{
			name:        "invalid bank returns error",
			pcrBank:     "invalid",
			expected:    0,
			expectError: true,
		},
		{
			name:        "empty string returns error",
			pcrBank:     "",
			expected:    0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParsePCRBankCryptoHash(tc.pcrBank)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidPCRBankType, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestParseCryptoHashAlgIDComprehensive(t *testing.T) {
	tests := []struct {
		name        string
		hash        crypto.Hash
		expected    tpm2.TPMAlgID
		expectError bool
	}{
		{
			name:        "SHA1 to TPMAlgSHA1",
			hash:        crypto.SHA1,
			expected:    tpm2.TPMAlgSHA1,
			expectError: false,
		},
		{
			name:        "SHA256 to TPMAlgSHA256",
			hash:        crypto.SHA256,
			expected:    tpm2.TPMAlgSHA256,
			expectError: false,
		},
		{
			name:        "SHA384 to TPMAlgSHA384",
			hash:        crypto.SHA384,
			expected:    tpm2.TPMAlgSHA384,
			expectError: false,
		},
		{
			name:        "SHA512 to TPMAlgSHA512",
			hash:        crypto.SHA512,
			expected:    tpm2.TPMAlgSHA512,
			expectError: false,
		},
		{
			name:        "SHA3_256 to TPMAlgSHA3256",
			hash:        crypto.SHA3_256,
			expected:    tpm2.TPMAlgSHA3256,
			expectError: false,
		},
		{
			name:        "SHA3_384 to TPMAlgSHA3384",
			hash:        crypto.SHA3_384,
			expected:    tpm2.TPMAlgSHA3384,
			expectError: false,
		},
		{
			name:        "SHA3_512 to TPMAlgSHA3512",
			hash:        crypto.SHA3_512,
			expected:    tpm2.TPMAlgSHA3512,
			expectError: false,
		},
		{
			name:        "MD5 not supported",
			hash:        crypto.MD5,
			expected:    0,
			expectError: true,
		},
		{
			name:        "invalid hash",
			hash:        crypto.Hash(0),
			expected:    0,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseCryptoHashAlgID(tc.hash)
			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, ErrInvalidCryptoHashAlgID, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestIDevIDAttributesFromConfigTableDriven(t *testing.T) {
	tests := []struct {
		name         string
		config       IDevIDConfig
		policyDigest *tpm2.TPM2BDigest
		expectError  bool
		validate     func(*testing.T, *types.KeyAttributes)
	}{
		{
			name: "valid RSA config with model and serial",
			config: IDevIDConfig{
				Model:              "device1",
				Serial:             "001",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, "device1-001", attrs.CN)
				assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
				assert.Equal(t, crypto.SHA256, attrs.Hash)
				assert.Equal(t, x509.SHA256WithRSAPSS, attrs.SignatureAlgorithm)
				assert.Equal(t, types.KeyTypeIDevID, attrs.KeyType)
				assert.Equal(t, types.StoreTPM2, attrs.StoreType)
				assert.NotNil(t, attrs.TPMAttributes)
				assert.Equal(t, tpm2.TPMHandle(0x81020000), attrs.TPMAttributes.Handle)
				assert.Equal(t, tpm2.TPMRHEndorsement, attrs.TPMAttributes.Hierarchy)
				assert.NotNil(t, attrs.RSAAttributes)
				assert.Equal(t, 2048, attrs.RSAAttributes.KeySize)
			},
		},
		{
			name: "valid config with explicit CN",
			config: IDevIDConfig{
				CN:                 "custom-cn",
				Model:              "device1",
				Serial:             "001",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, "custom-cn", attrs.CN)
			},
		},
		{
			name: "valid ECC config",
			config: IDevIDConfig{
				Model:              "device1",
				Serial:             "001",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.ECDSA.String(),
				SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
				Handle:             0x81020000,
				ECCConfig:          &store.ECCConfig{Curve: "P-256"},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
				assert.NotNil(t, attrs.ECCAttributes)
			},
		},
		{
			name: "config with platform policy",
			config: IDevIDConfig{
				Model:              "device1",
				Serial:             "001",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				PlatformPolicy:     true,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: &tpm2.TPM2BDigest{
				Buffer: []byte{0x01, 0x02, 0x03},
			},
			expectError: false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.True(t, attrs.PlatformPolicy)
			},
		},
		{
			name: "invalid hash algorithm",
			config: IDevIDConfig{
				Model:              "device1",
				Serial:             "001",
				Hash:               "INVALID-HASH",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "invalid signature algorithm",
			config: IDevIDConfig{
				Model:              "device1",
				Serial:             "001",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: "INVALID-SIG",
				Handle:             0x81020000,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "invalid key algorithm without fallback",
			config: IDevIDConfig{
				Model:              "device1",
				Serial:             "001",
				Hash:               "SHA-256",
				KeyAlgorithm:       "INVALID",
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
			},
			policyDigest: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "invalid key algorithm falls back to RSA",
			config: IDevIDConfig{
				Model:              "device1",
				Serial:             "001",
				Hash:               "SHA-256",
				KeyAlgorithm:       "INVALID",
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
			},
		},
		{
			name: "invalid ECC curve",
			config: IDevIDConfig{
				Model:              "device1",
				Serial:             "001",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.ECDSA.String(),
				SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
				Handle:             0x81020000,
				ECCConfig:          &store.ECCConfig{Curve: "INVALID"},
			},
			policyDigest: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "config with password",
			config: IDevIDConfig{
				Model:              "device1",
				Serial:             "001",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				Password:           "secret",
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.NotNil(t, attrs.Password)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := IDevIDAttributesFromConfig(tc.config, tc.policyDigest)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, attrs)
				if tc.validate != nil {
					tc.validate(t, attrs)
				}
			}
		})
	}
}

func TestLDevIDAttributesFromConfigTableDriven(t *testing.T) {
	tests := []struct {
		name         string
		config       LDevIDConfig
		policyDigest *tpm2.TPM2BDigest
		expectError  bool
		validate     func(*testing.T, *types.KeyAttributes)
	}{
		{
			name: "valid config uses default CN",
			config: LDevIDConfig{
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, "ldevid", attrs.CN)
				assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
				assert.Equal(t, types.KeyTypeIDevID, attrs.KeyType)
			},
		},
		{
			name: "valid config with explicit CN",
			config: LDevIDConfig{
				CN:                 "custom-ldevid",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, "custom-ldevid", attrs.CN)
			},
		},
		{
			name: "valid ECC config",
			config: LDevIDConfig{
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.ECDSA.String(),
				SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
				Handle:             0x81020000,
				ECCConfig:          &store.ECCConfig{Curve: "P-256"},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
				assert.NotNil(t, attrs.ECCAttributes)
			},
		},
		{
			name: "invalid hash algorithm",
			config: LDevIDConfig{
				Hash:               "INVALID",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "invalid signature algorithm",
			config: LDevIDConfig{
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: "INVALID",
				Handle:             0x81020000,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "config with platform policy",
			config: LDevIDConfig{
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				PlatformPolicy:     true,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: &tpm2.TPM2BDigest{
				Buffer: []byte{0x01, 0x02, 0x03},
			},
			expectError: false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.True(t, attrs.PlatformPolicy)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := LDevIDAttributesFromConfig(tc.config, tc.policyDigest)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, attrs)
				if tc.validate != nil {
					tc.validate(t, attrs)
				}
			}
		})
	}
}

func TestEKAttributesFromConfigTableDriven(t *testing.T) {
	tests := []struct {
		name         string
		config       EKConfig
		policyDigest *tpm2.TPM2BDigest
		idevidConfig *IDevIDConfig
		expectError  bool
		validate     func(*testing.T, *types.KeyAttributes)
	}{
		{
			name: "valid RSA config without IDevID",
			config: EKConfig{
				KeyAlgorithm:  x509.RSA.String(),
				Handle:        0x81010001,
				CertHandle:    0x01C00002,
				HierarchyAuth: "password",
				RSAConfig:     &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			idevidConfig: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, "ek", attrs.CN)
				assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
				assert.Equal(t, types.KeyTypeEndorsement, attrs.KeyType)
				assert.Equal(t, tpm2.TPMHandle(0x81010001), attrs.TPMAttributes.Handle)
				assert.Equal(t, tpm2.TPMHandle(tpm2.TPMRHEndorsement), attrs.TPMAttributes.Hierarchy)
			},
		},
		{
			name: "valid RSA config with IDevID generates CN",
			config: EKConfig{
				KeyAlgorithm:  x509.RSA.String(),
				Handle:        0x81010001,
				CertHandle:    0x01C00002,
				HierarchyAuth: "password",
				RSAConfig:     &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			idevidConfig: &IDevIDConfig{
				Model:  "model1",
				Serial: "serial1",
			},
			expectError: false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, "ek-model1-serial1", attrs.CN)
			},
		},
		{
			name: "valid ECC config",
			config: EKConfig{
				KeyAlgorithm: x509.ECDSA.String(),
				Handle:       0x81010001,
				CertHandle:   0x01C00002,
				ECCConfig:    &store.ECCConfig{Curve: "P-256"},
			},
			policyDigest: nil,
			idevidConfig: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
				assert.NotNil(t, attrs.ECCAttributes)
			},
		},
		{
			name: "invalid key algorithm without fallback",
			config: EKConfig{
				KeyAlgorithm: "INVALID",
				Handle:       0x81010001,
			},
			policyDigest: nil,
			idevidConfig: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "invalid key algorithm falls back to RSA",
			config: EKConfig{
				KeyAlgorithm: "INVALID",
				Handle:       0x81010001,
				RSAConfig:    &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			idevidConfig: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
			},
		},
		{
			name: "config with platform policy",
			config: EKConfig{
				KeyAlgorithm:   x509.RSA.String(),
				Handle:         0x81010001,
				PlatformPolicy: true,
				RSAConfig:      &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: &tpm2.TPM2BDigest{
				Buffer: []byte{0x01, 0x02, 0x03},
			},
			idevidConfig: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.True(t, attrs.PlatformPolicy)
			},
		},
		{
			name: "invalid ECC curve",
			config: EKConfig{
				KeyAlgorithm: x509.ECDSA.String(),
				Handle:       0x81010001,
				ECCConfig:    &store.ECCConfig{Curve: "INVALID"},
			},
			policyDigest: nil,
			idevidConfig: nil,
			expectError:  true,
			validate:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := EKAttributesFromConfig(tc.config, tc.policyDigest, tc.idevidConfig)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, attrs)
				if tc.validate != nil {
					tc.validate(t, attrs)
				}
			}
		})
	}
}

func TestSRKAttributesFromConfigTableDriven(t *testing.T) {
	tests := []struct {
		name         string
		config       SRKConfig
		policyDigest *tpm2.TPM2BDigest
		expectError  bool
		validate     func(*testing.T, *types.KeyAttributes)
	}{
		{
			name: "valid RSA config uses default CN",
			config: SRKConfig{
				KeyAlgorithm:  x509.RSA.String(),
				Handle:        0x81000001,
				HierarchyAuth: "password",
				RSAConfig:     &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, "srk", attrs.CN)
				assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
				assert.Equal(t, types.KeyTypeStorage, attrs.KeyType)
				assert.Equal(t, tpm2.TPMHandle(tpm2.TPMRHOwner), attrs.TPMAttributes.Hierarchy)
			},
		},
		{
			name: "valid ECC config",
			config: SRKConfig{
				KeyAlgorithm: x509.ECDSA.String(),
				Handle:       0x81000001,
				ECCConfig:    &store.ECCConfig{Curve: "P-256"},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
				assert.NotNil(t, attrs.ECCAttributes)
			},
		},
		{
			name: "invalid key algorithm without fallback",
			config: SRKConfig{
				KeyAlgorithm: "INVALID",
				Handle:       0x81000001,
			},
			policyDigest: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "config with platform policy",
			config: SRKConfig{
				KeyAlgorithm:   x509.RSA.String(),
				Handle:         0x81000001,
				PlatformPolicy: true,
				RSAConfig:      &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: &tpm2.TPM2BDigest{
				Buffer: []byte{0x01, 0x02, 0x03},
			},
			expectError: false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.True(t, attrs.PlatformPolicy)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := SRKAttributesFromConfig(tc.config, tc.policyDigest)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, attrs)
				if tc.validate != nil {
					tc.validate(t, attrs)
				}
			}
		})
	}
}

func TestIAKAttributesFromConfigTableDriven(t *testing.T) {
	soPIN := store.NewClearPassword([]byte("password"))

	tests := []struct {
		name         string
		config       *IAKConfig
		policyDigest *tpm2.TPM2BDigest
		expectError  bool
		validate     func(*testing.T, *types.KeyAttributes)
	}{
		{
			name: "valid RSA config",
			config: &IAKConfig{
				CN:                 "iak-test",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81010002,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, "iak-test", attrs.CN)
				assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
				assert.Equal(t, types.KeyTypeAttestation, attrs.KeyType)
				assert.Equal(t, tpm2.TPMRHEndorsement, attrs.TPMAttributes.Hierarchy)
				assert.Equal(t, soPIN, attrs.TPMAttributes.HierarchyAuth)
			},
		},
		{
			name: "valid ECC config",
			config: &IAKConfig{
				CN:                 "iak-ecc",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.ECDSA.String(),
				SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
				Handle:             0x81010002,
				ECCConfig:          &store.ECCConfig{Curve: "P-256"},
			},
			policyDigest: nil,
			expectError:  false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
				assert.NotNil(t, attrs.ECCAttributes)
			},
		},
		{
			name: "invalid hash algorithm",
			config: &IAKConfig{
				CN:                 "iak-test",
				Hash:               "INVALID",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81010002,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "invalid signature algorithm",
			config: &IAKConfig{
				CN:                 "iak-test",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: "INVALID",
				Handle:             0x81010002,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "invalid key algorithm without fallback",
			config: &IAKConfig{
				CN:                 "iak-test",
				Hash:               "SHA-256",
				KeyAlgorithm:       "INVALID",
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81010002,
			},
			policyDigest: nil,
			expectError:  true,
			validate:     nil,
		},
		{
			name: "config with platform policy",
			config: &IAKConfig{
				CN:                 "iak-test",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81010002,
				PlatformPolicy:     true,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			},
			policyDigest: &tpm2.TPM2BDigest{
				Buffer: []byte{0x01, 0x02, 0x03},
			},
			expectError: false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.True(t, attrs.PlatformPolicy)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := IAKAttributesFromConfig(soPIN, tc.config, tc.policyDigest)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, attrs)
				if tc.validate != nil {
					tc.validate(t, attrs)
				}
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Run("default config has expected values", func(t *testing.T) {
		assert.Equal(t, "/dev/tpmrm0", DefaultConfig.Device)
		assert.True(t, DefaultConfig.UseSimulator)
		assert.Equal(t, "SHA-256", DefaultConfig.Hash)
		assert.Equal(t, uint(16), DefaultConfig.PlatformPCR)
		assert.Equal(t, PCRBankSHA256, DefaultConfig.PlatformPCRBank)
		assert.NotNil(t, DefaultConfig.EK)
		assert.NotNil(t, DefaultConfig.IAK)
		assert.NotNil(t, DefaultConfig.IDevID)
		assert.NotNil(t, DefaultConfig.SSRK)
		assert.NotNil(t, DefaultConfig.KeyStore)
	})

	t.Run("default EK config", func(t *testing.T) {
		assert.Equal(t, uint32(0x01C00002), DefaultConfig.EK.CertHandle)
		assert.Equal(t, uint32(0x81010001), DefaultConfig.EK.Handle)
		assert.Equal(t, x509.RSA.String(), DefaultConfig.EK.KeyAlgorithm)
		assert.NotNil(t, DefaultConfig.EK.RSAConfig)
		assert.Equal(t, 2048, DefaultConfig.EK.RSAConfig.KeySize)
	})

	t.Run("default IAK config", func(t *testing.T) {
		assert.Equal(t, uint32(0x81010002), DefaultConfig.IAK.Handle)
		assert.Equal(t, x509.RSA.String(), DefaultConfig.IAK.KeyAlgorithm)
		assert.Equal(t, x509.SHA256WithRSAPSS.String(), DefaultConfig.IAK.SignatureAlgorithm)
	})

	t.Run("default IDevID config", func(t *testing.T) {
		assert.Equal(t, uint32(0x01C90000), DefaultConfig.IDevID.CertHandle)
		assert.Equal(t, uint32(0x81020000), DefaultConfig.IDevID.Handle)
		assert.Equal(t, "edge", DefaultConfig.IDevID.Model)
		assert.Equal(t, "001", DefaultConfig.IDevID.Serial)
	})
}

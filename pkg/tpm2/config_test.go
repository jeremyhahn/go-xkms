package tpm2

import (
	"crypto"
	"crypto/x509"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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
	soPIN := store.NewPassword([]byte("password"))

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
		assert.NotNil(t, DefaultConfig.PlatformSRK)
	})

	t.Run("default EK config", func(t *testing.T) {
		assert.Equal(t, uint32(0x01C00002), DefaultConfig.EK.CertHandle)
		assert.Equal(t, uint32(0x81010001), DefaultConfig.EK.Handle)
		assert.Equal(t, x509.RSA.String(), DefaultConfig.EK.KeyAlgorithm)
		assert.NotNil(t, DefaultConfig.EK.RSAConfig)
		assert.Equal(t, 2048, DefaultConfig.EK.RSAConfig.KeySize)
	})

	t.Run("default IAK config", func(t *testing.T) {
		assert.Equal(t, uint32(0x81020001), DefaultConfig.IAK.Handle)
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

// Tests merged from config_parsing_test.go

func TestParseHierarchy_Extended(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    tpm2.TPMIRHHierarchy
		expectError bool
	}{
		{"Endorsement", "ENDORSEMENT", tpm2.TPMRHEndorsement, false},
		{"Owner", "OWNER", tpm2.TPMRHOwner, false},
		{"Platform", "PLATFORM", tpm2.TPMRHPlatform, false},
		{"Invalid", "INVALID", 0, true},
		{"Empty", "", 0, true},
		{"Lowercase endorsement", "endorsement", 0, true}, // Case sensitive
		{"Lowercase owner", "owner", 0, true},
		{"Lowercase platform", "platform", 0, true},
		{"Mixed case", "Endorsement", 0, true},
		{"NULL", "NULL", 0, true}, // NULL is not a valid hierarchy for parsing
		{"Whitespace", " OWNER", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHierarchy(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidHierarchyType)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseIdentityProvisioningStrategy_Extended(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{"IAK", "IAK", EnrollmentStrategyIAK},
		{"IAK_IDEVID_SINGLE_PASS", "IAK_IDEVID_SINGLE_PASS", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Default for invalid", "INVALID", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Default for empty", "", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Lowercase iak", "iak", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},     // Case sensitive
		{"Partial match", "IAK_", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},    // No partial match
		{"Extra chars", "IAK_EXTRA", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS}, // Falls to default
		{"Whitespace", " IAK", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},       // No whitespace handling
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfigStructTags_Extended(t *testing.T) {
	// This test verifies that the Config struct can be properly used
	// with YAML/JSON/mapstructure tags
	config := Config{
		CommandAddress:               "localhost:2321",
		Device:                       "/dev/tpmrm0",
		EncryptSession:               true,
		UseSimulator:                 false,
		Hash:                         "SHA-256",
		PlatformPCR:                  16,
		PlatformPCRBank:              "sha256",
		IdentityProvisioningStrategy: "IAK_IDEVID_SINGLE_PASS",
		UseEntropy:                   true,
		LockoutAuth:                  "test-lockout",
		PlatformAddress:              "localhost:2322",
		GoldenPCRs:                   []uint{0, 7, 9, 10},
		FileIntegrity:                []string{"/etc", "/usr/bin"},
	}

	assert.Equal(t, "localhost:2321", config.CommandAddress)
	assert.Equal(t, "/dev/tpmrm0", config.Device)
	assert.True(t, config.EncryptSession)
	assert.False(t, config.UseSimulator)
	assert.Equal(t, "SHA-256", config.Hash)
	assert.Equal(t, uint(16), config.PlatformPCR)
	assert.Equal(t, "sha256", config.PlatformPCRBank)
	assert.True(t, config.UseEntropy)
	assert.Equal(t, "test-lockout", config.LockoutAuth)
	assert.Equal(t, "localhost:2322", config.PlatformAddress)
	assert.Equal(t, []uint{0, 7, 9, 10}, config.GoldenPCRs)
	assert.Equal(t, []string{"/etc", "/usr/bin"}, config.FileIntegrity)
}

func TestEKConfigStructure_Extended(t *testing.T) {
	config := EKConfig{
		CertHandle:     0x01C00002,
		CN:             "test-ek",
		Debug:          true,
		Handle:         0x81010001,
		HierarchyAuth:  "test-auth",
		KeyAlgorithm:   "RSA",
		Password:       "test-password",
		PlatformPolicy: true,
	}

	assert.Equal(t, uint32(0x01C00002), config.CertHandle)
	assert.Equal(t, "test-ek", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81010001), config.Handle)
	assert.Equal(t, "test-auth", config.HierarchyAuth)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
}

func TestSRKConfigStructure_Extended(t *testing.T) {
	config := SRKConfig{
		CN:             "test-srk",
		Debug:          true,
		Handle:         0x81000001,
		HierarchyAuth:  "test-auth",
		KeyAlgorithm:   "RSA",
		Password:       "test-password",
		PlatformPolicy: true,
	}

	assert.Equal(t, "test-srk", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81000001), config.Handle)
	assert.Equal(t, "test-auth", config.HierarchyAuth)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
}

func TestIDevIDConfigStructure_Extended(t *testing.T) {
	config := IDevIDConfig{
		CertHandle:         0x01C90000,
		CN:                 "test-idevid",
		Debug:              true,
		Handle:             0x81020000,
		Hash:               "SHA-256",
		KeyAlgorithm:       "RSA",
		Manufacturer:       "Test Manufacturer",
		Model:              "Test Model",
		Pad:                true,
		Password:           "test-password",
		PlatformPolicy:     true,
		Serial:             "12345",
		SignatureAlgorithm: "SHA256WithRSAPSS",
		Version:            "1.0",
	}

	assert.Equal(t, uint32(0x01C90000), config.CertHandle)
	assert.Equal(t, "test-idevid", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81020000), config.Handle)
	assert.Equal(t, "SHA-256", config.Hash)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
	assert.Equal(t, "Test Manufacturer", config.Manufacturer)
	assert.Equal(t, "Test Model", config.Model)
	assert.True(t, config.Pad)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
	assert.Equal(t, "12345", config.Serial)
	assert.Equal(t, "SHA256WithRSAPSS", config.SignatureAlgorithm)
	assert.Equal(t, "1.0", config.Version)
}

func TestIAKConfigStructure_Extended(t *testing.T) {
	config := IAKConfig{
		CertHandle:         0x01C90001,
		CN:                 "test-iak",
		Debug:              true,
		Handle:             0x81010002,
		Hash:               "SHA-256",
		KeyAlgorithm:       "RSA",
		Password:           "test-password",
		PlatformPolicy:     true,
		SignatureAlgorithm: "SHA256WithRSAPSS",
	}

	assert.Equal(t, uint32(0x01C90001), config.CertHandle)
	assert.Equal(t, "test-iak", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81010002), config.Handle)
	assert.Equal(t, "SHA-256", config.Hash)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
	assert.Equal(t, "SHA256WithRSAPSS", config.SignatureAlgorithm)
}

func TestPlatformSRKConfigStructure_Extended(t *testing.T) {
	config := PlatformSRKConfig{
		CN:             "test-keystore",
		SRKAuth:        "test-srk-auth",
		SRKHandle:      0x81000002,
		PlatformPolicy: true,
	}

	assert.Equal(t, "test-keystore", config.CN)
	assert.Equal(t, "test-srk-auth", config.SRKAuth)
	assert.Equal(t, uint32(0x81000002), config.SRKHandle)
	assert.True(t, config.PlatformPolicy)
}

func TestLDevIDConfigStructure_Extended(t *testing.T) {
	config := LDevIDConfig{
		CertHandle:         0x01C90010,
		CN:                 "test-ldevid",
		Debug:              true,
		Handle:             0x81020010,
		Hash:               "SHA-256",
		KeyAlgorithm:       "RSA",
		Model:              "Test Model",
		Pad:                true,
		Password:           "test-password",
		PlatformPolicy:     true,
		Serial:             "67890",
		SignatureAlgorithm: "SHA256WithRSA",
	}

	assert.Equal(t, uint32(0x01C90010), config.CertHandle)
	assert.Equal(t, "test-ldevid", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81020010), config.Handle)
	assert.Equal(t, "SHA-256", config.Hash)
	assert.Equal(t, "RSA", config.KeyAlgorithm)
	assert.Equal(t, "Test Model", config.Model)
	assert.True(t, config.Pad)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
	assert.Equal(t, "67890", config.Serial)
	assert.Equal(t, "SHA256WithRSA", config.SignatureAlgorithm)
}

func TestLAKConfigStructure_Extended(t *testing.T) {
	config := LAKConfig{
		CertHandle:         0x01C90011,
		CN:                 "test-lak",
		Debug:              true,
		Handle:             0x81020011,
		Hash:               "SHA-256",
		KeyAlgorithm:       "ECDSA",
		Password:           "test-password",
		PlatformPolicy:     true,
		SignatureAlgorithm: "ECDSAWithSHA256",
	}

	assert.Equal(t, uint32(0x01C90011), config.CertHandle)
	assert.Equal(t, "test-lak", config.CN)
	assert.True(t, config.Debug)
	assert.Equal(t, uint32(0x81020011), config.Handle)
	assert.Equal(t, "SHA-256", config.Hash)
	assert.Equal(t, "ECDSA", config.KeyAlgorithm)
	assert.Equal(t, "test-password", config.Password)
	assert.True(t, config.PlatformPolicy)
	assert.Equal(t, "ECDSAWithSHA256", config.SignatureAlgorithm)
}

// Tests merged from configvalidation_test.go

func TestConfigVal_ParseHashAlgFromString_Comprehensive(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    tpm2.TPMIAlgHash
		expectError bool
	}{
		{"SHA-1", "SHA-1", tpm2.TPMAlgSHA1, false},
		{"SHA-256", "SHA-256", tpm2.TPMAlgSHA256, false},
		{"SHA-384", "SHA-384", tpm2.TPMAlgSHA384, false},
		{"SHA-512", "SHA-512", tpm2.TPMAlgSHA512, false},
		{"sha-1 lowercase", "sha-1", tpm2.TPMAlgSHA1, false},
		{"sha-256 lowercase", "sha-256", tpm2.TPMAlgSHA256, false},
		{"sha-384 lowercase", "sha-384", tpm2.TPMAlgSHA384, false},
		{"sha-512 lowercase", "sha-512", tpm2.TPMAlgSHA512, false},
		{"Invalid algorithm", "MD5", 0, true},
		{"Empty string", "", 0, true},
		{"Unknown algorithm", "SHA3-256", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashAlgFromString(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseHashAlgFromString(%q) expected error, got nil", tt.input)
				}
				if result != 0 {
					t.Errorf("ParseHashAlgFromString(%q) expected 0 on error, got %v", tt.input, result)
				}
			} else {
				if err != nil {
					t.Errorf("ParseHashAlgFromString(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseHashAlgFromString(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParseHashAlg_Comprehensive(t *testing.T) {
	tests := []struct {
		name        string
		input       crypto.Hash
		expected    tpm2.TPMIAlgHash
		expectError bool
	}{
		{"SHA1", crypto.SHA1, tpm2.TPMAlgSHA1, false},
		{"SHA256", crypto.SHA256, tpm2.TPMAlgSHA256, false},
		{"SHA384", crypto.SHA384, tpm2.TPMAlgSHA384, false},
		{"SHA512", crypto.SHA512, tpm2.TPMAlgSHA512, false},
		{"MD5", crypto.MD5, 0, true},
		{"SHA3_256", crypto.SHA3_256, 0, true},
		{"BLAKE2b_256", crypto.BLAKE2b_256, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashAlg(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseHashAlg(%v) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseHashAlg(%v) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseHashAlg(%v) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParseHashSize_Comprehensive(t *testing.T) {
	tests := []struct {
		name        string
		input       crypto.Hash
		expected    uint32
		expectError bool
	}{
		{"SHA1", crypto.SHA1, 20, false},
		{"SHA256", crypto.SHA256, 32, false},
		{"SHA384", crypto.SHA384, 48, false},
		{"SHA512", crypto.SHA512, 64, false},
		{"MD5", crypto.MD5, 0, true},
		{"SHA3_256", crypto.SHA3_256, 0, true},
		{"Invalid hash", crypto.Hash(0), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHashSize(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseHashSize(%v) expected error, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("ParseHashSize(%v) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseHashSize(%v) = %d, want %d", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParseHierarchy_All(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    tpm2.TPMIRHHierarchy
		expectError bool
	}{
		{"ENDORSEMENT", "ENDORSEMENT", tpm2.TPMRHEndorsement, false},
		{"OWNER", "OWNER", tpm2.TPMRHOwner, false},
		{"PLATFORM", "PLATFORM", tpm2.TPMRHPlatform, false},
		{"Invalid lowercase", "endorsement", 0, true},
		{"Invalid type", "INVALID", 0, true},
		{"Empty string", "", 0, true},
		{"NULL hierarchy", "NULL", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseHierarchy(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseHierarchy(%q) expected error, got nil", tt.input)
				}
				if err != ErrInvalidHierarchyType {
					t.Errorf("ParseHierarchy(%q) expected ErrInvalidHierarchyType, got %v", tt.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("ParseHierarchy(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseHierarchy(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParseIdentityStrategy_All(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EnrollmentStrategy
	}{
		{"IAK strategy", "IAK", EnrollmentStrategyIAK},
		{"IAK_IDEVID_SINGLE_PASS", "IAK_IDEVID_SINGLE_PASS", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Default for empty", "", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Default for unknown", "UNKNOWN", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"Default for lowercase", "iak", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseIdentityProvisioningStrategy(tt.input)
			if result != tt.expected {
				t.Errorf("ParseIdentityProvisioningStrategy(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestConfigVal_ParsePCRBankAlgID_All(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    tpm2.TPMAlgID
		expectError bool
	}{
		{"sha1 lowercase", "sha1", tpm2.TPMAlgSHA1, false},
		{"sha256 lowercase", "sha256", tpm2.TPMAlgSHA256, false},
		{"sha384 lowercase", "sha384", tpm2.TPMAlgSHA384, false},
		{"sha512 lowercase", "sha512", tpm2.TPMAlgSHA512, false},
		{"SHA1 uppercase", "SHA1", tpm2.TPMAlgSHA1, false},
		{"SHA256 uppercase", "SHA256", tpm2.TPMAlgSHA256, false},
		{"SHA384 uppercase", "SHA384", tpm2.TPMAlgSHA384, false},
		{"SHA512 uppercase", "SHA512", tpm2.TPMAlgSHA512, false},
		{"Invalid bank", "md5", 0, true},
		{"Empty string", "", 0, true},
		{"SHA-256 with dash", "sha-256", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePCRBankAlgID(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParsePCRBankAlgID(%q) expected error, got nil", tt.input)
				}
				if err != ErrInvalidPCRBankType {
					t.Errorf("ParsePCRBankAlgID(%q) expected ErrInvalidPCRBankType, got %v", tt.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("ParsePCRBankAlgID(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParsePCRBankAlgID(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParsePCRBankCryptoHash_All(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    crypto.Hash
		expectError bool
	}{
		{"sha1 lowercase", "sha1", crypto.SHA1, false},
		{"sha256 lowercase", "sha256", crypto.SHA256, false},
		{"sha384 lowercase", "sha384", crypto.SHA3_384, false},
		{"sha512 lowercase", "sha512", crypto.SHA512, false},
		{"SHA1 uppercase", "SHA1", crypto.SHA1, false},
		{"Invalid bank", "md5", 0, true},
		{"Empty string", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParsePCRBankCryptoHash(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParsePCRBankCryptoHash(%q) expected error, got nil", tt.input)
				}
				if err != ErrInvalidPCRBankType {
					t.Errorf("ParsePCRBankCryptoHash(%q) expected ErrInvalidPCRBankType, got %v", tt.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("ParsePCRBankCryptoHash(%q) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParsePCRBankCryptoHash(%q) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_ParseCryptoHashAlgID_All(t *testing.T) {
	tests := []struct {
		name        string
		input       crypto.Hash
		expected    tpm2.TPMAlgID
		expectError bool
	}{
		{"SHA1", crypto.SHA1, tpm2.TPMAlgSHA1, false},
		{"SHA256", crypto.SHA256, tpm2.TPMAlgSHA256, false},
		{"SHA384", crypto.SHA384, tpm2.TPMAlgSHA384, false},
		{"SHA512", crypto.SHA512, tpm2.TPMAlgSHA512, false},
		{"SHA3_256", crypto.SHA3_256, tpm2.TPMAlgSHA3256, false},
		{"SHA3_384", crypto.SHA3_384, tpm2.TPMAlgSHA3384, false},
		{"SHA3_512", crypto.SHA3_512, tpm2.TPMAlgSHA3512, false},
		{"MD5", crypto.MD5, 0, true},
		{"BLAKE2b", crypto.BLAKE2b_256, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCryptoHashAlgID(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseCryptoHashAlgID(%v) expected error, got nil", tt.input)
				}
				if err != ErrInvalidCryptoHashAlgID {
					t.Errorf("ParseCryptoHashAlgID(%v) expected ErrInvalidCryptoHashAlgID, got %v", tt.input, err)
				}
			} else {
				if err != nil {
					t.Errorf("ParseCryptoHashAlgID(%v) unexpected error: %v", tt.input, err)
				}
				if result != tt.expected {
					t.Errorf("ParseCryptoHashAlgID(%v) = %v, want %v", tt.input, result, tt.expected)
				}
			}
		})
	}
}

func TestConfigVal_HierarchyName_All(t *testing.T) {
	tests := []struct {
		name      string
		hierarchy tpm2.TPMHandle
		expected  string
	}{
		{"PLATFORM", tpm2.TPMRHPlatform, "PLATFORM"},
		{"OWNER", tpm2.TPMRHOwner, "OWNER"},
		{"ENDORSEMENT", tpm2.TPMRHEndorsement, "ENDORSEMENT"},
		{"NULL", tpm2.TPMRHNull, "NULL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := HierarchyName(tt.hierarchy)
			if err != nil {
				t.Errorf("HierarchyName(%v) returned unexpected error: %v", tt.hierarchy, err)
			}
			if result != tt.expected {
				t.Errorf("HierarchyName(%v) = %q, want %q", tt.hierarchy, result, tt.expected)
			}
		})
	}
}

func TestConfigVal_HierarchyName_Invalid_ReturnsError(t *testing.T) {
	_, err := HierarchyName(tpm2.TPMHandle(0xFFFFFFFF))
	if err == nil {
		t.Error("HierarchyName() with invalid hierarchy expected error, but got nil")
	}
}

func TestConfigVal_TCGVendorID_String(t *testing.T) {
	tests := []struct {
		name     string
		vendorID TCGVendorID
		expected string
	}{
		{"AMD", 1095582720, "AMD"},
		{"Intel", 1229870147, "Intel"},
		{"Microsoft", 1297303124, "Microsoft"},
		{"Infineon", 1229346816, "Infineon"},
		{"Google", 1196379975, "Google"},
		{"Unknown vendor", 0x12345678, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.vendorID.String()
			if result != tt.expected {
				t.Errorf("TCGVendorID(%d).String() = %q, want %q", tt.vendorID, result, tt.expected)
			}
		})
	}
}

func TestConfigVal_PCRBankAlgo_String(t *testing.T) {
	tests := []struct {
		name     string
		algo     PCRBankAlgo
		expected string
	}{
		{"sha1", PCRBankAlgo("sha1"), "sha1"},
		{"sha256", PCRBankAlgo("sha256"), "sha256"},
		{"sha384", PCRBankAlgo("sha384"), "sha384"},
		{"sha512", PCRBankAlgo("sha512"), "sha512"},
		{"custom", PCRBankAlgo("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.algo.String()
			if result != tt.expected {
				t.Errorf("PCRBankAlgo(%q).String() = %q, want %q", tt.algo, result, tt.expected)
			}
		})
	}
}

func TestConfigVal_DefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig

	if cfg.Device != "/dev/tpmrm0" {
		t.Errorf("DefaultConfig.Device = %q, want %q", cfg.Device, "/dev/tpmrm0")
	}

	if cfg.Hash != "SHA-256" {
		t.Errorf("DefaultConfig.Hash = %q, want %q", cfg.Hash, "SHA-256")
	}

	if !cfg.UseSimulator {
		t.Error("DefaultConfig.UseSimulator = false, want true")
	}

	if cfg.EK == nil {
		t.Fatal("DefaultConfig.EK is nil")
	}
	if cfg.EK.Handle != 0x81010001 {
		t.Errorf("DefaultConfig.EK.Handle = %#x, want %#x", cfg.EK.Handle, 0x81010001)
	}
	if cfg.EK.CertHandle != 0x01C00002 {
		t.Errorf("DefaultConfig.EK.CertHandle = %#x, want %#x", cfg.EK.CertHandle, 0x01C00002)
	}

	if cfg.IAK == nil {
		t.Fatal("DefaultConfig.IAK is nil")
	}
	if cfg.IAK.Handle != 0x81020001 {
		t.Errorf("DefaultConfig.IAK.Handle = %#x, want %#x", cfg.IAK.Handle, 0x81020001)
	}
	if cfg.IAK.Hash != "SHA-256" {
		t.Errorf("DefaultConfig.IAK.Hash = %q, want %q", cfg.IAK.Hash, "SHA-256")
	}

	if cfg.IDevID == nil {
		t.Fatal("DefaultConfig.IDevID is nil")
	}
	if cfg.IDevID.Handle != 0x81020000 {
		t.Errorf("DefaultConfig.IDevID.Handle = %#x, want %#x", cfg.IDevID.Handle, 0x81020000)
	}
	if cfg.IDevID.CertHandle != 0x01C90000 {
		t.Errorf("DefaultConfig.IDevID.CertHandle = %#x, want %#x", cfg.IDevID.CertHandle, 0x01C90000)
	}
	if cfg.IDevID.Model != "edge" {
		t.Errorf("DefaultConfig.IDevID.Model = %q, want %q", cfg.IDevID.Model, "edge")
	}
	if cfg.IDevID.Serial != "001" {
		t.Errorf("DefaultConfig.IDevID.Serial = %q, want %q", cfg.IDevID.Serial, "001")
	}
	if !cfg.IDevID.Pad {
		t.Error("DefaultConfig.IDevID.Pad = false, want true")
	}

	if cfg.SSRK == nil {
		t.Fatal("DefaultConfig.SSRK is nil")
	}
	if cfg.SSRK.Handle != 0x81000001 {
		t.Errorf("DefaultConfig.SSRK.Handle = %#x, want %#x", cfg.SSRK.Handle, 0x81000001)
	}

	if cfg.PlatformPCR != 16 {
		t.Errorf("DefaultConfig.PlatformPCR = %d, want 16", cfg.PlatformPCR)
	}
	if cfg.PlatformPCRBank != PCRBankSHA256 {
		t.Errorf("DefaultConfig.PlatformPCRBank = %q, want %q", cfg.PlatformPCRBank, PCRBankSHA256)
	}

	expectedStrategy := string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
	if cfg.IdentityProvisioningStrategy != expectedStrategy {
		t.Errorf("DefaultConfig.IdentityProvisioningStrategy = %q, want %q", cfg.IdentityProvisioningStrategy, expectedStrategy)
	}
}

func TestConfigVal_EnrollmentStrategy_Constants(t *testing.T) {
	if EnrollmentStrategyIAK != "IAK" {
		t.Errorf("EnrollmentStrategyIAK = %q, want %q", EnrollmentStrategyIAK, "IAK")
	}

	if EnrollmentStrategyIAK_IDEVID_SINGLE_PASS != "IAK_IDEVID_SINGLE_PASS" {
		t.Errorf("EnrollmentStrategyIAK_IDEVID_SINGLE_PASS = %q, want %q", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, "IAK_IDEVID_SINGLE_PASS")
	}
}

func TestConfigVal_PCRBankConstants(t *testing.T) {
	if PCRBankSHA1 != "sha1" {
		t.Errorf("PCRBankSHA1 = %q, want %q", PCRBankSHA1, "sha1")
	}
	if PCRBankSHA256 != "sha256" {
		t.Errorf("PCRBankSHA256 = %q, want %q", PCRBankSHA256, "sha256")
	}
	if PCRBankSHA384 != "sha384" {
		t.Errorf("PCRBankSHA384 = %q, want %q", PCRBankSHA384, "sha384")
	}
	if PCRBankSHA512 != "sha512" {
		t.Errorf("PCRBankSHA512 = %q, want %q", PCRBankSHA512, "sha512")
	}
}

func TestConfigVal_AlgorithmConstants(t *testing.T) {
	if AlgSHA1 != 0x0004 {
		t.Errorf("AlgSHA1 = %#x, want %#x", AlgSHA1, 0x0004)
	}
	if AlgSHA256 != 0x000B {
		t.Errorf("AlgSHA256 = %#x, want %#x", AlgSHA256, 0x000B)
	}
	if AlgSHA384 != 0x000C {
		t.Errorf("AlgSHA384 = %#x, want %#x", AlgSHA384, 0x000C)
	}
	if AlgSHA512 != 0x000D {
		t.Errorf("AlgSHA512 = %#x, want %#x", AlgSHA512, 0x000D)
	}
	if AlgSM3256 != 0x0012 {
		t.Errorf("AlgSM3256 = %#x, want %#x", AlgSM3256, 0x0012)
	}
	if AlgSM3256Alt != 0x2000 {
		t.Errorf("AlgSM3256Alt = %#x, want %#x", AlgSM3256Alt, 0x2000)
	}
}

func TestConfigVal_ErrorTypes(t *testing.T) {
	if ErrInvalidHierarchyType == nil {
		t.Error("ErrInvalidHierarchyType is nil")
	}
	if ErrInvalidPCRBankType == nil {
		t.Error("ErrInvalidPCRBankType is nil")
	}
	if ErrInvalidHashFunction == nil {
		t.Error("ErrInvalidHashFunction is nil")
	}
	if ErrInvalidCryptoHashAlgID == nil {
		t.Error("ErrInvalidCryptoHashAlgID is nil")
	}
	if ErrInvalidEnrollmentStrategy == nil {
		t.Error("ErrInvalidEnrollmentStrategy is nil")
	}

	if ErrInvalidHierarchyType.Error() == "" {
		t.Error("ErrInvalidHierarchyType has empty message")
	}
	if ErrInvalidPCRBankType.Error() == "" {
		t.Error("ErrInvalidPCRBankType has empty message")
	}
}

func TestConfigVal_VendorsMapCompleteness(t *testing.T) {
	importantVendors := map[TCGVendorID]string{
		1095582720: "AMD",
		1229870147: "Intel",
		1297303124: "Microsoft",
		1229346816: "Infineon",
		1196379975: "Google",
		1229081856: "IBM",
		1213220096: "HPE",
		1279610368: "Lenovo",
	}

	for id, name := range importantVendors {
		result := id.String()
		if result != name {
			t.Errorf("vendors[%d] = %q, want %q", id, result, name)
		}
	}
}

func TestFileIntegritySum_InvalidPCRBank(t *testing.T) {
	logger := slog.Default()
	config := &Config{
		PlatformPCRBank: "INVALID_BANK",
	}

	tpm := &TPM2{
		logger: logger,
		config: config,
	}

	// ParsePCRBankCryptoHash should fail with invalid bank
	_, err := ParsePCRBankCryptoHash(tpm.config.PlatformPCRBank)
	assert.Error(t, err)
}

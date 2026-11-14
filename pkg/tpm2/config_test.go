package tpm2

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIDevIDAttributesFromConfigTableDriven(t *testing.T) {
	tests := []struct {
		name        string
		config      IDevIDConfig
		expectError bool
		validate    func(*testing.T, *types.KeyAttributes)
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
			expectError: false,
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
			expectError: false,
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
			expectError: false,
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
			expectError: false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.True(t, (attrs.TPMPolicy == types.TPMPolicyPlatform))
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
			expectError: true,
			validate:    nil,
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
			expectError: true,
			validate:    nil,
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
			expectError: true,
			validate:    nil,
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
			expectError: false,
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
			expectError: true,
			validate:    nil,
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
				Password:           secrettest.Literal(t, []byte("secret")),

				RSAConfig: &store.RSAConfig{KeySize: 2048},
			},
			expectError: false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.NotNil(t, attrs.Password)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := IDevIDAttributesFromConfig(tc.config)
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
		name        string
		config      LDevIDConfig
		expectError bool
		validate    func(*testing.T, *types.KeyAttributes)
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
			expectError: false,
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
			expectError: false,
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
			expectError: false,
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
			expectError: true,
			validate:    nil,
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
			expectError: true,
			validate:    nil,
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
			expectError: false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.True(t, (attrs.TPMPolicy == types.TPMPolicyPlatform))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := LDevIDAttributesFromConfig(tc.config)
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
				HierarchyAuth: secrettest.Literal(t, []byte("password")),

				RSAConfig: &store.RSAConfig{KeySize: 2048},
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
				HierarchyAuth: secrettest.Literal(t, []byte("password")),

				RSAConfig: &store.RSAConfig{KeySize: 2048},
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
			name: "invalid key algorithm falls back to ECDSA",
			config: EKConfig{
				KeyAlgorithm: "INVALID",
				Handle:       0x81010001,
				ECCConfig:    &store.ECCConfig{Curve: "P-256"},
			},
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
				assert.Equal(t, tpm2.ECCEKTemplate.Type, attrs.TPMAttributes.Template.Type)
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
				assert.True(t, (attrs.TPMPolicy == types.TPMPolicyPlatform))
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
		name        string
		config      SRKConfig
		expectError bool
		validate    func(*testing.T, *types.KeyAttributes)
	}{
		{
			name: "valid RSA config uses default CN",
			config: SRKConfig{
				KeyAlgorithm:  x509.RSA.String(),
				Handle:        0x81000001,
				HierarchyAuth: secrettest.Literal(t, []byte("password")),

				RSAConfig: &store.RSAConfig{KeySize: 2048},
			},
			expectError: false,
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
			expectError: false,
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
			expectError: true,
			validate:    nil,
		},
		{
			name: "invalid key algorithm falls back to RSA",
			config: SRKConfig{
				KeyAlgorithm: "INVALID",
				Handle:       0x81000001,
				RSAConfig:    &store.RSAConfig{KeySize: 2048},
			},
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
				assert.Equal(t, tpm2.RSASRKTemplate.Type, attrs.TPMAttributes.Template.Type)
			},
		},
		{
			name: "invalid key algorithm falls back to ECDSA",
			config: SRKConfig{
				KeyAlgorithm: "INVALID",
				Handle:       0x81000001,
				ECCConfig:    &store.ECCConfig{Curve: "P-256"},
			},
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
				assert.Equal(t, tpm2.ECCSRKTemplate.Type, attrs.TPMAttributes.Template.Type)
			},
		},
		{
			name: "no configuration yields a platform policy or an AuthPolicy",
			config: SRKConfig{
				KeyAlgorithm: x509.RSA.String(),
				Handle:       0x81000001,
				RSAConfig:    &store.RSAConfig{KeySize: 2048},
			},
			expectError: false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.False(t, (attrs.TPMPolicy == types.TPMPolicyPlatform),
					"the shared SRK never carries a platform policy")
				assert.Empty(t, attrs.TPMAttributes.Template.AuthPolicy.Buffer,
					"no AuthPolicy may be baked into the shared SRK template")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := SRKAttributesFromConfig(tc.config)
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
	soPIN := mustPassword(t, []byte("password"))

	tests := []struct {
		name        string
		config      *IAKConfig
		expectError bool
		validate    func(*testing.T, *types.KeyAttributes)
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
			expectError: false,
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
			expectError: false,
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
			expectError: true,
			validate:    nil,
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
			expectError: true,
			validate:    nil,
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
			expectError: true,
			validate:    nil,
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
			expectError: false,
			validate: func(t *testing.T, attrs *types.KeyAttributes) {
				assert.True(t, (attrs.TPMPolicy == types.TPMPolicyPlatform))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := IAKAttributesFromConfig(soPIN, tc.config)
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

// Tests merged from config_parsing_test.go

// Tests merged from configvalidation_test.go

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

// TestSigningKeyAttrBuildersLeaveTemplateZero locks in the fix for #355: the
// IAK, IDevID and LDevID attribute builders formerly assigned an Endorsement
// Key template (Restricted, SignEncrypt false) into TPMAttributes.Template.
// Nothing on those key types' creation paths ever read the field -- CreateIAK
// and CreateIDevID construct their own templates -- but the dead assignment
// misled readers into diagnosing the signing keys as EK-derived. The builders
// must now leave Template as the zero TPMTPublic, so any future write to the
// field is a deliberate act. PlatformPolicy enabled with a non-nil digest is
// the exact condition that previously baked an AuthPolicy into the dead
// template.
func TestSigningKeyAttrBuildersLeaveTemplateZero(t *testing.T) {
	zeroTemplate := tpm2.TPMTPublic{}

	t.Run("IAK", func(t *testing.T) {
		attrs, err := IAKAttributesFromConfig(
			mustPassword(t, []byte("so-pin")),
			&IAKConfig{
				CN:                 "iak-template-zero",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81010002,
				PlatformPolicy:     true,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			})
		require.NoError(t, err)
		assert.Equal(t, zeroTemplate, attrs.TPMAttributes.Template,
			"IAKAttributesFromConfig must not populate TPMAttributes.Template; CreateIAK builds its own template")
		assert.True(t, (attrs.TPMPolicy == types.TPMPolicyPlatform),
			"PlatformPolicy must still be conveyed by the attribute field")
	})

	t.Run("IDevID", func(t *testing.T) {
		attrs, err := IDevIDAttributesFromConfig(
			IDevIDConfig{
				CN:                 "idevid-template-zero",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.RSA.String(),
				SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				Handle:             0x81020000,
				PlatformPolicy:     true,
				RSAConfig:          &store.RSAConfig{KeySize: 2048},
			})
		require.NoError(t, err)
		assert.Equal(t, zeroTemplate, attrs.TPMAttributes.Template,
			"IDevIDAttributesFromConfig must not populate TPMAttributes.Template; CreateIDevID selects the IDevID templates")
		assert.True(t, (attrs.TPMPolicy == types.TPMPolicyPlatform),
			"PlatformPolicy must still be conveyed by the attribute field")
	})

	t.Run("LDevID", func(t *testing.T) {
		attrs, err := LDevIDAttributesFromConfig(
			LDevIDConfig{
				CN:                 "ldevid-template-zero",
				Hash:               "SHA-256",
				KeyAlgorithm:       x509.ECDSA.String(),
				SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
				Handle:             0x81020001,
				PlatformPolicy:     true,
				ECCConfig:          &store.ECCConfig{Curve: "P-256"},
			})
		require.NoError(t, err)
		assert.Equal(t, zeroTemplate, attrs.TPMAttributes.Template,
			"LDevIDAttributesFromConfig must not populate TPMAttributes.Template; CreateIDevID selects the LDevID template")
		assert.True(t, (attrs.TPMPolicy == types.TPMPolicyPlatform),
			"PlatformPolicy must still be conveyed by the attribute field")
	})

	// The Endorsement Key is created FROM its template (CreateEK reads
	// TPMAttributes.Template), so EKAttributesFromConfig must keep
	// populating it -- including the platform policy digest.
	t.Run("EK keeps its template", func(t *testing.T) {
		// Only the EK builder still takes a digest, so it is the EK
		// subtest's fixture rather than the function's.
		policyDigest := &tpm2.TPM2BDigest{Buffer: []byte{0xAA, 0xBB, 0xCC}}
		attrs, err := EKAttributesFromConfig(
			EKConfig{
				CN:             "ek-template-kept",
				KeyAlgorithm:   x509.RSA.String(),
				Handle:         0x81010001,
				PlatformPolicy: true,
				RSAConfig:      &store.RSAConfig{KeySize: 2048},
			},
			policyDigest, nil)
		require.NoError(t, err)
		assert.Equal(t, tpm2.TPMAlgRSA, attrs.TPMAttributes.Template.Type,
			"EKAttributesFromConfig must keep assigning the EK template")
		assert.Equal(t, policyDigest.Buffer, attrs.TPMAttributes.Template.AuthPolicy.Buffer,
			"the platform policy digest must still be baked into the EK template")
	})
}

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

package ca

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// =============================================================================
// DefaultMultiIdentityCAConfig Tests
// =============================================================================

func TestDefaultMultiIdentityCAConfig_ReturnsValidDefaults(t *testing.T) {
	t.Parallel()

	config := DefaultMultiIdentityCAConfig()

	if config == nil {
		t.Fatal("DefaultMultiIdentityCAConfig() returned nil")
	}

	if len(config.Identity) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(config.Identity))
	}

	rootID := config.Identity[0]
	if rootID.Subject.CommonName != "Root CA" {
		t.Errorf("CommonName: expected %q, got %q", "Root CA", rootID.Subject.CommonName)
	}
	if rootID.Subject.Organization != "Organization" {
		t.Errorf("Organization: expected %q, got %q", "Organization", rootID.Subject.Organization)
	}
	if rootID.Subject.Country != "US" {
		t.Errorf("Country: expected %q, got %q", "US", rootID.Subject.Country)
	}
	if rootID.Valid != DefaultRootValidityYears {
		t.Errorf("Valid: expected %d, got %d", DefaultRootValidityYears, rootID.Valid)
	}
	if !rootID.IsRoot {
		t.Error("IsRoot: expected true, got false")
	}
	if len(rootID.Keys) == 0 {
		t.Fatal("Keys: expected at least 1 key configuration")
	}
	if rootID.KeystoreType != "software" {
		t.Errorf("KeystoreType: expected %q, got %q", "software", rootID.KeystoreType)
	}

	if config.SelectedCA != 0 {
		t.Errorf("SelectedCA: expected 0, got %d", config.SelectedCA)
	}
	if config.DefaultValidityDays != DefaultCertValidityDays {
		t.Errorf("DefaultValidityDays: expected %d, got %d", DefaultCertValidityDays, config.DefaultValidityDays)
	}

	// Validate should pass
	if err := config.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestDefaultMultiIdentityCAConfigWithIntermediate_ReturnsValidDefaults(t *testing.T) {
	t.Parallel()

	config := DefaultMultiIdentityCAConfigWithIntermediate()

	if config == nil {
		t.Fatal("DefaultMultiIdentityCAConfigWithIntermediate() returned nil")
	}

	if len(config.Identity) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(config.Identity))
	}

	// Check root CA
	rootID := config.Identity[0]
	if rootID.Subject.CommonName != "Root CA" {
		t.Errorf("Root CommonName: expected %q, got %q", "Root CA", rootID.Subject.CommonName)
	}
	if !rootID.IsRoot {
		t.Error("Root IsRoot: expected true, got false")
	}
	if rootID.Valid != DefaultRootValidityYears {
		t.Errorf("Root Valid: expected %d, got %d", DefaultRootValidityYears, rootID.Valid)
	}

	// Check intermediate CA
	intermediateID := config.Identity[1]
	if intermediateID.Subject.CommonName != "Intermediate CA" {
		t.Errorf("Intermediate CommonName: expected %q, got %q", "Intermediate CA", intermediateID.Subject.CommonName)
	}
	if intermediateID.IsRoot {
		t.Error("Intermediate IsRoot: expected false, got true")
	}
	if intermediateID.Valid != DefaultIntermediateValidityYears {
		t.Errorf("Intermediate Valid: expected %d, got %d", DefaultIntermediateValidityYears, intermediateID.Valid)
	}
	if intermediateID.ParentCA != "Root CA" {
		t.Errorf("Intermediate ParentCA: expected %q, got %q", "Root CA", intermediateID.ParentCA)
	}

	// SelectedCA should be 1 (intermediate)
	if config.SelectedCA != 1 {
		t.Errorf("SelectedCA: expected 1, got %d", config.SelectedCA)
	}

	// Validate should pass
	if err := config.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

// =============================================================================
// DefaultKeyConfig Tests
// =============================================================================

func TestDefaultKeyConfig_ReturnsValidConfig(t *testing.T) {
	t.Parallel()

	keys := DefaultKeyConfig()

	if len(keys) != 1 {
		t.Fatalf("expected 1 key config, got %d", len(keys))
	}

	key := keys[0]
	if key.KeyAlgorithm != types.AlgorithmECDSA {
		t.Errorf("KeyAlgorithm: expected %q, got %q", types.AlgorithmECDSA, key.KeyAlgorithm)
	}
	if key.ECCConfig == nil || key.ECCConfig.Curve != types.CurveP256 {
		t.Errorf("ECCConfig.Curve: expected %q, got %v", types.CurveP256, key.ECCConfig)
	}
	if key.Hash != types.HashSHA256 {
		t.Errorf("Hash: expected %q, got %q", types.HashSHA256, key.Hash)
	}
	if key.SignatureAlgorithm != types.SigECDSAWithSHA256 {
		t.Errorf("SignatureAlgorithm: expected %q, got %q", types.SigECDSAWithSHA256, key.SignatureAlgorithm)
	}
	if key.StoreType != types.StoreSoftware {
		t.Errorf("StoreType: expected %q, got %q", types.StoreSoftware, key.StoreType)
	}
}

// =============================================================================
// Identity Tests
// =============================================================================

func TestIdentity_Validate_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		identity Identity
	}{
		{
			name: "minimal valid identity",
			identity: Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   10,
				Keys:    DefaultKeyConfig(),
			},
		},
		{
			name: "root CA identity",
			identity: Identity{
				Subject:      Subject{CommonName: "Root CA", Organization: "Org"},
				Valid:        10,
				Keys:         DefaultKeyConfig(),
				KeystoreType: "software",
				IsRoot:       true,
			},
		},
		{
			name: "intermediate CA identity",
			identity: Identity{
				Subject:      Subject{CommonName: "Intermediate CA"},
				Valid:        5,
				Keys:         DefaultKeyConfig(),
				KeystoreType: "software",
				IsRoot:       false,
				ParentCA:     "Root CA",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.identity.Validate(); err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestIdentity_Validate_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		identity    Identity
		expectedErr error
	}{
		{
			name: "missing common name",
			identity: Identity{
				Subject: Subject{CommonName: ""},
				Valid:   10,
				Keys:    DefaultKeyConfig(),
			},
			expectedErr: ErrInvalidConfig,
		},
		{
			name: "zero validity",
			identity: Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   0,
				Keys:    DefaultKeyConfig(),
			},
			expectedErr: ErrInvalidConfig,
		},
		{
			name: "negative validity",
			identity: Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   -1,
				Keys:    DefaultKeyConfig(),
			},
			expectedErr: ErrInvalidConfig,
		},
		{
			name: "no keys configured",
			identity: Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   10,
				Keys:    nil,
			},
			expectedErr: ErrInvalidConfig,
		},
		{
			name: "empty keys slice",
			identity: Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   10,
				Keys:    []*types.KeyConfig{},
			},
			expectedErr: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.identity.Validate()
			if err == nil {
				t.Fatal("Validate() expected error, got nil")
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Validate() error = %v, expected %v", err, tt.expectedErr)
			}
		})
	}
}

func TestIdentity_GetValidityDays(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		valid    int
		expected int
	}{
		{name: "10 years", valid: 10, expected: 3650},
		{name: "5 years", valid: 5, expected: 1825},
		{name: "1 year", valid: 1, expected: 365},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			identity := Identity{Valid: tt.valid}
			if got := identity.GetValidityDays(); got != tt.expected {
				t.Errorf("GetValidityDays() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestIdentity_GetStoreType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		keystoreType types.StoreType
		expected     types.StoreType
	}{
		{name: "software", keystoreType: "software", expected: types.StoreSoftware},
		{name: "tpm2", keystoreType: "tpm2", expected: types.StoreTPM2},
		{name: "pkcs11", keystoreType: "pkcs11", expected: types.StorePKCS11},
		{name: "unknown", keystoreType: "unknown", expected: types.StoreUnknown},
		{name: "empty_defaults_to_software", keystoreType: "", expected: types.StoreSoftware},
		// Custom backend names should be preserved, not converted to "unknown"
		{name: "custom_backend_preserved", keystoreType: "pkcs8-ca2", expected: "pkcs8-ca2"},
		{name: "custom_backend_my_hsm", keystoreType: "my-hsm", expected: "my-hsm"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			identity := Identity{KeystoreType: tt.keystoreType}
			if got := identity.GetStoreType(); got != tt.expected {
				t.Errorf("GetStoreType() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestIdentity_ToKeyAttributes_Success(t *testing.T) {
	t.Parallel()

	identity := Identity{
		Subject: Subject{CommonName: "Test CA"},
		Valid:   10,
		Keys:    DefaultKeyConfig(),
	}

	attrs, err := identity.ToKeyAttributes()
	if err != nil {
		t.Fatalf("ToKeyAttributes() unexpected error: %v", err)
	}

	if attrs == nil {
		t.Fatal("ToKeyAttributes() returned nil")
	}

	if attrs.CN != "Test CA" {
		t.Errorf("CN: expected %q, got %q", "Test CA", attrs.CN)
	}

	if attrs.KeyAlgorithm != x509.ECDSA {
		t.Errorf("KeyAlgorithm: expected %v, got %v", x509.ECDSA, attrs.KeyAlgorithm)
	}
}

func TestIdentity_ToKeyAttributes_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		identity Identity
	}{
		{
			name: "no keys",
			identity: Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   10,
				Keys:    nil,
			},
		},
		{
			name: "empty keys slice",
			identity: Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   10,
				Keys:    []*types.KeyConfig{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			attrs, err := tt.identity.ToKeyAttributes()
			if err == nil {
				t.Fatal("ToKeyAttributes() expected error, got nil")
			}
			if attrs != nil {
				t.Error("ToKeyAttributes() expected nil attrs on error")
			}
		})
	}
}

func TestIdentity_GetSignatureAlgorithm_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		keyConf  *types.KeyConfig
		expected x509.SignatureAlgorithm
	}{
		{
			name: "explicit ECDSA SHA256",
			keyConf: &types.KeyConfig{
				KeyAlgorithm:       types.AlgorithmECDSA,
				ECCConfig:          &types.ECCConfig{Curve: types.CurveP256},
				SignatureAlgorithm: types.SigECDSAWithSHA256,
			},
			expected: x509.ECDSAWithSHA256,
		},
		{
			name: "explicit RSA SHA256",
			keyConf: &types.KeyConfig{
				KeyAlgorithm:       types.AlgorithmRSA,
				RSAConfig:          &types.RSAConfig{KeySize: 2048},
				SignatureAlgorithm: types.SigSHA256WithRSA,
			},
			expected: x509.SHA256WithRSA,
		},
		{
			name: "derived ECDSA P-256",
			keyConf: &types.KeyConfig{
				KeyAlgorithm: types.AlgorithmECDSA,
				ECCConfig:    &types.ECCConfig{Curve: types.CurveP256},
			},
			expected: x509.ECDSAWithSHA256,
		},
		{
			name: "derived ECDSA P-384",
			keyConf: &types.KeyConfig{
				KeyAlgorithm: types.AlgorithmECDSA,
				ECCConfig:    &types.ECCConfig{Curve: types.CurveP384},
			},
			expected: x509.ECDSAWithSHA384,
		},
		{
			name: "derived ECDSA P-521",
			keyConf: &types.KeyConfig{
				KeyAlgorithm: types.AlgorithmECDSA,
				ECCConfig:    &types.ECCConfig{Curve: types.CurveP521},
			},
			expected: x509.ECDSAWithSHA512,
		},
		{
			name: "derived RSA",
			keyConf: &types.KeyConfig{
				KeyAlgorithm: types.AlgorithmRSA,
				RSAConfig:    &types.RSAConfig{KeySize: 2048},
			},
			expected: x509.SHA256WithRSA,
		},
		{
			name: "Ed25519",
			keyConf: &types.KeyConfig{
				KeyAlgorithm: types.AlgorithmEd25519,
			},
			expected: x509.PureEd25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			identity := Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   10,
				Keys:    []*types.KeyConfig{tt.keyConf},
			}

			sigAlgo, err := identity.GetSignatureAlgorithm()
			if err != nil {
				t.Fatalf("GetSignatureAlgorithm() unexpected error: %v", err)
			}
			if sigAlgo != tt.expected {
				t.Errorf("GetSignatureAlgorithm() = %v, expected %v", sigAlgo, tt.expected)
			}
		})
	}
}

func TestIdentity_GetSignatureAlgorithm_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		identity Identity
	}{
		{
			name: "no keys",
			identity: Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   10,
				Keys:    nil,
			},
		},
		{
			name: "empty keys slice",
			identity: Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   10,
				Keys:    []*types.KeyConfig{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sigAlgo, err := tt.identity.GetSignatureAlgorithm()
			if err == nil {
				t.Fatal("GetSignatureAlgorithm() expected error, got nil")
			}
			if sigAlgo != x509.UnknownSignatureAlgorithm {
				t.Errorf("GetSignatureAlgorithm() = %v, expected UnknownSignatureAlgorithm", sigAlgo)
			}
		})
	}
}

func TestIdentity_GetKeyAlgorithm_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		keyConf  *types.KeyConfig
		expected x509.PublicKeyAlgorithm
	}{
		{
			name:     "ECDSA",
			keyConf:  &types.KeyConfig{KeyAlgorithm: types.AlgorithmECDSA},
			expected: x509.ECDSA,
		},
		{
			name:     "RSA",
			keyConf:  &types.KeyConfig{KeyAlgorithm: types.AlgorithmRSA},
			expected: x509.RSA,
		},
		{
			name:     "Ed25519",
			keyConf:  &types.KeyConfig{KeyAlgorithm: types.AlgorithmEd25519},
			expected: x509.Ed25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			identity := Identity{
				Subject: Subject{CommonName: "Test CA"},
				Valid:   10,
				Keys:    []*types.KeyConfig{tt.keyConf},
			}

			keyAlgo, err := identity.GetKeyAlgorithm()
			if err != nil {
				t.Fatalf("GetKeyAlgorithm() unexpected error: %v", err)
			}
			if keyAlgo != tt.expected {
				t.Errorf("GetKeyAlgorithm() = %v, expected %v", keyAlgo, tt.expected)
			}
		})
	}
}

func TestIdentity_GetKeyAlgorithm_Error(t *testing.T) {
	t.Parallel()

	identity := Identity{
		Subject: Subject{CommonName: "Test CA"},
		Valid:   10,
		Keys:    nil,
	}

	keyAlgo, err := identity.GetKeyAlgorithm()
	if err == nil {
		t.Fatal("GetKeyAlgorithm() expected error, got nil")
	}
	if keyAlgo != x509.UnknownPublicKeyAlgorithm {
		t.Errorf("GetKeyAlgorithm() = %v, expected UnknownPublicKeyAlgorithm", keyAlgo)
	}
}

func TestIdentity_GetCurve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		keys        []*types.KeyConfig
		expectCurve bool
	}{
		{
			name:        "P-256 curve",
			keys:        []*types.KeyConfig{{ECCConfig: &types.ECCConfig{Curve: types.CurveP256}}},
			expectCurve: true,
		},
		{
			name:        "P-384 curve",
			keys:        []*types.KeyConfig{{ECCConfig: &types.ECCConfig{Curve: types.CurveP384}}},
			expectCurve: true,
		},
		{
			name:        "no keys",
			keys:        nil,
			expectCurve: false,
		},
		{
			name:        "empty curve",
			keys:        []*types.KeyConfig{{}},
			expectCurve: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			identity := Identity{Keys: tt.keys}
			curve := identity.GetCurve()
			if tt.expectCurve && curve == nil {
				t.Error("GetCurve() expected curve, got nil")
			}
			if !tt.expectCurve && curve != nil {
				t.Errorf("GetCurve() expected nil, got %v", curve)
			}
		})
	}
}

func TestIdentity_GetKeySize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		keys     []*types.KeyConfig
		expected int
	}{
		{
			name:     "RSA 2048",
			keys:     []*types.KeyConfig{{RSAConfig: &types.RSAConfig{KeySize: 2048}}},
			expected: 2048,
		},
		{
			name:     "RSA 4096",
			keys:     []*types.KeyConfig{{RSAConfig: &types.RSAConfig{KeySize: 4096}}},
			expected: 4096,
		},
		{
			name:     "no keys",
			keys:     nil,
			expected: 0,
		},
		{
			name:     "no key size set",
			keys:     []*types.KeyConfig{{}},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			identity := Identity{Keys: tt.keys}
			if got := identity.GetKeySize(); got != tt.expected {
				t.Errorf("GetKeySize() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestIdentity_GetCRLValidityDays(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		crlValidityDays int
		expected        int
	}{
		{
			name:            "custom CRL validity days",
			crlValidityDays: 30,
			expected:        30,
		},
		{
			name:            "zero returns default",
			crlValidityDays: 0,
			expected:        DefaultCRLValidityDays,
		},
		{
			name:            "negative returns default",
			crlValidityDays: -1,
			expected:        DefaultCRLValidityDays,
		},
		{
			name:            "default CRL validity days",
			crlValidityDays: DefaultCRLValidityDays,
			expected:        DefaultCRLValidityDays,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			identity := Identity{CRLValidityDays: tt.crlValidityDays}
			if got := identity.GetCRLValidityDays(); got != tt.expected {
				t.Errorf("GetCRLValidityDays() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

func TestIdentity_MaxPathLengthFields(t *testing.T) {
	t.Parallel()

	t.Run("default config root has MaxPathLength 1", func(t *testing.T) {
		t.Parallel()
		config := DefaultMultiIdentityCAConfig()
		root := config.RootIdentity()
		if root.MaxPathLength != 1 {
			t.Errorf("root MaxPathLength = %d, expected 1", root.MaxPathLength)
		}
		if root.MaxPathLengthZero {
			t.Error("root MaxPathLengthZero should be false")
		}
	})

	t.Run("default intermediate has MaxPathLengthZero true", func(t *testing.T) {
		t.Parallel()
		config := DefaultMultiIdentityCAConfigWithIntermediate()
		intermediates := config.IntermediateIdentities()
		if len(intermediates) == 0 {
			t.Fatal("expected intermediate identities")
		}
		intermediate := intermediates[0]
		if intermediate.MaxPathLength != 0 {
			t.Errorf("intermediate MaxPathLength = %d, expected 0", intermediate.MaxPathLength)
		}
		if !intermediate.MaxPathLengthZero {
			t.Error("intermediate MaxPathLengthZero should be true")
		}
	})
}

func TestIdentity_CertificateExtensionFields(t *testing.T) {
	t.Parallel()

	identity := Identity{
		Subject: Subject{CommonName: "Test CA"},
		Valid:   10,
		Keys:    DefaultKeyConfig(),
		CRLDistributionPoints: []string{
			"http://crl.example.com/ca.crl",
		},
		OCSPServers: []string{
			"http://ocsp.example.com",
		},
		IssuingCertificateURLs: []string{
			"http://ca.example.com/ca.crt",
		},
		PolicyIdentifiers: []string{
			"2.16.840.1.101.2.1",
		},
		CRLValidityDays: 14,
	}

	if len(identity.CRLDistributionPoints) != 1 || identity.CRLDistributionPoints[0] != "http://crl.example.com/ca.crl" {
		t.Errorf("CRLDistributionPoints = %v, expected single URL", identity.CRLDistributionPoints)
	}
	if len(identity.OCSPServers) != 1 || identity.OCSPServers[0] != "http://ocsp.example.com" {
		t.Errorf("OCSPServers = %v, expected single URL", identity.OCSPServers)
	}
	if len(identity.IssuingCertificateURLs) != 1 || identity.IssuingCertificateURLs[0] != "http://ca.example.com/ca.crt" {
		t.Errorf("IssuingCertificateURLs = %v, expected single URL", identity.IssuingCertificateURLs)
	}
	if len(identity.PolicyIdentifiers) != 1 || identity.PolicyIdentifiers[0] != "2.16.840.1.101.2.1" {
		t.Errorf("PolicyIdentifiers = %v, expected single OID", identity.PolicyIdentifiers)
	}
	if identity.CRLValidityDays != 14 {
		t.Errorf("CRLValidityDays = %d, expected 14", identity.CRLValidityDays)
	}
	if identity.GetCRLValidityDays() != 14 {
		t.Errorf("GetCRLValidityDays() = %d, expected 14", identity.GetCRLValidityDays())
	}
}

// =============================================================================
// MultiIdentityCAConfig Tests
// =============================================================================

func TestMultiIdentityCAConfig_Validate_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *MultiIdentityCAConfig
	}{
		{
			name:   "default config",
			config: DefaultMultiIdentityCAConfig(),
		},
		{
			name:   "default with intermediate",
			config: DefaultMultiIdentityCAConfigWithIntermediate(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.config.Validate(); err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestMultiIdentityCAConfig_Validate_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      *MultiIdentityCAConfig
		expectedErr error
	}{
		{
			name:        "no identities",
			config:      &MultiIdentityCAConfig{Identity: []Identity{}},
			expectedErr: ErrInvalidConfig,
		},
		{
			name: "first identity not root",
			config: &MultiIdentityCAConfig{
				Identity: []Identity{
					{
						Subject: Subject{CommonName: "Not Root"},
						Valid:   10,
						Keys:    DefaultKeyConfig(),
						IsRoot:  false,
					},
				},
			},
			expectedErr: ErrInvalidConfig,
		},
		{
			name: "invalid selected CA index",
			config: &MultiIdentityCAConfig{
				Identity: []Identity{
					{
						Subject: Subject{CommonName: "Root CA"},
						Valid:   10,
						Keys:    DefaultKeyConfig(),
						IsRoot:  true,
					},
				},
				SelectedCA: 5,
			},
			expectedErr: ErrInvalidConfig,
		},
		{
			name: "negative selected CA index",
			config: &MultiIdentityCAConfig{
				Identity: []Identity{
					{
						Subject: Subject{CommonName: "Root CA"},
						Valid:   10,
						Keys:    DefaultKeyConfig(),
						IsRoot:  true,
					},
				},
				SelectedCA: -1,
			},
			expectedErr: ErrInvalidConfig,
		},
		{
			name: "invalid identity in list",
			config: &MultiIdentityCAConfig{
				Identity: []Identity{
					{
						Subject: Subject{CommonName: "Root CA"},
						Valid:   10,
						Keys:    DefaultKeyConfig(),
						IsRoot:  true,
					},
					{
						Subject: Subject{CommonName: ""}, // Invalid - no CN
						Valid:   5,
						Keys:    DefaultKeyConfig(),
						IsRoot:  false,
					},
				},
				SelectedCA: 1,
			},
			expectedErr: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
			if err == nil {
				t.Fatal("Validate() expected error, got nil")
			}
			if !errors.Is(err, tt.expectedErr) {
				t.Errorf("Validate() error = %v, expected %v", err, tt.expectedErr)
			}
		})
	}
}

func TestMultiIdentityCAConfig_HasIntermediate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *MultiIdentityCAConfig
		expected bool
	}{
		{
			name:     "only root",
			config:   DefaultMultiIdentityCAConfig(),
			expected: false,
		},
		{
			name:     "with intermediate",
			config:   DefaultMultiIdentityCAConfigWithIntermediate(),
			expected: true,
		},
		{
			name:     "empty identities",
			config:   &MultiIdentityCAConfig{Identity: []Identity{}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.config.HasIntermediate(); got != tt.expected {
				t.Errorf("HasIntermediate() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestMultiIdentityCAConfig_RootIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     *MultiIdentityCAConfig
		expectRoot bool
	}{
		{
			name:       "default config",
			config:     DefaultMultiIdentityCAConfig(),
			expectRoot: true,
		},
		{
			name:       "with intermediate",
			config:     DefaultMultiIdentityCAConfigWithIntermediate(),
			expectRoot: true,
		},
		{
			name:       "empty identities",
			config:     &MultiIdentityCAConfig{Identity: []Identity{}},
			expectRoot: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := tt.config.RootIdentity()
			if tt.expectRoot && root == nil {
				t.Error("RootIdentity() expected non-nil, got nil")
			}
			if !tt.expectRoot && root != nil {
				t.Errorf("RootIdentity() expected nil, got %v", root)
			}
		})
	}
}

func TestMultiIdentityCAConfig_IssuingIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     *MultiIdentityCAConfig
		selectedCA int
		expectCN   string
		expectNil  bool
	}{
		{
			name:       "root as issuing",
			config:     DefaultMultiIdentityCAConfig(),
			selectedCA: 0,
			expectCN:   "Root CA",
			expectNil:  false,
		},
		{
			name:       "intermediate as issuing",
			config:     DefaultMultiIdentityCAConfigWithIntermediate(),
			selectedCA: 1,
			expectCN:   "Intermediate CA",
			expectNil:  false,
		},
		{
			name: "invalid selected CA",
			config: &MultiIdentityCAConfig{
				Identity: []Identity{
					{Subject: Subject{CommonName: "Root CA"}, Valid: 10, Keys: DefaultKeyConfig(), IsRoot: true},
				},
				SelectedCA: 5,
			},
			selectedCA: 5,
			expectNil:  true,
		},
		{
			name: "negative selected CA",
			config: &MultiIdentityCAConfig{
				Identity: []Identity{
					{Subject: Subject{CommonName: "Root CA"}, Valid: 10, Keys: DefaultKeyConfig(), IsRoot: true},
				},
				SelectedCA: -1,
			},
			selectedCA: -1,
			expectNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			issuing := tt.config.IssuingIdentity()
			if tt.expectNil {
				if issuing != nil {
					t.Errorf("IssuingIdentity() expected nil, got %v", issuing)
				}
				return
			}
			if issuing == nil {
				t.Fatal("IssuingIdentity() expected non-nil, got nil")
			}
			if issuing.Subject.CommonName != tt.expectCN {
				t.Errorf("IssuingIdentity().Subject.CommonName = %q, expected %q", issuing.Subject.CommonName, tt.expectCN)
			}
		})
	}
}

func TestMultiIdentityCAConfig_IntermediateIdentities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *MultiIdentityCAConfig
		expected int
	}{
		{
			name:     "only root",
			config:   DefaultMultiIdentityCAConfig(),
			expected: 0,
		},
		{
			name:     "with one intermediate",
			config:   DefaultMultiIdentityCAConfigWithIntermediate(),
			expected: 1,
		},
		{
			name:     "empty identities",
			config:   &MultiIdentityCAConfig{Identity: []Identity{}},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			intermediates := tt.config.IntermediateIdentities()
			if len(intermediates) != tt.expected {
				t.Errorf("IntermediateIdentities() length = %d, expected %d", len(intermediates), tt.expected)
			}
		})
	}
}

func TestMultiIdentityCAConfig_GetDefaultValidityDays(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *MultiIdentityCAConfig
		expected int
	}{
		{
			name:     "default config",
			config:   DefaultMultiIdentityCAConfig(),
			expected: DefaultCertValidityDays,
		},
		{
			name: "custom validity days",
			config: &MultiIdentityCAConfig{
				DefaultValidityDays: 730,
			},
			expected: 730,
		},
		{
			name: "zero uses default",
			config: &MultiIdentityCAConfig{
				DefaultValidityDays: 0,
			},
			expected: DefaultCertValidityDays,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.config.GetDefaultValidityDays(); got != tt.expected {
				t.Errorf("GetDefaultValidityDays() = %d, expected %d", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// ConfigBuilder Tests
// =============================================================================

func TestConfigBuilder_Success(t *testing.T) {
	t.Parallel()

	config, err := NewConfigBuilder().
		WithRootCA(
			Subject{CommonName: "My Root CA", Organization: "My Org"},
			10,
			nil, // Use defaults
			"software",
		).
		WithIntermediateCA(
			Subject{CommonName: "My Intermediate CA", Organization: "My Org"},
			5,
			nil, // Use defaults
			"software",
			"My Root CA",
		).
		WithSelectedCA(1).
		WithDefaultValidityDays(365).
		WithHomeDir("/tmp/ca").
		WithIncludeLocalhostSANS(true).
		Build()

	if err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}

	if config == nil {
		t.Fatal("Build() returned nil config")
	}

	if len(config.Identity) != 2 {
		t.Errorf("expected 2 identities, got %d", len(config.Identity))
	}

	if config.Identity[0].Subject.CommonName != "My Root CA" {
		t.Errorf("Root CN: expected %q, got %q", "My Root CA", config.Identity[0].Subject.CommonName)
	}

	if config.Identity[1].Subject.CommonName != "My Intermediate CA" {
		t.Errorf("Intermediate CN: expected %q, got %q", "My Intermediate CA", config.Identity[1].Subject.CommonName)
	}

	if config.SelectedCA != 1 {
		t.Errorf("SelectedCA: expected 1, got %d", config.SelectedCA)
	}

	if config.DefaultValidityDays != 365 {
		t.Errorf("DefaultValidityDays: expected 365, got %d", config.DefaultValidityDays)
	}

	if config.HomeDir != "/tmp/ca" {
		t.Errorf("HomeDir: expected %q, got %q", "/tmp/ca", config.HomeDir)
	}

	if !config.IncludeLocalhostSANS {
		t.Error("IncludeLocalhostSANS: expected true, got false")
	}
}

func TestConfigBuilder_Error_NoRootCA(t *testing.T) {
	t.Parallel()

	_, err := NewConfigBuilder().
		WithIntermediateCA(
			Subject{CommonName: "Intermediate CA"},
			5,
			nil,
			"software",
			"Root CA",
		).
		Build()

	if err == nil {
		t.Fatal("Build() expected error for missing root CA, got nil")
	}
}

func TestConfigBuilder_Error_InvalidSelectedCA(t *testing.T) {
	t.Parallel()

	_, err := NewConfigBuilder().
		WithRootCA(
			Subject{CommonName: "Root CA"},
			10,
			nil,
			"software",
		).
		WithSelectedCA(5). // Invalid index
		Build()

	if err == nil {
		t.Fatal("Build() expected error for invalid selected CA index, got nil")
	}
}

func TestConfigBuilder_DefaultKeys(t *testing.T) {
	t.Parallel()

	config, err := NewConfigBuilder().
		WithRootCA(
			Subject{CommonName: "Root CA"},
			10,
			nil, // Should use default keys
			"software",
		).
		Build()

	if err != nil {
		t.Fatalf("Build() unexpected error: %v", err)
	}

	if len(config.Identity[0].Keys) == 0 {
		t.Error("expected default keys to be set")
	}

	if string(config.Identity[0].Keys[0].KeyAlgorithm) != DefaultKeyAlgorithm {
		t.Errorf("KeyAlgorithm: expected %q, got %q", DefaultKeyAlgorithm, config.Identity[0].Keys[0].KeyAlgorithm)
	}
}

func TestConfigBuilder_SkipsAfterError(t *testing.T) {
	t.Parallel()

	// Create a builder that already has an error
	builder := &ConfigBuilder{
		config: &MultiIdentityCAConfig{},
		err:    errors.New("pre-existing error"),
	}

	// All With* methods should return immediately without modifying the config
	result := builder.
		WithRootCA(Subject{}, 1, nil, "").
		WithIntermediateCA(Subject{}, 1, nil, "", "").
		WithSelectedCA(5).
		WithDefaultValidityDays(365).
		WithHomeDir("/test").
		WithIncludeLocalhostSANS(true)

	// Builder should still have the original error
	_, err := result.Build()
	if err == nil {
		t.Fatal("expected error from Build()")
	}
	if err.Error() != "pre-existing error" {
		t.Fatalf("expected pre-existing error, got: %v", err)
	}

	// Config should not have been modified
	if builder.config.SelectedCA != 0 {
		t.Fatal("SelectedCA should not have been modified")
	}
	if builder.config.DefaultValidityDays != 0 {
		t.Fatal("DefaultValidityDays should not have been modified")
	}
	if builder.config.HomeDir != "" {
		t.Fatal("HomeDir should not have been modified")
	}
}

func TestConfigBuilder_BuildError(t *testing.T) {
	t.Parallel()

	// Test Build with pre-existing error
	builder := &ConfigBuilder{
		config: &MultiIdentityCAConfig{},
		err:    errors.New("build error"),
	}
	_, err := builder.Build()
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "build error" {
		t.Fatalf("expected build error, got: %v", err)
	}
}

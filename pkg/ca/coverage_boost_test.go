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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Intermediate CA Certificate Creation Tests
// =============================================================================

// setupTestCAWithRealIntermediate creates a CA that actually exercises
// the createIntermediateCertificates code path by directly constructing
// the CA struct with the full multi-identity config (root + intermediate).
func setupTestCAWithRealIntermediate(t *testing.T) *CA {
	t.Helper()

	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: certStorage,
	})
	require.NoError(t, err)

	cs, err := certstore.New(&certstore.Config{
		DAOs: testutil.NewMemoryDAOFactory(),
	})
	require.NoError(t, err)

	config := DefaultMultiIdentityCAConfigWithIntermediate()
	config.Identity[0].Subject.CommonName = "Test Root CA"
	config.Identity[0].Subject.Organization = "Test Organization"
	config.Identity[0].Keys[0].KeyType = "CA"
	config.Identity[1].Subject.CommonName = "Test Intermediate CA"
	config.Identity[1].Subject.Organization = "Test Organization"
	config.Identity[1].Keys[0].KeyType = "CA"

	// Directly construct CA with the full multi-identity config
	// so that createIntermediateCertificates is exercised during Init.
	ca := &CA{
		config:          config,
		keyStore:        backend,
		keystoreMap:     map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:       cs,
		revocationStore: storage.NewMemory(),
		revocations:     make(map[string]*RevocationInfo),
		serialGen:       NewSerialGenerator(NewMemoryStorage()),
		profiles:        NewDefaultProfileRegistry(),
	}

	err = ca.Init(context.Background())
	require.NoError(t, err)
	return ca
}

// =============================================================================
// Load Tests with Intermediate
// =============================================================================

func TestCA_Load_NilRootIdentity(t *testing.T) {
	ca := &CA{
		config:      &MultiIdentityCAConfig{Identity: []Identity{}},
		revocations: make(map[string]*RevocationInfo),
	}
	err := ca.Load(context.Background())
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// VerifySignature Tests
// =============================================================================

func TestCA_VerifySignature_InvalidSignature(t *testing.T) {
	ca := setupTestCA(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "fake-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = ca.VerifySignature(cert)
	assert.Error(t, err)
}

// =============================================================================
// Verify Tests (certificate chain verification)
// =============================================================================

func TestCA_Verify_UnrecognizedIssuer(t *testing.T) {
	ca := setupTestCA(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(55555),
		Subject:      pkix.Name{CommonName: "unknown-issuer.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"unknown-issuer.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	_, err = ca.Verify(cert)
	assert.ErrorIs(t, err, ErrInvalidCertificateChain)
}

// =============================================================================
// signatureAlgorithmToName Exhaustive Tests
// =============================================================================

func TestSignatureAlgorithmToName_AllAlgorithms(t *testing.T) {
	tests := []struct {
		algo     x509.SignatureAlgorithm
		expected types.SignatureAlgorithmName
	}{
		{x509.MD2WithRSA, types.SigMD2WithRSA},
		{x509.MD5WithRSA, types.SigMD5WithRSA},
		{x509.SHA1WithRSA, types.SigSHA1WithRSA},
		{x509.SHA256WithRSA, types.SigSHA256WithRSA},
		{x509.SHA384WithRSA, types.SigSHA384WithRSA},
		{x509.SHA512WithRSA, types.SigSHA512WithRSA},
		{x509.SHA256WithRSAPSS, types.SigSHA256WithRSAPSS},
		{x509.SHA384WithRSAPSS, types.SigSHA384WithRSAPSS},
		{x509.SHA512WithRSAPSS, types.SigSHA512WithRSAPSS},
		{x509.DSAWithSHA1, types.SigDSAWithSHA1},
		{x509.DSAWithSHA256, types.SigDSAWithSHA256},
		{x509.ECDSAWithSHA1, types.SigECDSAWithSHA1},
		{x509.ECDSAWithSHA256, types.SigECDSAWithSHA256},
		{x509.ECDSAWithSHA384, types.SigECDSAWithSHA384},
		{x509.ECDSAWithSHA512, types.SigECDSAWithSHA512},
		{x509.PureEd25519, types.SigEd25519},
		{x509.UnknownSignatureAlgorithm, types.SigECDSAWithSHA256},
	}

	for _, tt := range tests {
		t.Run(tt.algo.String(), func(t *testing.T) {
			result := signatureAlgorithmToName(tt.algo)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Params.Validate Tests
// =============================================================================

func TestParams_Validate_NilKeyAttributes(t *testing.T) {
	p := &Params{
		Config:        &CAConfig{Identity: "test", Subject: &Subject{CommonName: "test"}},
		KeyAttributes: nil,
	}
	err := p.Validate()
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestParams_Validate_NilKeyStore(t *testing.T) {
	p := &Params{
		Config:        &CAConfig{Identity: "test", Subject: &Subject{CommonName: "test"}},
		KeyAttributes: &types.KeyAttributes{},
		KeyStore:      nil,
	}
	err := p.Validate()
	assert.ErrorIs(t, err, ErrKeyStoreRequired)
}

func TestParams_Validate_NilCertStore(t *testing.T) {
	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: certStorage})
	require.NoError(t, err)

	p := &Params{
		Config:          &CAConfig{Identity: "test", Subject: &Subject{CommonName: "test"}},
		KeyAttributes:   &types.KeyAttributes{},
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
	}
	err = p.Validate()
	assert.ErrorIs(t, err, ErrCertStoreRequired)
}

// =============================================================================
// New() Tests
// =============================================================================

func TestNew_NilParams(t *testing.T) {
	_, err := New(nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// caConfigToMultiIdentity Tests
// =============================================================================

func TestCaConfigToMultiIdentity_EmptySubject(t *testing.T) {
	cfg := &CAConfig{Identity: "from-identity"}
	multi := caConfigToMultiIdentity(cfg, nil)
	assert.Equal(t, "from-identity", multi.Identity[0].Subject.CommonName)
}

// =============================================================================
// determineSignatureAlgorithm Tests
// =============================================================================

func TestDetermineSignatureAlgorithm_ECDSAP521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSAWithSHA512, determineSignatureAlgorithm(&key.PublicKey))
}

// =============================================================================
// SignCSR with custom options
// =============================================================================

func TestCA_SignCSR_WithOptions(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "custom-options.example.com")
	opts := &SignOptions{
		TenantID:     testTenant,
		ValidityDays: 90,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Subject:      &Subject{Organization: "Custom Org"},
		SANS:         &SubjectAlternativeNames{DNS: []string{"extra.example.com"}},
		NotBefore:    time.Now().Add(-time.Hour),
	}

	cert, err := ca.SignCSR(context.Background(), csrPEM, opts)
	require.NoError(t, err)
	assert.Contains(t, cert.DNSNames, "extra.example.com")
	assert.Equal(t, []string{"Custom Org"}, cert.Subject.Organization)
}

// =============================================================================
// IsRevoked edge cases
// =============================================================================

func TestCA_IsRevoked_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.IsRevoked(big.NewInt(1))
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// TLSCertificate with nonexistent cert
// =============================================================================

func TestCA_TLSCertificate_CertNotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.TLSCertificate(context.Background(), &types.KeyAttributes{CN: "nonexistent.example.com"})
	assert.ErrorIs(t, err, ErrTLSConfigFailed)
}

func TestCAProfile_Apply_NilTemplate(t *testing.T) {
	profile := NewCAProfile()
	err := profile.Apply(nil, nil)
	require.ErrorIs(t, err, ErrInvalidProfile)
}

func TestCustomCAProfile_Apply_NilTemplate(t *testing.T) {
	profile := NewProfileBuilder("custom-ca").AsCA().Build()
	err := profile.Apply(nil, nil)
	require.ErrorIs(t, err, ErrInvalidProfile)
}

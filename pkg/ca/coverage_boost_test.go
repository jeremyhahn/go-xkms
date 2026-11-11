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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	backendpkg "github.com/jeremyhahn/go-xkms/pkg/backend"
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

func TestCA_CreateIntermediateCertificates_SelectedCA(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	require.NotNil(t, ca.intermediateCert)
	issuingCert := ca.getIssuingCertificate()
	assert.Equal(t, ca.intermediateCert, issuingCert)
}

func TestCA_IntermediateCA_SignCSR(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	csrPEM := generateTestCSRPEM(t, "signed-by-intermediate.example.com")
	cert, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{TenantID: testTenant})
	require.NoError(t, err)

	err = cert.CheckSignatureFrom(ca.intermediateCert)
	assert.NoError(t, err)
}

func TestCA_IntermediateCA_Verify(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	request := &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "verify-intermediate.example.com", Organization: "Test"},
		SANS:     &SubjectAlternativeNames{DNS: []string{"verify-intermediate.example.com"}},
		Valid:    365,
	}

	issued, err := ca.IssueCertificate(context.Background(), request)
	require.NoError(t, err)

	chains, err := ca.Verify(issued.Certificate)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

func TestCA_IntermediateCA_CABundle(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	bundle, err := ca.CABundle()
	require.NoError(t, err)

	certs, err := ParsePEMCertificateChain(bundle)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestCA_IntermediateCA_CACertificate(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	cert, err := ca.CACertificate()
	require.NoError(t, err)
	assert.Equal(t, "Test Intermediate CA", cert.Subject.CommonName)
}

func TestCA_IntermediateCA_WithSANSAndExtensions(t *testing.T) {
	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)

	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: certStorage})
	require.NoError(t, err)

	cs, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)

	config := DefaultMultiIdentityCAConfigWithIntermediate()
	config.Identity[0].Subject.CommonName = "Root CA SANS"
	config.Identity[0].Keys[0].KeyType = "CA"
	config.Identity[1].Subject.CommonName = "Intermediate CA SANS"
	config.Identity[1].Keys[0].KeyType = "CA"
	config.Identity[1].SANS = &SubjectAlternativeNames{
		DNS:   []string{"intermediate.example.com"},
		Email: []string{"admin@example.com"},
	}
	config.Identity[1].CRLDistributionPoints = []string{"http://crl.example.com/intermediate.crl"}
	config.Identity[1].OCSPServers = []string{"http://ocsp.example.com"}
	config.Identity[1].IssuingCertificateURLs = []string{"http://ca.example.com/intermediate.cer"}

	ca := &CA{
		config:      config,
		keyStore:    backend,
		keystoreMap: map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	require.NoError(t, ca.Init(context.Background()))

	require.NotNil(t, ca.intermediateCert)
	assert.Contains(t, ca.intermediateCert.DNSNames, "intermediate.example.com")
	assert.Contains(t, ca.intermediateCert.EmailAddresses, "admin@example.com")
	assert.Contains(t, ca.intermediateCert.CRLDistributionPoints, "http://crl.example.com/intermediate.crl")
	assert.Contains(t, ca.intermediateCert.OCSPServer, "http://ocsp.example.com")
	assert.Contains(t, ca.intermediateCert.IssuingCertificateURL, "http://ca.example.com/intermediate.cer")
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

func TestCA_VerifySignature_WithIntermediate(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	request := &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "verify-sig-inter.example.com", Organization: "Test"},
		SANS:     &SubjectAlternativeNames{DNS: []string{"verify-sig-inter.example.com"}},
		Valid:    365,
	}

	issued, err := ca.IssueCertificate(context.Background(), request)
	require.NoError(t, err)

	err = ca.VerifySignature(issued.Certificate)
	assert.NoError(t, err)
}

// =============================================================================
// Verify Tests (certificate chain verification)
// =============================================================================

func TestCA_Verify_RevokedCert(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "revoked-verify.example.com", Organization: "Test"},
		SANS:     &SubjectAlternativeNames{DNS: []string{"revoked-verify.example.com"}},
		Valid:    365,
	}

	issued, err := ca.IssueCertificate(context.Background(), request)
	require.NoError(t, err)

	err = ca.Revoke(context.Background(), issued.Certificate.SerialNumber, 1)
	require.NoError(t, err)

	_, err = ca.Verify(issued.Certificate)
	assert.ErrorIs(t, err, ErrCertificateRevoked)
}

func TestCA_Verify_WithIntermediateCA(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	request := &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "verify-chain.example.com", Organization: "Test"},
		SANS:     &SubjectAlternativeNames{DNS: []string{"verify-chain.example.com"}},
		Valid:    365,
	}

	issued, err := ca.IssueCertificate(context.Background(), request)
	require.NoError(t, err)

	chains, err := ca.Verify(issued.Certificate)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
	assert.GreaterOrEqual(t, len(chains[0]), 2)
}

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

func TestNewFromMultiIdentityConfig_NilParams(t *testing.T) {
	_, err := NewFromMultiIdentityConfig(nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// caConfigToMultiIdentity Tests
// =============================================================================

func TestCaConfigToMultiIdentity_WithECCKeyAttrs(t *testing.T) {
	cfg := &CAConfig{
		Identity:     "test-ca",
		Subject:      &Subject{CommonName: "Test CA"},
		ValidityDays: 3650,
		IsRootCA:     true,
	}
	attrs := &types.KeyAttributes{
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()},
	}

	multi := caConfigToMultiIdentity(cfg, attrs)
	require.NotNil(t, multi)
	assert.Equal(t, "Test CA", multi.Identity[0].Subject.CommonName)
}

func TestCaConfigToMultiIdentity_WithRSAKeyAttrs(t *testing.T) {
	cfg := &CAConfig{
		Identity: "rsa-ca", Subject: &Subject{CommonName: "RSA CA"},
		ValidityDays: 3650, IsRootCA: true,
	}
	attrs := &types.KeyAttributes{
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 4096},
	}

	multi := caConfigToMultiIdentity(cfg, attrs)
	assert.Len(t, multi.Identity[0].Keys, 1)
}

func TestCaConfigToMultiIdentity_NilKeyAttrs(t *testing.T) {
	cfg := &CAConfig{Identity: "test-ca", Subject: &Subject{CommonName: "Test CA"}, IsRootCA: true}
	multi := caConfigToMultiIdentity(cfg, nil)
	assert.NotEmpty(t, multi.Identity[0].Keys)
}

func TestCaConfigToMultiIdentity_IntermediateDefaults(t *testing.T) {
	cfg := &CAConfig{Identity: "intermediate", Subject: &Subject{CommonName: "Intermediate"}, IsRootCA: false}
	multi := caConfigToMultiIdentity(cfg, nil)
	assert.Equal(t, DefaultIntermediateValidityYears, multi.Identity[0].Valid)
}

func TestCaConfigToMultiIdentity_EmptyStoreType(t *testing.T) {
	cfg := &CAConfig{Identity: "test", StoreType: ""}
	multi := caConfigToMultiIdentity(cfg, nil)
	assert.Equal(t, types.StoreSoftware, multi.Identity[0].GetStoreType())
}

// =============================================================================
// getOrGenerateCAKey Tests
// =============================================================================

func TestCA_GetOrGenerateCAKey_ExistingKey(t *testing.T) {
	ca := setupTestCA(t)
	rootIdentity := ca.config.RootIdentity()
	require.NotNil(t, rootIdentity)

	attrs, err := ca.getCAKeyAttributes(t.Context(), rootIdentity)
	require.NoError(t, err)

	key, err := ca.getOrGenerateCAKey(context.Background(), attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)
	assert.NotNil(t, signer.Public())
}

// TestCA_GetOrGenerateCAKey_UnsupportedAlgorithm exercises a key whose
// algorithm the backend itself rejects (KeyAttributes.Validate fails DSA
// before any "does the key exist" check runs). That is a genuine backend
// failure, not a not-found result, so getOrGenerateCAKey must fail closed
// with ErrKeyRetrievalFailed rather than fall through to the generation
// switch's ErrInvalidKeyAlgorithm branch -- go-xkms#801: only
// errors.Is(err, backend.ErrKeyNotFound) may fall through to generation.
func TestCA_GetOrGenerateCAKey_UnsupportedAlgorithm(t *testing.T) {
	ca := setupTestCA(t)
	attrs := &types.KeyAttributes{
		CN: "unsupported-algo", KeyAlgorithm: x509.DSA, KeyType: types.KeyTypeCA, StoreType: types.StoreSoftware,
	}
	_, err := ca.getOrGenerateCAKey(context.Background(), attrs)
	assert.ErrorIs(t, err, ErrKeyRetrievalFailed)
	assert.False(t, errors.Is(err, backendpkg.ErrKeyNotFound))
	assert.Contains(t, err.Error(), "DSA")
}

// =============================================================================
// getCAKeyAttributes Tests
// =============================================================================

func TestCA_GetCAKeyAttributes_SetsKeyTypeCA(t *testing.T) {
	ca := setupTestCA(t)
	identity := &Identity{Subject: Subject{CommonName: "test"}, Keys: DefaultKeyConfig()}
	identity.Keys[0].KeyType = ""

	attrs, err := ca.getCAKeyAttributes(t.Context(), identity)
	require.NoError(t, err)
	assert.Equal(t, types.KeyTypeCA, attrs.KeyType)
}

// =============================================================================
// getSigner Tests
// =============================================================================

// =============================================================================
// determineSignatureAlgorithm Tests
// =============================================================================

func TestDetermineSignatureAlgorithm_ECDSAP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSAWithSHA256, determineSignatureAlgorithm(&key.PublicKey))
}

func TestDetermineSignatureAlgorithm_ECDSAP384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSAWithSHA384, determineSignatureAlgorithm(&key.PublicKey))
}

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

func TestCA_SignCSR_WithProfile(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "profile-signed.example.com")
	opts := &SignOptions{TenantID: testTenant, Profile: "server"}

	cert, err := ca.SignCSR(context.Background(), csrPEM, opts)
	require.NoError(t, err)
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestCA_SignCSR_WithProfileAndCustomValidity(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "profile-custom-valid.example.com")
	opts := &SignOptions{TenantID: testTenant, Profile: "client", ValidityDays: 30}

	cert, err := ca.SignCSR(context.Background(), csrPEM, opts)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestCA_SignCSR_InvalidProfile(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "bad-profile.example.com")
	_, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{TenantID: testTenant, Profile: "nonexistent-profile"})
	assert.Error(t, err)
}

func TestCA_SignCSR_InvalidCSR(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.SignCSR(context.Background(), []byte("not a CSR"), &SignOptions{TenantID: testTenant})
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

func TestCA_SignCSR_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.SignCSR(context.Background(), []byte("unused"), &SignOptions{TenantID: testTenant})
	assert.ErrorIs(t, err, ErrNotInitialized)
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
// mergeSubjects edge cases
// =============================================================================

// =============================================================================
// createRootCertificate with SANs and extensions
// =============================================================================

func TestCA_Init_RootWithSANSAndExtensions(t *testing.T) {
	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)

	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: certStorage})
	require.NoError(t, err)

	cs, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Root With SANs"
	config.Identity[0].Keys[0].KeyType = "CA"
	config.Identity[0].SANS = &SubjectAlternativeNames{
		DNS:   []string{"root.example.com"},
		Email: []string{"root@example.com"},
	}
	config.Identity[0].CRLDistributionPoints = []string{"http://crl.example.com/root.crl"}
	config.Identity[0].OCSPServers = []string{"http://ocsp.example.com"}
	config.Identity[0].IssuingCertificateURLs = []string{"http://ca.example.com/root.cer"}

	ca := &CA{
		config:      config,
		keyStore:    backend,
		keystoreMap: map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	require.NoError(t, ca.Init(context.Background()))

	assert.Contains(t, ca.rootCert.DNSNames, "root.example.com")
	assert.Contains(t, ca.rootCert.EmailAddresses, "root@example.com")
	assert.Contains(t, ca.rootCert.CRLDistributionPoints, "http://crl.example.com/root.crl")
	assert.Contains(t, ca.rootCert.OCSPServer, "http://ocsp.example.com")
}

// =============================================================================
// Init error: already initialized
// =============================================================================

// =============================================================================
// GenerateCRL with various revocation reasons
// =============================================================================

// =============================================================================
// New() with Params (flat config path)
// =============================================================================

func TestNew_Success(t *testing.T) {
	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: certStorage})
	require.NoError(t, err)

	cs, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)

	params := &Params{
		Config: &CAConfig{
			Identity: "flat-ca",
			Subject:  &Subject{CommonName: "Flat CA"},
			IsRootCA: true,
		},
		KeyAttributes: &types.KeyAttributes{
			CN: "Flat CA", KeyAlgorithm: x509.ECDSA, KeyType: types.KeyTypeCA,
			ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
		},
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
	}

	caIface, err := New(params)
	require.NoError(t, err)
	require.NoError(t, caIface.Init(context.Background()))
	assert.True(t, caIface.IsInitialized())
}

func TestNew_WithCustomSerialGenAndProfiles(t *testing.T) {
	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: certStorage})
	require.NoError(t, err)

	cs, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)

	customSerialGen := NewSerialGenerator(NewMemoryStorage())
	customProfiles := NewDefaultProfileRegistry()

	params := &Params{
		Config: &CAConfig{
			Identity: "custom-ca",
			Subject:  &Subject{CommonName: "Custom CA"},
			IsRootCA: true,
		},
		KeyAttributes: &types.KeyAttributes{
			CN: "Custom CA", KeyAlgorithm: x509.ECDSA, KeyType: types.KeyTypeCA,
			ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
		},
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		SerialGen:       customSerialGen,
		Profiles:        customProfiles,
	}

	caIface, err := New(params)
	require.NoError(t, err)

	concreteCA := caIface.(*CA)
	assert.Equal(t, customSerialGen, concreteCA.serialGen)
	assert.Equal(t, customProfiles, concreteCA.profiles)
}

// =============================================================================
// getIssuingCertificate Tests
// =============================================================================

func TestCA_GetIssuingCertificate_IntermediatePreferred(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	cert := ca.getIssuingCertificate()
	assert.Equal(t, ca.intermediateCert, cert)
}

func TestCA_GetIssuingCertificate_FallsBackToRoot(t *testing.T) {
	ca := setupTestCA(t)
	cert := ca.getIssuingCertificate()
	assert.Equal(t, ca.rootCert, cert)
}

// =============================================================================
// buildCAPool Tests
// =============================================================================

func TestCA_BuildCAPool_WithIntermediate(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	pool := ca.buildCAPool()
	require.NotNil(t, pool)
}

// =============================================================================
// TLSCertificate with nonexistent cert
// =============================================================================

func TestCA_TLSCertificate_CertNotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.TLSCertificate(context.Background(), &types.KeyAttributes{CN: "nonexistent.example.com"})
	assert.ErrorIs(t, err, ErrTLSConfigFailed)
}

func TestCAProfile_Apply(t *testing.T) {
	profile := NewCAProfile()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	err := profile.Apply(template, &CertificateRequest{
		TenantID:       testTenant,
		MaxPathLen:     2,
		MaxPathLenZero: false,
	})
	require.NoError(t, err)
	assert.True(t, template.IsCA)
	assert.True(t, template.BasicConstraintsValid)
	assert.Equal(t, 2, template.MaxPathLen)
}

func TestCAProfile_Apply_NilTemplate(t *testing.T) {
	profile := NewCAProfile()
	err := profile.Apply(nil, nil)
	require.ErrorIs(t, err, ErrInvalidProfile)
}

func TestCustomCAProfile_Apply(t *testing.T) {
	profile := NewProfileBuilder("custom-ca").
		WithKeyUsage(x509.KeyUsageCertSign | x509.KeyUsageCRLSign).
		AsCA().
		Build()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	err := profile.Apply(template, &CertificateRequest{
		TenantID:       testTenant,
		MaxPathLen:     1,
		MaxPathLenZero: false,
	})
	require.NoError(t, err)
	assert.True(t, template.IsCA)
	assert.True(t, template.BasicConstraintsValid)
	assert.Equal(t, 1, template.MaxPathLen)
}

func TestCustomCAProfile_Apply_NilTemplate(t *testing.T) {
	profile := NewProfileBuilder("custom-ca").AsCA().Build()
	err := profile.Apply(nil, nil)
	require.ErrorIs(t, err, ErrInvalidProfile)
}

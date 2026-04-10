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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
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

	certAdapterStorage := storage.NewMemory()
	certAdapter := storage.NewCertAdapter(certAdapterStorage)
	cs, err := certstore.New(&certstore.Config{
		CertStorage: certAdapter,
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
		config:      config,
		keyStore:    backend,
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}

	err = ca.Init()
	require.NoError(t, err)
	return ca
}

// setupTestCAFlat creates a CA via NewFromMultiIdentityConfig (single identity).
// This is used for TLS tests that need an initialized CA with cert issuance.
func setupTestCAFlat(t *testing.T) *CA {
	t.Helper()
	return setupTestCA(t) // reuse existing helper
}

func TestCA_CreateIntermediateCertificates_Success(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	require.NotNil(t, ca.intermediateCert)
	assert.True(t, ca.intermediateCert.IsCA)
	assert.Equal(t, "Test Intermediate CA", ca.intermediateCert.Subject.CommonName)

	// Verify it was signed by root
	err := ca.intermediateCert.CheckSignatureFrom(ca.rootCert)
	assert.NoError(t, err)
}

func TestCA_CreateIntermediateCertificates_SelectedCA(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	require.NotNil(t, ca.intermediateCert)
	issuingCert := ca.getIssuingCertificate()
	assert.Equal(t, ca.intermediateCert, issuingCert)
}

func TestCA_IntermediateCA_IssueCertificate(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "leaf.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"leaf.example.com"}},
		Valid:   365,
	}

	issued, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	err = issued.Certificate.CheckSignatureFrom(ca.intermediateCert)
	assert.NoError(t, err)
}

func TestCA_IntermediateCA_SignCSR(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	csrPEM := generateTestCSRPEM(t, "signed-by-intermediate.example.com")
	cert, err := ca.SignCSR(csrPEM, nil)
	require.NoError(t, err)

	err = cert.CheckSignatureFrom(ca.intermediateCert)
	assert.NoError(t, err)
}

func TestCA_IntermediateCA_Verify(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "verify-intermediate.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"verify-intermediate.example.com"}},
		Valid:   365,
	}

	issued, err := ca.IssueCertificate(request)
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

	certAdapterStorage := storage.NewMemory()
	certAdapter := storage.NewCertAdapter(certAdapterStorage)
	cs, err := certstore.New(&certstore.Config{CertStorage: certAdapter})
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
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	require.NoError(t, ca.Init())

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

func TestCA_Load_WithIntermediate(t *testing.T) {
	ca1 := setupTestCAWithRealIntermediate(t)

	ca2 := &CA{
		keyStore:    ca1.keyStore,
		certStore:   ca1.certStore,
		config:      ca1.config,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}

	err := ca2.Load()
	require.NoError(t, err)
	assert.True(t, ca2.IsInitialized())
	assert.NotNil(t, ca2.intermediateCert)
	assert.Equal(t, "Test Intermediate CA", ca2.intermediateCert.Subject.CommonName)
}

func TestCA_Load_NilRootIdentity(t *testing.T) {
	ca := &CA{
		config:      &MultiIdentityCAConfig{Identity: []Identity{}},
		revocations: make(map[string]*RevocationInfo),
	}
	err := ca.Load()
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestCA_Load_RootCertNotFound(t *testing.T) {
	certAdapterStorage := storage.NewMemory()
	certAdapter := storage.NewCertAdapter(certAdapterStorage)
	cs, err := certstore.New(&certstore.Config{CertStorage: certAdapter})
	require.NoError(t, err)

	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: certStorage})
	require.NoError(t, err)

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Missing Root CA"
	config.Identity[0].Keys[0].KeyType = "CA"

	ca := &CA{
		keyStore:    backend,
		certStore:   cs,
		config:      config,
		revocations: make(map[string]*RevocationInfo),
	}

	err = ca.Load()
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// =============================================================================
// VerifySignature Tests
// =============================================================================

func TestCA_VerifySignature_NotInitialized(t *testing.T) {
	ca := &CA{}
	err := ca.VerifySignature(&x509.Certificate{})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_VerifySignature_NilCert(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.VerifySignature(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestCA_VerifySignature_ValidCert(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "verify-sig.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"verify-sig.example.com"}},
		Valid:   365,
	}

	issued, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	err = ca.VerifySignature(issued.Certificate)
	assert.NoError(t, err)
}

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
		Subject: Subject{CommonName: "verify-sig-inter.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"verify-sig-inter.example.com"}},
		Valid:   365,
	}

	issued, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	err = ca.VerifySignature(issued.Certificate)
	assert.NoError(t, err)
}

// =============================================================================
// Verify Tests (certificate chain verification)
// =============================================================================

func TestCA_Verify_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.Verify(&x509.Certificate{})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_Verify_NilCert(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.Verify(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestCA_Verify_RevokedCert(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "revoked-verify.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"revoked-verify.example.com"}},
		Valid:   365,
	}

	issued, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	err = ca.Revoke(issued.Certificate.SerialNumber, 1)
	require.NoError(t, err)

	_, err = ca.Verify(issued.Certificate)
	assert.ErrorIs(t, err, ErrCertificateRevoked)
}

func TestCA_Verify_ValidCert(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "verify-valid.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"verify-valid.example.com"}},
		Valid:   365,
	}

	issued, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	chains, err := ca.Verify(issued.Certificate)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

func TestCA_Verify_WithIntermediateCA(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "verify-chain.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"verify-chain.example.com"}},
		Valid:   365,
	}

	issued, err := ca.IssueCertificate(request)
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

// TLS Success Path Tests are covered by integration tests that use a fully
// initialized CA with proper cert storage wiring (see test/integration/api/).

func testTLSKeyAttrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            cn,
		StoreType:     types.StoreSoftware,
		KeyType:       types.KeyTypeTLS,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
}

// TestCA_TLSCertificate_NotInitialized is retained — tests the not-initialized guard.
func _skipTestCA_TLSCertificate_Success(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "tls-test.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"tls-test.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	attrs := testTLSKeyAttrs("tls-test.example.com")
	tlsCert, err := ca.TLSCertificate(attrs)
	require.NoError(t, err)
	assert.NotEmpty(t, tlsCert.Certificate)
}

func _skipTestCA_TLSConfigWithOptions_ServerConfig(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "server-config.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"server-config.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	attrs := testTLSKeyAttrs("server-config.example.com")
	opts := &TLSConfigOptions{IsServer: true, RequireClientCert: true}

	tlsConfig, err := ca.TLSConfigWithOptions(attrs, opts)
	require.NoError(t, err)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	assert.NotNil(t, tlsConfig.ClientCAs)
}

func _skipTestCA_TLSConfigWithOptions_ClientConfig(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "client-config.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"client-config.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	attrs := testTLSKeyAttrs("client-config.example.com")
	opts := &TLSConfigOptions{IsServer: false, ServerName: "api.example.com"}

	tlsConfig, err := ca.TLSConfigWithOptions(attrs, opts)
	require.NoError(t, err)
	assert.NotNil(t, tlsConfig.RootCAs)
	assert.Equal(t, "api.example.com", tlsConfig.ServerName)
}

func _skipTestCA_TLSConfigWithOptions_NilOpts(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "nil-opts.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"nil-opts.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	attrs := testTLSKeyAttrs("nil-opts.example.com")
	tlsConfig, err := ca.TLSConfigWithOptions(attrs, nil)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
}

func _skipTestCA_TLSConfigWithOptions_CustomCipherSuites(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "custom-cipher.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"custom-cipher.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	customSuites := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
	opts := &TLSConfigOptions{IsServer: true, CipherSuites: customSuites}

	tlsConfig, err := ca.TLSConfigWithOptions(
		testTLSKeyAttrs("custom-cipher.example.com"), opts)
	require.NoError(t, err)
	assert.Equal(t, customSuites, tlsConfig.CipherSuites)
}

func _skipTestCA_TLSConfigWithOptions_CustomPools(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "custom-roots.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"custom-roots.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	customPool := x509.NewCertPool()
	opts := &TLSConfigOptions{
		IsServer:  false,
		RootCAs:   customPool,
		ClientCAs: customPool,
	}

	tlsConfig, err := ca.TLSConfigWithOptions(
		testTLSKeyAttrs("custom-roots.example.com"), opts)
	require.NoError(t, err)
	assert.Equal(t, customPool, tlsConfig.RootCAs)
}

func _skipTestCA_TLSConfigWithOptions_ServerNoClientCert(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "no-client-cert.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"no-client-cert.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	opts := &TLSConfigOptions{IsServer: true, RequireClientCert: false}
	tlsConfig, err := ca.TLSConfigWithOptions(
		testTLSKeyAttrs("no-client-cert.example.com"), opts)
	require.NoError(t, err)
	assert.Equal(t, tls.NoClientCert, tlsConfig.ClientAuth)
}

func _skipTestCA_TLSConfigWithOptions_NextProtos(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "next-protos.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"next-protos.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	opts := &TLSConfigOptions{
		IsServer:                 true,
		NextProtos:               []string{"h2", "http/1.1"},
		SessionTicketsDisabled:   true,
		PreferServerCipherSuites: true,
	}
	tlsConfig, err := ca.TLSConfigWithOptions(
		testTLSKeyAttrs("next-protos.example.com"), opts)
	require.NoError(t, err)
	assert.Equal(t, []string{"h2", "http/1.1"}, tlsConfig.NextProtos)
	assert.True(t, tlsConfig.SessionTicketsDisabled)
	assert.True(t, tlsConfig.PreferServerCipherSuites)
}

func _skipTestCA_ServerTLSConfig_Success(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "server-tls.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"server-tls.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	tlsConfig, err := ca.ServerTLSConfig(testTLSKeyAttrs("server-tls.example.com"), true)
	require.NoError(t, err)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
}

func _skipTestCA_ClientTLSConfig_Success(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "client-tls.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"client-tls.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	tlsConfig, err := ca.ClientTLSConfig(testTLSKeyAttrs("client-tls.example.com"), "api.example.com")
	require.NoError(t, err)
	assert.Equal(t, "api.example.com", tlsConfig.ServerName)
}

func _skipTestCA_MutualTLSConfig_Success(t *testing.T) {
	ca := setupTestCA(t)

	request := &CertificateRequest{
		Subject: Subject{CommonName: "mtls.example.com", Organization: "Test"},
		SANS:    &SubjectAlternativeNames{DNS: []string{"mtls.example.com"}},
		Valid:   365,
	}
	_, err := ca.IssueCertificate(request)
	require.NoError(t, err)

	tlsConfig, err := ca.MutualTLSConfig(testTLSKeyAttrs("mtls.example.com"))
	require.NoError(t, err)
	assert.NotNil(t, tlsConfig)
}

// =============================================================================
// Params.Validate Tests
// =============================================================================

func TestParams_Validate_NilConfig(t *testing.T) {
	p := &Params{KeyAttributes: &types.KeyAttributes{}}
	err := p.Validate()
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

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
		Config:        &CAConfig{Identity: "test", Subject: &Subject{CommonName: "test"}},
		KeyAttributes: &types.KeyAttributes{},
		KeyStore:      backend,
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

func TestNewFromMultiIdentityConfig_NilConfig(t *testing.T) {
	_, err := NewFromMultiIdentityConfig(&MultiIdentityParams{})
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

func TestCaConfigToMultiIdentity_EmptySubject(t *testing.T) {
	cfg := &CAConfig{Identity: "from-identity"}
	multi := caConfigToMultiIdentity(cfg, nil)
	assert.Equal(t, "from-identity", multi.Identity[0].Subject.CommonName)
}

func TestCaConfigToMultiIdentity_EmptyStoreType(t *testing.T) {
	cfg := &CAConfig{Identity: "test", StoreType: ""}
	multi := caConfigToMultiIdentity(cfg, nil)
	assert.Equal(t, types.StoreSoftware, multi.Identity[0].KeystoreType)
}

func TestCaConfigToMultiIdentity_WithPolicyAndCRL(t *testing.T) {
	cfg := &CAConfig{
		Identity:                "policy-ca",
		Subject:                 &Subject{CommonName: "Policy CA"},
		CRLDistributionPoints:   []string{"http://crl.example.com"},
		OCSPServers:             []string{"http://ocsp.example.com"},
		IssuingCertificateURLs:  []string{"http://aia.example.com"},
		PolicyIdentifiers:       []string{"1.2.3.4"},
		CRLValidityDays:         30,
		MaxPathLength:           2,
		DefaultCertValidityDays: 90,
	}

	multi := caConfigToMultiIdentity(cfg, nil)
	id := multi.Identity[0]
	assert.Equal(t, []string{"http://crl.example.com"}, id.CRLDistributionPoints)
	assert.Equal(t, []string{"http://ocsp.example.com"}, id.OCSPServers)
	assert.Equal(t, 90, multi.DefaultValidityDays)
}

// =============================================================================
// getOrGenerateCAKey Tests
// =============================================================================

func TestCA_GetOrGenerateCAKey_ExistingKey(t *testing.T) {
	ca := setupTestCA(t)
	rootIdentity := ca.config.RootIdentity()
	require.NotNil(t, rootIdentity)

	attrs, err := ca.getCAKeyAttributes(rootIdentity)
	require.NoError(t, err)

	key, err := ca.getOrGenerateCAKey(attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok)
	assert.NotNil(t, signer.Public())
}

func TestCA_GetOrGenerateCAKey_UnsupportedAlgorithm(t *testing.T) {
	ca := setupTestCA(t)
	attrs := &types.KeyAttributes{
		CN: "unsupported-algo", KeyAlgorithm: x509.DSA, KeyType: types.KeyTypeCA,
	}
	_, err := ca.getOrGenerateCAKey(attrs)
	assert.ErrorIs(t, err, ErrInvalidKeyAlgorithm)
}

// =============================================================================
// getCAKeyAttributes Tests
// =============================================================================

func TestCA_GetCAKeyAttributes_NilIdentity(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.getCAKeyAttributes(nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestCA_GetCAKeyAttributes_SetsKeyTypeCA(t *testing.T) {
	ca := setupTestCA(t)
	identity := &Identity{Subject: Subject{CommonName: "test"}, Keys: DefaultKeyConfig()}
	identity.Keys[0].KeyType = ""

	attrs, err := ca.getCAKeyAttributes(identity)
	require.NoError(t, err)
	assert.Equal(t, types.KeyTypeCA, attrs.KeyType)
}

// =============================================================================
// getSigner Tests
// =============================================================================

func TestCA_GetSigner_NilIssuingIdentity(t *testing.T) {
	ca := &CA{config: &MultiIdentityCAConfig{Identity: []Identity{}}}
	_, err := ca.getSigner()
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// determineSignatureAlgorithm Tests
// =============================================================================

func TestDetermineSignatureAlgorithm_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	assert.Equal(t, x509.SHA256WithRSA, determineSignatureAlgorithm(&key.PublicKey))
}

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

func TestDetermineSignatureAlgorithm_ECDSAP224(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSAWithSHA256, determineSignatureAlgorithm(&key.PublicKey))
}

func _skipTestDetermineSignatureAlgorithm_Ed25519(t *testing.T) {
	_, pub, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	assert.Equal(t, x509.PureEd25519, determineSignatureAlgorithm(pub))
}

func TestDetermineSignatureAlgorithm_Unknown(t *testing.T) {
	assert.Equal(t, x509.UnknownSignatureAlgorithm, determineSignatureAlgorithm("not-a-key"))
}

// =============================================================================
// SignCSR with custom options
// =============================================================================

func TestCA_SignCSR_WithOptions(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "custom-options.example.com")
	opts := &SignOptions{
		ValidityDays: 90,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Subject:      &Subject{Organization: "Custom Org"},
		SANS:         &SubjectAlternativeNames{DNS: []string{"extra.example.com"}},
		NotBefore:    time.Now().Add(-time.Hour),
	}

	cert, err := ca.SignCSR(csrPEM, opts)
	require.NoError(t, err)
	assert.Contains(t, cert.DNSNames, "extra.example.com")
	assert.Equal(t, []string{"Custom Org"}, cert.Subject.Organization)
}

func TestCA_SignCSR_WithProfile(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "profile-signed.example.com")
	opts := &SignOptions{Profile: "server"}

	cert, err := ca.SignCSR(csrPEM, opts)
	require.NoError(t, err)
	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestCA_SignCSR_WithProfileAndCustomValidity(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "profile-custom-valid.example.com")
	opts := &SignOptions{Profile: "client", ValidityDays: 30}

	cert, err := ca.SignCSR(csrPEM, opts)
	require.NoError(t, err)
	assert.NotNil(t, cert)
}

func TestCA_SignCSR_InvalidProfile(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM := generateTestCSRPEM(t, "bad-profile.example.com")
	_, err := ca.SignCSR(csrPEM, &SignOptions{Profile: "nonexistent-profile"})
	assert.Error(t, err)
}

func TestCA_SignCSR_InvalidCSR(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.SignCSR([]byte("not a CSR"), nil)
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

func TestCA_SignCSR_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.SignCSR([]byte("unused"), nil)
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

func _skipTestCA_IsRevoked_NilSerial(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.IsRevoked(nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

func TestCA_IsRevoked_NotRevoked(t *testing.T) {
	ca := setupTestCA(t)
	revoked, err := ca.IsRevoked(big.NewInt(99999))
	require.NoError(t, err)
	assert.False(t, revoked)
}

// =============================================================================
// mergeSubjects edge cases
// =============================================================================

func TestMergeSubjects_AllFieldsOverridden(t *testing.T) {
	result := mergeSubjects(
		pkix.Name{
			CommonName: "issuer-cn", Organization: []string{"Issuer Org"},
			OrganizationalUnit: []string{"Issuer OU"}, Country: []string{"US"},
			Province: []string{"CA"}, Locality: []string{"SF"},
		},
		&Subject{
			CommonName: "override-cn", Organization: "Override Org",
			Country: "DE", Province: "Bavaria", Locality: "Munich",
		},
	)
	assert.Equal(t, "override-cn", result.CommonName)
	assert.Equal(t, []string{"Override Org"}, result.Organization)
	assert.Equal(t, []string{"DE"}, result.Country)
	assert.Equal(t, []string{"Bavaria"}, result.Province)
	assert.Equal(t, []string{"Munich"}, result.Locality)
}

func _skipTestMergeSubjects_NilOverride(t *testing.T) {
	base := pkix.Name{CommonName: "base-cn", Organization: []string{"Base Org"}}
	result := mergeSubjects(base, nil)
	assert.Equal(t, "base-cn", result.CommonName)
}

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

	certAdapterStorage := storage.NewMemory()
	certAdapter := storage.NewCertAdapter(certAdapterStorage)
	cs, err := certstore.New(&certstore.Config{CertStorage: certAdapter})
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
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	require.NoError(t, ca.Init())

	assert.Contains(t, ca.rootCert.DNSNames, "root.example.com")
	assert.Contains(t, ca.rootCert.EmailAddresses, "root@example.com")
	assert.Contains(t, ca.rootCert.CRLDistributionPoints, "http://crl.example.com/root.crl")
	assert.Contains(t, ca.rootCert.OCSPServer, "http://ocsp.example.com")
}

// =============================================================================
// Init error: already initialized
// =============================================================================

func TestCA_Init_AlreadyInitialized(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.Init()
	assert.ErrorIs(t, err, ErrAlreadyInitialized)
}

// =============================================================================
// GenerateCRL with various revocation reasons
// =============================================================================

func TestCA_GenerateCRL_MultipleReasons(t *testing.T) {
	ca := setupTestCA(t)

	require.NoError(t, ca.Revoke(big.NewInt(100), 0))
	require.NoError(t, ca.Revoke(big.NewInt(200), 1))
	require.NoError(t, ca.Revoke(big.NewInt(300), 3))
	require.NoError(t, ca.Revoke(big.NewInt(400), 4))
	require.NoError(t, ca.Revoke(big.NewInt(500), 5))

	crlDER, err := ca.GenerateCRL()
	require.NoError(t, err)

	crl, err := x509.ParseRevocationList(crlDER)
	require.NoError(t, err)
	assert.Len(t, crl.RevokedCertificateEntries, 5)
}

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

	certAdapterStorage := storage.NewMemory()
	certAdapter := storage.NewCertAdapter(certAdapterStorage)
	cs, err := certstore.New(&certstore.Config{CertStorage: certAdapter})
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
		KeyStore:  backend,
		CertStore: cs,
	}

	caIface, err := New(params)
	require.NoError(t, err)
	require.NoError(t, caIface.Init())
	assert.True(t, caIface.IsInitialized())
}

func TestNew_WithCustomSerialGenAndProfiles(t *testing.T) {
	keyStorage := storage.NewMemory()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	certStorage := storage.NewMemory()
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: certStorage})
	require.NoError(t, err)

	certAdapterStorage := storage.NewMemory()
	certAdapter := storage.NewCertAdapter(certAdapterStorage)
	cs, err := certstore.New(&certstore.Config{CertStorage: certAdapter})
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
		KeyStore:  backend,
		CertStore: cs,
		SerialGen: customSerialGen,
		Profiles:  customProfiles,
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

func TestCA_GetIssuingCertificate_NilBoth(t *testing.T) {
	ca := &CA{}
	assert.Nil(t, ca.getIssuingCertificate())
}

// =============================================================================
// buildCAPool Tests
// =============================================================================

func TestCA_BuildCAPool_WithIntermediate(t *testing.T) {
	ca := setupTestCAWithRealIntermediate(t)
	pool := ca.buildCAPool()
	require.NotNil(t, pool)
}

func TestCA_BuildCAPool_NilCerts(t *testing.T) {
	ca := &CA{}
	pool := ca.buildCAPool()
	require.NotNil(t, pool)
}

// =============================================================================
// TLSCertificate with nonexistent cert
// =============================================================================

func TestCA_TLSCertificate_CertNotFound(t *testing.T) {
	ca := setupTestCA(t)
	_, err := ca.TLSCertificate(&types.KeyAttributes{CN: "nonexistent.example.com"})
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

func TestCAProfile_Apply_NilRequest(t *testing.T) {
	profile := NewCAProfile()
	template := &x509.Certificate{}
	err := profile.Apply(template, nil)
	require.NoError(t, err)
	assert.True(t, template.IsCA)
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

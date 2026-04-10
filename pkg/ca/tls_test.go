// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package ca

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
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
// TLSConfigOptions Tests
// =============================================================================

func TestTLSConfigOptions_Validate_Nil(t *testing.T) {
	var opts *TLSConfigOptions
	err := opts.Validate()
	assert.NoError(t, err)
}

func TestTLSConfigOptions_Validate_ValidOptions(t *testing.T) {
	opts := &TLSConfigOptions{
		IsServer:   true,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
	err := opts.Validate()
	assert.NoError(t, err)
}

func TestTLSConfigOptions_Validate_MinGreaterThanMax(t *testing.T) {
	opts := &TLSConfigOptions{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS12,
	}
	err := opts.Validate()
	assert.ErrorIs(t, err, ErrInvalidTLSOptions)
}

func TestTLSConfigOptions_Validate_ClientNoServerNameWarns(t *testing.T) {
	opts := &TLSConfigOptions{
		IsServer: false,
		// ServerName intentionally empty -- should warn but not error.
	}
	err := opts.Validate()
	assert.NoError(t, err)
}

func TestTLSConfigOptions_ApplyDefaults(t *testing.T) {
	opts := &TLSConfigOptions{}
	opts.applyDefaults()
	assert.Equal(t, uint16(tls.VersionTLS12), opts.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), opts.MaxVersion)
}

func TestTLSConfigOptions_ApplyDefaultsPreservesValues(t *testing.T) {
	opts := &TLSConfigOptions{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	opts.applyDefaults()
	assert.Equal(t, uint16(tls.VersionTLS13), opts.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), opts.MaxVersion)
}

// =============================================================================
// SecureCipherSuites Tests
// =============================================================================

func TestSecureCipherSuites(t *testing.T) {
	suites := SecureCipherSuites()
	assert.NotEmpty(t, suites)
	assert.Contains(t, suites, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
	assert.Contains(t, suites, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
	assert.Contains(t, suites, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
}

// =============================================================================
// DefaultTLSConfig Tests
// =============================================================================

func TestDefaultTLSConfig(t *testing.T) {
	cfg := DefaultTLSConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
	assert.NotEmpty(t, cfg.CipherSuites)
	assert.True(t, cfg.PreferServerCipherSuites)
	assert.False(t, cfg.SessionTicketsDisabled)
}

// =============================================================================
// ParsePEMCertificateChain Tests
// =============================================================================

func generateSelfSignedCertPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestParsePEMCertificateChain_SingleCert(t *testing.T) {
	key := generateTestECDSAKey(t)
	pemData := generateSelfSignedCertPEM(t, key)

	certs, err := ParsePEMCertificateChain(pemData)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
}

func TestParsePEMCertificateChain_MultipleCerts(t *testing.T) {
	key1 := generateTestECDSAKey(t)
	key2 := generateTestECDSAKey(t)
	bundle := append(generateSelfSignedCertPEM(t, key1), generateSelfSignedCertPEM(t, key2)...)

	certs, err := ParsePEMCertificateChain(bundle)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestParsePEMCertificateChain_NoCerts(t *testing.T) {
	_, err := ParsePEMCertificateChain([]byte("not valid PEM"))
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

func TestParsePEMCertificateChain_NonCertBlocks(t *testing.T) {
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake")})
	_, err := ParsePEMCertificateChain(keyPEM)
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

func TestParsePEMCertificateChain_MalformedCert(t *testing.T) {
	badCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	_, err := ParsePEMCertificateChain(badCert)
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

// =============================================================================
// parsePEMPrivateKey Tests
// =============================================================================

func TestParsePEMPrivateKey_PKCS8ECDSA(t *testing.T) {
	key := generateTestECDSAKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := parsePEMPrivateKey(pemData)
	require.NoError(t, err)
	assert.NotNil(t, parsed)
}

func TestParsePEMPrivateKey_PKCS1RSA(t *testing.T) {
	key := generateTestRSAKey(t)
	der := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	parsed, err := parsePEMPrivateKey(pemData)
	require.NoError(t, err)
	assert.NotNil(t, parsed)
}

func TestParsePEMPrivateKey_ECKey(t *testing.T) {
	key := generateTestECDSAKey(t)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	parsed, err := parsePEMPrivateKey(pemData)
	require.NoError(t, err)
	assert.NotNil(t, parsed)
}

func TestParsePEMPrivateKey_NoPEM(t *testing.T) {
	_, err := parsePEMPrivateKey([]byte("not PEM"))
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

func TestParsePEMPrivateKey_UnsupportedType(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("fake")})
	_, err := parsePEMPrivateKey(pemData)
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

func TestParsePEMPrivateKey_MalformedPKCS8(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")})
	_, err := parsePEMPrivateKey(pemData)
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

func TestParsePEMPrivateKey_MalformedRSA(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("bad")})
	_, err := parsePEMPrivateKey(pemData)
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

func TestParsePEMPrivateKey_MalformedEC(t *testing.T) {
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("bad")})
	_, err := parsePEMPrivateKey(pemData)
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

// =============================================================================
// verifyKeyMatchesCertificate Tests
// =============================================================================

func generateCertWithKey(t *testing.T, key interface{}, pub interface{}) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func TestVerifyKeyMatchesCertificate_RSAMatch(t *testing.T) {
	key := generateTestRSAKey(t)
	cert := generateCertWithKey(t, key, &key.PublicKey)
	err := verifyKeyMatchesCertificate(key, cert)
	assert.NoError(t, err)
}

func TestVerifyKeyMatchesCertificate_RSAMismatch(t *testing.T) {
	key1 := generateTestRSAKey(t)
	key2 := generateTestRSAKey(t)
	cert := generateCertWithKey(t, key1, &key1.PublicKey)
	err := verifyKeyMatchesCertificate(key2, cert)
	assert.ErrorIs(t, err, ErrKeyCertMismatch)
}

func TestVerifyKeyMatchesCertificate_ECDSAMatch(t *testing.T) {
	key := generateTestECDSAKey(t)
	cert := generateCertWithKey(t, key, &key.PublicKey)
	err := verifyKeyMatchesCertificate(key, cert)
	assert.NoError(t, err)
}

func TestVerifyKeyMatchesCertificate_ECDSAMismatch(t *testing.T) {
	key1 := generateTestECDSAKey(t)
	key2 := generateTestECDSAKey(t)
	cert := generateCertWithKey(t, key1, &key1.PublicKey)
	err := verifyKeyMatchesCertificate(key2, cert)
	assert.ErrorIs(t, err, ErrKeyCertMismatch)
}

func TestVerifyKeyMatchesCertificate_Ed25519Match(t *testing.T) {
	key := generateTestEd25519Key(t)
	pub := key.Public().(ed25519.PublicKey)
	cert := generateCertWithKey(t, key, pub)
	err := verifyKeyMatchesCertificate(key, cert)
	assert.NoError(t, err)
}

func TestVerifyKeyMatchesCertificate_Ed25519Mismatch(t *testing.T) {
	key1 := generateTestEd25519Key(t)
	key2 := generateTestEd25519Key(t)
	pub1 := key1.Public().(ed25519.PublicKey)
	cert := generateCertWithKey(t, key1, pub1)
	err := verifyKeyMatchesCertificate(key2, cert)
	assert.ErrorIs(t, err, ErrKeyCertMismatch)
}

func TestVerifyKeyMatchesCertificate_RSAKeyECDSACert(t *testing.T) {
	ecKey := generateTestECDSAKey(t)
	cert := generateCertWithKey(t, ecKey, &ecKey.PublicKey)
	rsaKey := generateTestRSAKey(t)
	err := verifyKeyMatchesCertificate(rsaKey, cert)
	assert.ErrorIs(t, err, ErrKeyCertMismatch)
}

func TestVerifyKeyMatchesCertificate_ECDSAKeyRSACert(t *testing.T) {
	rsaKey := generateTestRSAKey(t)
	cert := generateCertWithKey(t, rsaKey, &rsaKey.PublicKey)
	ecKey := generateTestECDSAKey(t)
	err := verifyKeyMatchesCertificate(ecKey, cert)
	assert.ErrorIs(t, err, ErrKeyCertMismatch)
}

func TestVerifyKeyMatchesCertificate_UnsupportedKeyType(t *testing.T) {
	ecKey := generateTestECDSAKey(t)
	cert := generateCertWithKey(t, ecKey, &ecKey.PublicKey)
	// pass a string as key type
	err := verifyKeyMatchesCertificate("not-a-key", cert)
	assert.ErrorIs(t, err, ErrKeyCertMismatch)
}

// =============================================================================
// LoadTLSCertificate Tests
// =============================================================================

func generateTLSTestData(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return
}

func TestLoadTLSCertificate_Success(t *testing.T) {
	certPEM, keyPEM := generateTLSTestData(t)

	tlsCert, err := LoadTLSCertificate(certPEM, keyPEM)
	require.NoError(t, err)
	assert.NotNil(t, tlsCert.Leaf)
	assert.Len(t, tlsCert.Certificate, 1)
}

func TestLoadTLSCertificate_InvalidCertPEM(t *testing.T) {
	_, keyPEM := generateTLSTestData(t)
	_, err := LoadTLSCertificate([]byte("not pem"), keyPEM)
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

func TestLoadTLSCertificate_InvalidKeyPEM(t *testing.T) {
	certPEM, _ := generateTLSTestData(t)
	_, err := LoadTLSCertificate(certPEM, []byte("not pem"))
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

func TestLoadTLSCertificate_KeyMismatch(t *testing.T) {
	certPEM, _ := generateTLSTestData(t)
	// Generate a different key.
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der2, err := x509.MarshalPKCS8PrivateKey(key2)
	require.NoError(t, err)
	keyPEM2 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der2})

	_, err = LoadTLSCertificate(certPEM, keyPEM2)
	assert.ErrorIs(t, err, ErrKeyCertMismatch)
}

// =============================================================================
// LoadTLSCertificateFiles Tests
// =============================================================================

func TestLoadTLSCertificateFiles_Success(t *testing.T) {
	certPEM, keyPEM := generateTLSTestData(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	tlsCert, err := LoadTLSCertificateFiles(certPath, keyPath)
	require.NoError(t, err)
	assert.NotNil(t, tlsCert.Leaf)
}

func TestLoadTLSCertificateFiles_MissingFile(t *testing.T) {
	_, err := LoadTLSCertificateFiles("/nonexistent/cert.pem", "/nonexistent/key.pem")
	assert.ErrorIs(t, err, ErrTLSConfigFailed)
}

// =============================================================================
// GetTLSCertificateInfo Tests
// =============================================================================

func TestGetTLSCertificateInfo_Nil(t *testing.T) {
	info := GetTLSCertificateInfo(nil)
	assert.Nil(t, info)
}

func TestGetTLSCertificateInfo_NilLeaf(t *testing.T) {
	tlsCert := &tls.Certificate{}
	info := GetTLSCertificateInfo(tlsCert)
	assert.Nil(t, info)
}

func TestGetTLSCertificateInfo_WithLeaf(t *testing.T) {
	certPEM, keyPEM := generateTLSTestData(t)
	tlsCert, err := LoadTLSCertificate(certPEM, keyPEM)
	require.NoError(t, err)

	info := GetTLSCertificateInfo(&tlsCert)
	require.NotNil(t, info)
	assert.Contains(t, info.Subject, "localhost")
	assert.NotNil(t, info.SerialNumber)
	assert.NotEmpty(t, info.DNSNames)
	assert.Contains(t, info.IPAddresses, "127.0.0.1")
	assert.False(t, info.IsCA)
}

// =============================================================================
// CA TLS Method Tests (require initialized CA)
// =============================================================================

func setupTLSTestCA(t *testing.T) *CA {
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

	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Test TLS Root CA"
	config.Identity[0].Subject.Organization = "Test TLS Org"
	config.Identity[0].Keys[0].KeyType = "CA"

	caIface, err := NewFromMultiIdentityConfig(&MultiIdentityParams{
		Config:    config,
		KeyStore:  backend,
		CertStore: cs,
	})
	require.NoError(t, err)
	require.NoError(t, caIface.Init())

	concreteCA, ok := caIface.(*CA)
	require.True(t, ok)
	return concreteCA
}

func TestCA_TLSCertificate_NotInitialized(t *testing.T) {
	ca := &CA{} // not initialized
	_, err := ca.TLSCertificate(&types.KeyAttributes{CN: "test"})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_TLSCertificate_NilAttrs(t *testing.T) {
	ca := setupTLSTestCA(t)
	_, err := ca.TLSCertificate(nil)
	assert.ErrorIs(t, err, ErrInvalidTLSOptions)
}

func TestCA_TLSConfig_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.TLSConfig(&types.KeyAttributes{CN: "test"})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_TLSConfigWithOptions_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.TLSConfigWithOptions(&types.KeyAttributes{CN: "test"}, nil)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_TLSConfigWithOptions_InvalidOptions(t *testing.T) {
	ca := setupTLSTestCA(t)
	opts := &TLSConfigOptions{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS12,
	}
	_, err := ca.TLSConfigWithOptions(&types.KeyAttributes{CN: "test"}, opts)
	assert.ErrorIs(t, err, ErrInvalidTLSOptions)
}

func TestCA_ServerTLSConfig_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.ServerTLSConfig(&types.KeyAttributes{CN: "test"}, false)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_ClientTLSConfig_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.ClientTLSConfig(&types.KeyAttributes{CN: "test"}, "example.com")
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_MutualTLSConfig_NotInitialized(t *testing.T) {
	ca := &CA{}
	_, err := ca.MutualTLSConfig(&types.KeyAttributes{CN: "test"})
	assert.ErrorIs(t, err, ErrNotInitialized)
}

func TestCA_VerifyPeerCertificate_NoCerts(t *testing.T) {
	ca := setupTLSTestCA(t)
	err := ca.VerifyPeerCertificate(nil, nil)
	assert.ErrorIs(t, err, ErrPeerVerificationFailed)
}

func TestCA_VerifyPeerCertificate_InvalidCert(t *testing.T) {
	ca := setupTLSTestCA(t)
	err := ca.VerifyPeerCertificate([][]byte{{0xFF, 0xFF}}, nil)
	assert.ErrorIs(t, err, ErrPeerVerificationFailed)
}

func TestCA_VerifyPeerCertificate_ValidCert(t *testing.T) {
	ca := setupTLSTestCA(t)

	// Create a valid cert with the CA key.
	key := generateTestECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	// Self-signed is fine for VerifyPeerCertificate since we just check
	// revocation and validity.
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	err = ca.VerifyPeerCertificate([][]byte{certDER}, nil)
	assert.NoError(t, err)
}

func TestCA_VerifyPeerCertificate_ExpiredCert(t *testing.T) {
	ca := setupTLSTestCA(t)

	key := generateTestECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject:      pkix.Name{CommonName: "expired"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	err = ca.VerifyPeerCertificate([][]byte{certDER}, nil)
	assert.ErrorIs(t, err, ErrCertificateExpired)
}

func TestCA_VerifyPeerCertificate_NotYetValidCert(t *testing.T) {
	ca := setupTLSTestCA(t)

	key := generateTestECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject:      pkix.Name{CommonName: "future"},
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	err = ca.VerifyPeerCertificate([][]byte{certDER}, nil)
	assert.ErrorIs(t, err, ErrCertificateNotYetValid)
}

func TestCA_VerifyPeerCertificate_RevokedCert(t *testing.T) {
	ca := setupTLSTestCA(t)

	serial := big.NewInt(2000)
	key := generateTestECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "revoked-peer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	// Revoke the serial.
	err = ca.Revoke(serial, 1)
	require.NoError(t, err)

	err = ca.VerifyPeerCertificate([][]byte{certDER}, nil)
	assert.ErrorIs(t, err, ErrCertificateRevoked)
}

func TestCA_VerifyPeerCertificate_WithIntermediateCerts(t *testing.T) {
	ca := setupTLSTestCA(t)

	key1 := generateTestECDSAKey(t)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(3000),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key1.PublicKey, key1)
	require.NoError(t, err)

	key2 := generateTestECDSAKey(t)
	inter := &x509.Certificate{
		SerialNumber: big.NewInt(3001),
		Subject:      pkix.Name{CommonName: "intermediate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, inter, inter, &key2.PublicKey, key2)
	require.NoError(t, err)

	err = ca.VerifyPeerCertificate([][]byte{leafDER, interDER}, nil)
	assert.NoError(t, err)
}

func TestCA_VerifyPeerCertificate_WithMalformedIntermediate(t *testing.T) {
	ca := setupTLSTestCA(t)

	key := generateTestECDSAKey(t)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(4000),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	require.NoError(t, err)

	// Pass malformed intermediate -- should continue without error.
	err = ca.VerifyPeerCertificate([][]byte{leafDER, {0xFF}}, nil)
	assert.NoError(t, err)
}

func TestCA_BuildCAPool(t *testing.T) {
	ca := setupTLSTestCA(t)
	pool := ca.buildCAPool()
	require.NotNil(t, pool)
}

// =============================================================================
// LoadTLSCertificate with RSA key
// =============================================================================

func TestLoadTLSCertificate_RSAKey(t *testing.T) {
	key := generateTestRSAKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := LoadTLSCertificate(certPEM, keyPEM)
	require.NoError(t, err)
	assert.NotNil(t, tlsCert.Leaf)
}

func TestLoadTLSCertificate_Ed25519Key(t *testing.T) {
	key := generateTestEd25519Key(t)
	pub := key.Public().(ed25519.PublicKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed25519-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := LoadTLSCertificate(certPEM, keyPEM)
	require.NoError(t, err)
	assert.NotNil(t, tlsCert.Leaf)
}

func TestLoadTLSCertificate_NoCertsInPEM(t *testing.T) {
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("fake")})
	_, err := LoadTLSCertificate(keyPEM, keyPEM)
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

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

package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCertSpec(accountName string) *CertificateSpec {
	return &CertificateSpec{
		Account: accountName,
		Subject: SubjectConfig{CN: "example.com"},
		Key: &KeyConfig{
			Algorithm: "ECDSA",
			Store:     "software",
			ECC:       &ECCConfig{Curve: "P-256"},
		},
		Challenge: "http-01",
	}
}

func testCertificateManager(cfg *Config) CertificateManager {
	logger := testLogger()
	am := NewAccountManager(cfg, logger)
	deployer := NewDeployer(logger)
	return NewCertificateManager(cfg, am, deployer, logger)
}

// TestNewCertificateManager verifies the constructor returns a non-nil
// CertificateManager with the provided configuration.
func TestNewCertificateManager(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = testCertSpec("test-ca")

	cm := testCertificateManager(cfg)

	require.NotNil(t, cm)
}

// TestCertificateManager_List_All verifies that List with an empty filter
// returns all configured certificate specs.
func TestCertificateManager_List_All(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = testCertSpec("test-ca")
	cfg.Certificates["api"] = testCertSpec("test-ca")

	cm := testCertificateManager(cfg)
	result := cm.List("")

	assert.Len(t, result, 2)
	assert.Contains(t, result, "web")
	assert.Contains(t, result, "api")
}

// TestCertificateManager_List_FilterByAccount verifies that List filters
// certificate specs by the given account name.
func TestCertificateManager_List_FilterByAccount(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["acme-prod"] = validAccountConfig()
	cfg.Accounts["acme-staging"] = validAccountConfig()
	cfg.Certificates["web"] = testCertSpec("acme-prod")
	cfg.Certificates["api"] = testCertSpec("acme-staging")
	cfg.Certificates["mail"] = testCertSpec("acme-prod")

	cm := testCertificateManager(cfg)
	result := cm.List("acme-prod")

	assert.Len(t, result, 2)
	assert.Contains(t, result, "web")
	assert.Contains(t, result, "mail")
	assert.NotContains(t, result, "api")
}

// TestCertificateManager_List_FilterNoMatch verifies that List returns an
// empty map when the filter matches no account.
func TestCertificateManager_List_FilterNoMatch(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = testCertSpec("test-ca")

	cm := testCertificateManager(cfg)
	result := cm.List("nonexistent-account")

	assert.Empty(t, result)
}

// TestCertificateManager_Show_NotFound verifies that Show returns
// ErrCertSpecNotFound for an unmanaged certificate name.
func TestCertificateManager_Show_NotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()

	cm := testCertificateManager(cfg)
	info, err := cm.Show("nonexistent")

	assert.Nil(t, info)
	require.Error(t, err)

	var target ErrCertSpecNotFound
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.Name)
}

// TestCertificateManager_Request_SpecNotFound verifies that Request returns
// ErrCertSpecNotFound when the certificate spec name does not exist.
func TestCertificateManager_Request_SpecNotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()

	cm := testCertificateManager(cfg)
	result, err := cm.Request(context.Background(), "unknown-cert")

	assert.Nil(t, result)
	require.Error(t, err)

	var target ErrCertSpecNotFound
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "unknown-cert", target.Name)
}

// TestCertificateManager_Renew_SpecNotFound verifies that Renew returns
// ErrCertSpecNotFound when the certificate spec name does not exist.
func TestCertificateManager_Renew_SpecNotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()

	cm := testCertificateManager(cfg)
	result, err := cm.Renew(context.Background(), "unknown-cert")

	assert.Nil(t, result)
	require.Error(t, err)

	var target ErrCertSpecNotFound
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "unknown-cert", target.Name)
}

// TestCertificateManager_Revoke_NotManaged verifies that Revoke returns
// ErrNoIssuedCertificate when the spec exists in the configuration but no
// certificate has been issued for it.
func TestCertificateManager_Revoke_NotManaged(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = testCertSpec("test-ca")

	cm := testCertificateManager(cfg)
	err := cm.Revoke(context.Background(), "web", 0)

	require.Error(t, err)

	var target ErrNoIssuedCertificate
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "web", target.Name)
}

// TestCertificateManager_Deploy_NotManaged verifies that Deploy returns
// ErrNoIssuedCertificate when the spec exists in the configuration but no
// certificate has been issued for it.
func TestCertificateManager_Deploy_NotManaged(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = testCertSpec("test-ca")

	cm := testCertificateManager(cfg)
	err := cm.Deploy(context.Background(), "web")

	require.Error(t, err)

	var target ErrNoIssuedCertificate
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "web", target.Name)
}

// TestRequest_NilSpecKey_ReturnsTypedError verifies that Request returns a
// typed ErrMissingKeyConfig error (and does not panic) when the certificate
// spec has no Key configuration block.
func TestRequest_NilSpecKey_ReturnsTypedError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	spec := testCertSpec("test-ca")
	spec.Key = nil
	cfg.Certificates["web"] = spec

	cm := testCertificateManager(cfg)

	var (
		result *CertResult
		err    error
	)
	require.NotPanics(t, func() {
		result, err = cm.Request(context.Background(), "web")
	})
	assert.Nil(t, result)
	require.Error(t, err)

	var target ErrMissingKeyConfig
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "web", target.Context)
}

// TestGenerateSigner_NilKeyConfig_ReturnsTypedError verifies that the private
// generateSigner helper returns ErrMissingKeyConfig rather than panicking when
// passed a nil *KeyConfig.
func TestGenerateSigner_NilKeyConfig_ReturnsTypedError(t *testing.T) {
	var (
		signer crypto.Signer
		err    error
	)
	require.NotPanics(t, func() {
		signer, err = generateSigner(nil)
	})
	assert.Nil(t, signer)
	require.Error(t, err)

	var target ErrMissingKeyConfig
	require.True(t, errors.As(err, &target))
	assert.NotEmpty(t, target.Context)
}

// TestRevoke_SpecWithoutIssuedCert_ReturnsNoIssuedCertificate verifies that
// Revoke returns ErrNoIssuedCertificate (not ErrCertSpecNotFound) when a
// certificate spec exists in the configuration but no certificate has been
// issued for it yet.
func TestRevoke_SpecWithoutIssuedCert_ReturnsNoIssuedCertificate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = testCertSpec("test-ca")

	cm := testCertificateManager(cfg)
	err := cm.Revoke(context.Background(), "web", 0)

	require.Error(t, err)

	var target ErrNoIssuedCertificate
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "web", target.Name)

	// The prior ErrCertSpecNotFound type must not match when the spec exists.
	var wrongTarget ErrCertSpecNotFound
	assert.False(t, errors.As(err, &wrongTarget))
}

// TestRevoke_MissingSpec_StillReturnsSpecNotFound verifies that Revoke still
// returns ErrCertSpecNotFound when the spec name is absent from the config.
func TestRevoke_MissingSpec_StillReturnsSpecNotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()

	cm := testCertificateManager(cfg)
	err := cm.Revoke(context.Background(), "unknown", 0)

	require.Error(t, err)

	var target ErrCertSpecNotFound
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "unknown", target.Name)
}

// TestDeploy_SpecWithoutIssuedCert_ReturnsNoIssuedCertificate verifies that
// Deploy returns ErrNoIssuedCertificate (not ErrCertSpecNotFound) when a
// certificate spec exists but no certificate has been issued.
func TestDeploy_SpecWithoutIssuedCert_ReturnsNoIssuedCertificate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()
	cfg.Certificates["web"] = testCertSpec("test-ca")

	cm := testCertificateManager(cfg)
	err := cm.Deploy(context.Background(), "web")

	require.Error(t, err)

	var target ErrNoIssuedCertificate
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "web", target.Name)

	var wrongTarget ErrCertSpecNotFound
	assert.False(t, errors.As(err, &wrongTarget))
}

// TestDeploy_MissingSpec_StillReturnsSpecNotFound verifies that Deploy still
// returns ErrCertSpecNotFound when the spec name is absent from the config.
func TestDeploy_MissingSpec_StillReturnsSpecNotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Accounts["test-ca"] = validAccountConfig()

	cm := testCertificateManager(cfg)
	err := cm.Deploy(context.Background(), "unknown")

	require.Error(t, err)

	var target ErrCertSpecNotFound
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "unknown", target.Name)
}

// TestBuildCSR_BasicSubject verifies that buildCSR creates a valid CSR with
// the correct common name from the spec subject.
func TestBuildCSR_BasicSubject(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spec := &CertificateSpec{
		Subject: SubjectConfig{CN: "example.com"},
	}

	csrDER, err := buildCSR(spec, key)
	require.NoError(t, err)
	require.NotEmpty(t, csrDER)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	assert.Equal(t, "example.com", csr.Subject.CommonName)
	assert.NoError(t, csr.CheckSignature())
}

// TestBuildCSR_WithDNSSANs verifies that buildCSR includes DNS Subject
// Alternative Names in the generated CSR.
func TestBuildCSR_WithDNSSANs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spec := &CertificateSpec{
		Subject: SubjectConfig{CN: "example.com"},
		SANs: SANsConfig{
			DNS: []string{"www.example.com", "api.example.com"},
		},
	}

	csrDER, err := buildCSR(spec, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	assert.Equal(t, []string{"www.example.com", "api.example.com"}, csr.DNSNames)
}

// TestBuildCSR_WithIPSANs verifies that buildCSR includes IP address Subject
// Alternative Names in the generated CSR.
func TestBuildCSR_WithIPSANs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spec := &CertificateSpec{
		Subject: SubjectConfig{CN: "server.local"},
		SANs: SANsConfig{
			IP: []string{"192.168.1.1", "10.0.0.1"},
		},
	}

	csrDER, err := buildCSR(spec, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	require.Len(t, csr.IPAddresses, 2)
	assert.Equal(t, "192.168.1.1", csr.IPAddresses[0].String())
	assert.Equal(t, "10.0.0.1", csr.IPAddresses[1].String())
}

// TestBuildCSR_WithInvalidIP verifies that buildCSR returns an ErrCSRCreation
// wrapping ErrInvalidIP when given an unparseable IP address string.
func TestBuildCSR_WithInvalidIP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spec := &CertificateSpec{
		Subject: SubjectConfig{CN: "server.local"},
		SANs: SANsConfig{
			IP: []string{"not-an-ip"},
		},
	}

	csrDER, err := buildCSR(spec, key)
	assert.Nil(t, csrDER)
	require.Error(t, err)

	var csrErr ErrCSRCreation
	require.True(t, errors.As(err, &csrErr))

	var ipErr ErrInvalidIP
	require.True(t, errors.As(err, &ipErr))
	assert.Equal(t, "not-an-ip", ipErr.Value)
}

// TestBuildCSR_WithURISANs verifies that buildCSR includes URI Subject
// Alternative Names in the generated CSR.
func TestBuildCSR_WithURISANs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spec := &CertificateSpec{
		Subject: SubjectConfig{CN: "service.local"},
		SANs: SANsConfig{
			URI: []string{"spiffe://cluster.local/ns/default/sa/web"},
		},
	}

	csrDER, err := buildCSR(spec, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	require.Len(t, csr.URIs, 1)
	assert.Equal(t, "spiffe://cluster.local/ns/default/sa/web", csr.URIs[0].String())
}

// TestBuildCSR_WithEmailSANs verifies that buildCSR includes email Subject
// Alternative Names in the generated CSR.
func TestBuildCSR_WithEmailSANs(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spec := &CertificateSpec{
		Subject: SubjectConfig{CN: "admin@example.com"},
		SANs: SANsConfig{
			Email: []string{"admin@example.com", "security@example.com"},
		},
	}

	csrDER, err := buildCSR(spec, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	assert.Equal(t, []string{"admin@example.com", "security@example.com"}, csr.EmailAddresses)
}

// TestBuildCSR_FullSubject verifies that buildCSR populates all subject
// distinguished name fields from the spec configuration.
func TestBuildCSR_FullSubject(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spec := &CertificateSpec{
		Subject: SubjectConfig{
			CN:           "secure.example.com",
			Organization: []string{"Example Inc"},
			Country:      []string{"US"},
			Province:     []string{"California"},
			Locality:     []string{"San Francisco"},
		},
	}

	csrDER, err := buildCSR(spec, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	assert.Equal(t, "secure.example.com", csr.Subject.CommonName)
	assert.Equal(t, []string{"Example Inc"}, csr.Subject.Organization)
	assert.Equal(t, []string{"US"}, csr.Subject.Country)
	assert.Equal(t, []string{"California"}, csr.Subject.Province)
	assert.Equal(t, []string{"San Francisco"}, csr.Subject.Locality)
}

// TestEncodeCertPEM verifies that encodeCertPEM produces a valid PEM block
// with the CERTIFICATE type header from a self-signed certificate.
func TestEncodeCertPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	pemBytes := encodeCertPEM(cert)

	require.NotEmpty(t, pemBytes)
	assert.True(t, strings.HasPrefix(string(pemBytes), "-----BEGIN CERTIFICATE-----"),
		"PEM output must start with CERTIFICATE header")
	assert.Contains(t, string(pemBytes), "-----END CERTIFICATE-----")
}

// TestEncodeKeyPEM_ECDSA verifies that encodeKeyPEM produces a valid PKCS8
// PEM block from an ECDSA private key.
func TestEncodeKeyPEM_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pemBytes, err := encodeKeyPEM(key)
	require.NoError(t, err)
	require.NotEmpty(t, pemBytes)

	assert.True(t, strings.HasPrefix(string(pemBytes), "-----BEGIN PRIVATE KEY-----"),
		"PEM output must start with PRIVATE KEY header")
	assert.Contains(t, string(pemBytes), "-----END PRIVATE KEY-----")
}

// TestEncodeKeyPEM_RSA verifies that encodeKeyPEM produces a valid PKCS8
// PEM block from an RSA private key.
func TestEncodeKeyPEM_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemBytes, err := encodeKeyPEM(key)
	require.NoError(t, err)
	require.NotEmpty(t, pemBytes)

	assert.True(t, strings.HasPrefix(string(pemBytes), "-----BEGIN PRIVATE KEY-----"),
		"PEM output must start with PRIVATE KEY header")
	assert.Contains(t, string(pemBytes), "-----END PRIVATE KEY-----")
}

// TestEncodeKeyPEM_Ed25519 verifies that encodeKeyPEM produces a valid PKCS8
// PEM block from an Ed25519 private key.
func TestEncodeKeyPEM_Ed25519(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemBytes, err := encodeKeyPEM(key)
	require.NoError(t, err)
	require.NotEmpty(t, pemBytes)

	assert.True(t, strings.HasPrefix(string(pemBytes), "-----BEGIN PRIVATE KEY-----"),
		"PEM output must start with PRIVATE KEY header")
	assert.Contains(t, string(pemBytes), "-----END PRIVATE KEY-----")
}

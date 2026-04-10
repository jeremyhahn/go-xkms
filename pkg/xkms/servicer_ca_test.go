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

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCA implements the provider.CA interface used by servicer_ca.go.
// Each method returns configurable values so tests can exercise both success
// and error paths without a real CA implementation.
type mockCA struct {
	bundlePEM     []byte
	bundleErr     error
	cert          *x509.Certificate
	certErr       error
	signCSRCert   *x509.Certificate
	signCSRErr    error
	issueCertPEM  []byte
	issueChainPEM []byte
	issueKeyPEM   []byte
	issueSerial   string
	issueErr      error
	revokeErr     error
	crlDER        []byte
	crlErr        error
	isRevoked     bool
	isRevokedErr  error
	identity      string
	initialized   bool
}

func (m *mockCA) CABundle() ([]byte, error)                 { return m.bundlePEM, m.bundleErr }
func (m *mockCA) CACertificate() (*x509.Certificate, error) { return m.cert, m.certErr }
func (m *mockCA) SignCSRRaw(csrPEM []byte, profile string, validityDays int) (*x509.Certificate, error) {
	return m.signCSRCert, m.signCSRErr
}
func (m *mockCA) IssueCertificateRaw(commonName, organization string, sans []string, validityDays int, profile, algorithm string) (certPEM, chainPEM, keyPEM []byte, serialHex string, err error) {
	return m.issueCertPEM, m.issueChainPEM, m.issueKeyPEM, m.issueSerial, m.issueErr
}
func (m *mockCA) Revoke(serial *big.Int, reason int) error { return m.revokeErr }
func (m *mockCA) GenerateCRL() ([]byte, error)             { return m.crlDER, m.crlErr }
func (m *mockCA) IsRevoked(serial *big.Int) (bool, error)  { return m.isRevoked, m.isRevokedErr }
func (m *mockCA) Identity() string                         { return m.identity }
func (m *mockCA) IsInitialized() bool                      { return m.initialized }

// createSelfSignedCert generates a self-signed CA certificate for testing.
func createSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(12345),
		Subject:               pkix.Name{CommonName: "Test CA"},
		Issuer:                pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// createPEMBundle encodes the given certificates into a PEM bundle.
func createPEMBundle(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var bundle []byte
	for _, cert := range certs {
		block := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		bundle = append(bundle, block...)
	}
	return bundle
}

// setupServiceWithCA initializes the service singleton and optionally wires a CA.
func setupServiceWithCA(t *testing.T, ca provider.CA) *XKMSService {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	if ca != nil {
		svc.SetCA(ca)
	}
	return svc
}

// ========================================================================
// GetCABundle
// ========================================================================

func TestGetCABundle_Success(t *testing.T) {
	cert1 := createSelfSignedCert(t)
	cert2 := createSelfSignedCert(t)
	bundlePEM := createPEMBundle(t, cert1, cert2)

	ca := &mockCA{
		bundlePEM: bundlePEM,
	}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &transport.GetCABundleRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, bundlePEM, resp.BundlePEM)
	assert.Equal(t, "application/x-pem-file", resp.ContentType)
	require.Len(t, resp.Certificates, 2)

	// Verify the DER certificates can be parsed back.
	parsed1, err := x509.ParseCertificate(resp.Certificates[0])
	require.NoError(t, err)
	assert.Equal(t, cert1.SerialNumber.Int64(), parsed1.SerialNumber.Int64())

	parsed2, err := x509.ParseCertificate(resp.Certificates[1])
	require.NoError(t, err)
	assert.Equal(t, cert2.SerialNumber.Int64(), parsed2.SerialNumber.Int64())
}

func TestGetCABundle_SingleCert(t *testing.T) {
	cert := createSelfSignedCert(t)
	bundlePEM := createPEMBundle(t, cert)

	ca := &mockCA{bundlePEM: bundlePEM}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &transport.GetCABundleRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Certificates, 1)
}

func TestGetCABundle_NoCA(t *testing.T) {
	svc := setupServiceWithCA(t, nil)
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &transport.GetCABundleRequest{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestGetCABundle_CAError(t *testing.T) {
	caErr := errors.New("ca: internal failure")
	ca := &mockCA{bundleErr: caErr}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &transport.GetCABundleRequest{})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: get bundle")
}

func TestGetCABundle_EmptyPEM(t *testing.T) {
	ca := &mockCA{bundlePEM: []byte{}}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &transport.GetCABundleRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Certificates)
	assert.Equal(t, "application/x-pem-file", resp.ContentType)
}

// ========================================================================
// GetCACertificate
// ========================================================================

func TestGetCACertificate_Success(t *testing.T) {
	cert := createSelfSignedCert(t)
	ca := &mockCA{cert: cert}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, cert.Subject.String(), resp.Subject)
	assert.Equal(t, cert.Issuer.String(), resp.Issuer)
	assert.Equal(t, cert.SerialNumber.Text(16), resp.SerialNumber)
	assert.True(t, resp.IsCA)

	// Verify the PEM can be decoded back to the original cert.
	block, rest := pem.Decode(resp.CertificatePEM)
	require.NotNil(t, block)
	assert.Empty(t, rest)
	assert.Equal(t, "CERTIFICATE", block.Type)

	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, cert.SerialNumber.Int64(), parsed.SerialNumber.Int64())

	// Verify time formatting.
	assert.Equal(t, cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"), resp.NotBefore)
	assert.Equal(t, cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), resp.NotAfter)
}

func TestGetCACertificate_NoCA(t *testing.T) {
	svc := setupServiceWithCA(t, nil)
	ctx := context.Background()

	resp, err := svc.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestGetCACertificate_CAError(t *testing.T) {
	caErr := errors.New("ca: cert unavailable")
	ca := &mockCA{certErr: caErr}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: get certificate")
}

// ========================================================================
// SignCSR
// ========================================================================

func TestSignCSR_Success(t *testing.T) {
	caCert := createSelfSignedCert(t)
	signedCert := createSelfSignedCert(t)

	ca := &mockCA{
		signCSRCert: signedCert,
		cert:        caCert,
	}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:       []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
		Profile:      "server",
		ValidityDays: 365,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the signed certificate PEM.
	block, _ := pem.Decode(resp.CertificatePEM)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, signedCert.SerialNumber.Int64(), parsed.SerialNumber.Int64())

	// Verify the chain PEM contains the CA certificate.
	chainBlock, _ := pem.Decode(resp.ChainPEM)
	require.NotNil(t, chainBlock)
	chainParsed, err := x509.ParseCertificate(chainBlock.Bytes)
	require.NoError(t, err)
	assert.Equal(t, caCert.SerialNumber.Int64(), chainParsed.SerialNumber.Int64())

	assert.Equal(t, signedCert.SerialNumber.Text(16), resp.SerialNumber)
}

func TestSignCSR_SuccessNoChain(t *testing.T) {
	// Test when CACertificate() returns an error - chain should be empty.
	signedCert := createSelfSignedCert(t)
	ca := &mockCA{
		signCSRCert: signedCert,
		certErr:     errors.New("no ca cert"),
	}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// CertificatePEM should still be present.
	assert.NotEmpty(t, resp.CertificatePEM)
	// Chain should be nil/empty since CACertificate() failed.
	assert.Empty(t, resp.ChainPEM)
}

func TestSignCSR_NilRequest(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestSignCSR_EmptyCSR(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM: nil,
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilData)

	// Also test with zero-length byte slice.
	resp, err = svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM: []byte{},
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilData)
}

func TestSignCSR_NoCA(t *testing.T) {
	svc := setupServiceWithCA(t, nil)
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestSignCSR_CAError(t *testing.T) {
	caErr := errors.New("ca: signing failed")
	ca := &mockCA{signCSRErr: caErr}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: sign csr")
}

// ========================================================================
// IssueCertificate
// ========================================================================

func TestIssueCertificate_Success(t *testing.T) {
	certPEM := []byte("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----")
	chainPEM := []byte("-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----")
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nkey\n-----END EC PRIVATE KEY-----")

	ca := &mockCA{
		issueCertPEM:  certPEM,
		issueChainPEM: chainPEM,
		issueKeyPEM:   keyPEM,
		issueSerial:   "abcdef01",
	}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName:   "test.example.com",
		Organization: "Test Org",
		SANs:         []string{"DNS:test.example.com", "IP:127.0.0.1"},
		ValidityDays: 365,
		Profile:      "server",
		Algorithm:    "ecdsa-p256",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, certPEM, resp.CertificatePEM)
	assert.Equal(t, chainPEM, resp.ChainPEM)
	assert.Equal(t, keyPEM, resp.PrivateKeyPEM)
	assert.Equal(t, "abcdef01", resp.SerialNumber)
}

func TestIssueCertificate_NilRequest(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestIssueCertificate_EmptyCommonName(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName: "",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "common name required")
}

func TestIssueCertificate_NoCA(t *testing.T) {
	svc := setupServiceWithCA(t, nil)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName: "test.example.com",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestIssueCertificate_CAError(t *testing.T) {
	caErr := errors.New("ca: issuance failed")
	ca := &mockCA{issueErr: caErr}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName: "test.example.com",
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: issue certificate")
}

// ========================================================================
// RevokeCertificate
// ========================================================================

func TestRevokeCertificate_Success(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "abcdef01",
		Reason:       1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Success)
	assert.Contains(t, resp.Message, "abcdef01")
	assert.Contains(t, resp.Message, "revoked")
}

func TestRevokeCertificate_NilRequest(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestRevokeCertificate_EmptySerial(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "serial number required")
}

func TestRevokeCertificate_InvalidSerialFormat(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "xyz-not-hex",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "invalid serial number format")
}

func TestRevokeCertificate_WithHexPrefix(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "0xabcdef",
		Reason:       1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.Contains(t, resp.Message, "0xabcdef")
}

func TestRevokeCertificate_WithUpperHexPrefix(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "0Xabcdef",
		Reason:       0,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

func TestRevokeCertificate_NoCA(t *testing.T) {
	svc := setupServiceWithCA(t, nil)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "abcdef01",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestRevokeCertificate_CAError(t *testing.T) {
	caErr := errors.New("ca: revocation failed")
	ca := &mockCA{revokeErr: caErr}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "abcdef01",
		Reason:       1,
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: revoke")
}

// ========================================================================
// GenerateCRL
// ========================================================================

func TestGenerateCRL_Success(t *testing.T) {
	crlDER := []byte("fake-crl-der-content")
	ca := &mockCA{crlDER: crlDER}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.GenerateCRL(ctx, &transport.GenerateCRLRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the response is PEM-encoded with the correct block type.
	block, rest := pem.Decode(resp.CRLPEM)
	require.NotNil(t, block)
	assert.Empty(t, rest)
	assert.Equal(t, "X509 CRL", block.Type)
	assert.Equal(t, crlDER, block.Bytes)
}

func TestGenerateCRL_NoCA(t *testing.T) {
	svc := setupServiceWithCA(t, nil)
	ctx := context.Background()

	resp, err := svc.GenerateCRL(ctx, &transport.GenerateCRLRequest{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestGenerateCRL_CAError(t *testing.T) {
	caErr := errors.New("ca: crl generation failed")
	ca := &mockCA{crlErr: caErr}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.GenerateCRL(ctx, &transport.GenerateCRLRequest{})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: generate crl")
}

// ========================================================================
// IsRevoked
// ========================================================================

func TestIsRevoked_Revoked(t *testing.T) {
	ca := &mockCA{isRevoked: true}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "abcdef01",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.True(t, resp.Revoked)
	assert.Equal(t, "certificate is revoked", resp.Message)
}

func TestIsRevoked_NotRevoked(t *testing.T) {
	ca := &mockCA{isRevoked: false}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "abcdef01",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.False(t, resp.Revoked)
	assert.Equal(t, "certificate is not revoked", resp.Message)
}

func TestIsRevoked_NilRequest(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestIsRevoked_EmptySerial(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "serial number required")
}

func TestIsRevoked_InvalidSerialFormat(t *testing.T) {
	ca := &mockCA{}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "not-valid-hex",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "invalid serial number format")
}

func TestIsRevoked_NoCA(t *testing.T) {
	svc := setupServiceWithCA(t, nil)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "abcdef01",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestIsRevoked_CAError(t *testing.T) {
	caErr := errors.New("ca: revocation check failed")
	ca := &mockCA{isRevokedErr: caErr}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "abcdef01",
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: is revoked")
}

func TestIsRevoked_WithHexPrefix(t *testing.T) {
	ca := &mockCA{isRevoked: true}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "0xabcdef",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Revoked)
}

// ========================================================================
// parseSerialHex
// ========================================================================

func TestParseSerialHex_Valid(t *testing.T) {
	serial, err := parseSerialHex("abc")
	require.NoError(t, err)
	require.NotNil(t, serial)
	assert.Equal(t, int64(0xabc), serial.Int64())
}

func TestParseSerialHex_WithLowerPrefix(t *testing.T) {
	serial, err := parseSerialHex("0xabc")
	require.NoError(t, err)
	require.NotNil(t, serial)
	assert.Equal(t, int64(0xabc), serial.Int64())
}

func TestParseSerialHex_WithUpperPrefix(t *testing.T) {
	serial, err := parseSerialHex("0Xabc")
	require.NoError(t, err)
	require.NotNil(t, serial)
	assert.Equal(t, int64(0xabc), serial.Int64())
}

func TestParseSerialHex_Invalid(t *testing.T) {
	serial, err := parseSerialHex("xyz")
	assert.Nil(t, serial)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "invalid serial number format")
}

func TestParseSerialHex_LargeValue(t *testing.T) {
	serial, err := parseSerialHex("ffffffffffffffffffffffffffffffff")
	require.NoError(t, err)
	require.NotNil(t, serial)

	expected := new(big.Int)
	expected.SetString("ffffffffffffffffffffffffffffffff", 16)
	assert.Equal(t, 0, serial.Cmp(expected))
}

func TestParseSerialHex_Empty(t *testing.T) {
	serial, err := parseSerialHex("")
	assert.Nil(t, serial)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
}

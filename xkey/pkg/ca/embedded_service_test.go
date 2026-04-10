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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockXKMSCA implements ca.TCGCA for unit testing.
type mockXKMSCA struct {
	caCert          *x509.Certificate
	caBundlePEM     []byte
	signCSRCert     *x509.Certificate
	issuedCert      *ca.IssuedCertificate
	crlDER          []byte
	revokedSerials  map[string]bool
	initErr         error
	loadErr         error
	caCertErr       error
	caBundleErr     error
	signCSRErr      error
	issueErr        error
	issueProfileErr error
	revokeErr       error
	generateCRLErr  error
	isRevokedErr    error
	initialized     bool
	privateKey      crypto.PrivateKey

	// TCG certificate fields
	ekCert        *x509.Certificate
	akCert        *x509.Certificate
	iakCertDER    []byte
	idevidCertDER []byte
	enrollResult  *ca.TCGEnrollmentResult
	issueEKErr    error
	issueAKErr    error
	signTCGCSRErr error
	enrollErr     error
	tpmSet        bool
}

func (m *mockXKMSCA) Init() error                    { return m.initErr }
func (m *mockXKMSCA) Load() error                    { return m.loadErr }
func (m *mockXKMSCA) IsInitialized() bool            { return m.initialized }
func (m *mockXKMSCA) Config() *ca.Identity           { return &ca.Identity{} }
func (m *mockXKMSCA) Identity() string               { return "Test CA" }
func (m *mockXKMSCA) KeyStore() xkms.Backend         { return nil }
func (m *mockXKMSCA) CertStore() certstore.CertStore { return nil }
func (m *mockXKMSCA) Verify(_ *x509.Certificate) ([][]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockXKMSCA) TLSCertificate(_ *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *mockXKMSCA) TLSConfig(_ *types.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *mockXKMSCA) CreateCSR(_ *ca.CertificateRequest) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSCA) Public() crypto.PublicKey {
	if m.privateKey == nil {
		return nil
	}
	if signer, ok := m.privateKey.(crypto.Signer); ok {
		return signer.Public()
	}
	return nil
}

func (m *mockXKMSCA) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func (m *mockXKMSCA) CACertificate() (*x509.Certificate, error) {
	if m.caCertErr != nil {
		return nil, m.caCertErr
	}
	return m.caCert, nil
}

func (m *mockXKMSCA) CABundle() ([]byte, error) {
	if m.caBundleErr != nil {
		return nil, m.caBundleErr
	}
	return m.caBundlePEM, nil
}

func (m *mockXKMSCA) SignCSR(_ []byte, _ *ca.SignOptions) (*x509.Certificate, error) {
	if m.signCSRErr != nil {
		return nil, m.signCSRErr
	}
	return m.signCSRCert, nil
}

func (m *mockXKMSCA) IssueCertificate(_ *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	if m.issueErr != nil {
		return nil, m.issueErr
	}
	return m.issuedCert, nil
}

func (m *mockXKMSCA) IssueCertificateWithProfile(_ *ca.CertificateRequest, _ string) (*ca.IssuedCertificate, error) {
	if m.issueProfileErr != nil {
		return nil, m.issueProfileErr
	}
	return m.issuedCert, nil
}

func (m *mockXKMSCA) Revoke(serial *big.Int, _ int) error {
	if m.revokeErr != nil {
		return m.revokeErr
	}
	if m.revokedSerials == nil {
		m.revokedSerials = make(map[string]bool)
	}
	m.revokedSerials[serial.Text(10)] = true
	return nil
}

func (m *mockXKMSCA) GenerateCRL() ([]byte, error) {
	if m.generateCRLErr != nil {
		return nil, m.generateCRLErr
	}
	return m.crlDER, nil
}

func (m *mockXKMSCA) IsRevoked(serial *big.Int) (bool, error) {
	if m.isRevokedErr != nil {
		return false, m.isRevokedErr
	}
	if m.revokedSerials == nil {
		return false, nil
	}
	return m.revokedSerials[serial.Text(10)], nil
}

func (m *mockXKMSCA) IssueEKCertificate(_ *ca.CertificateRequest, _ crypto.PublicKey) (*x509.Certificate, error) {
	if m.issueEKErr != nil {
		return nil, m.issueEKErr
	}
	return m.ekCert, nil
}

func (m *mockXKMSCA) IssueAKCertificate(_ *ca.CertificateRequest, _ crypto.PublicKey) (*x509.Certificate, error) {
	if m.issueAKErr != nil {
		return nil, m.issueAKErr
	}
	return m.akCert, nil
}

func (m *mockXKMSCA) SignTCGCSRIDevID(_ *tpm2.TCG_CSR_IDEVID, _ *ca.CertificateRequest) ([]byte, []byte, error) {
	if m.signTCGCSRErr != nil {
		return nil, nil, m.signTCGCSRErr
	}
	return m.iakCertDER, m.idevidCertDER, nil
}

func (m *mockXKMSCA) EnrollDevice(_ []byte, _ *ca.CertificateRequest) (*ca.TCGEnrollmentResult, error) {
	if m.enrollErr != nil {
		return nil, m.enrollErr
	}
	return m.enrollResult, nil
}

func (m *mockXKMSCA) SetTPM(_ tpm2.TrustedPlatformModule) {
	m.tpmSet = true
}

// createTestCert generates a self-signed test certificate for mock responses.
func createTestCert(t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// createTestCertPEM returns the PEM-encoded test certificate.
func createTestCertPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// createTestCRL generates a test CRL in DER format.
func createTestCRL(t *testing.T, caCert *x509.Certificate, caKey crypto.PrivateKey) []byte {
	t.Helper()

	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(7 * 24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, caKey.(crypto.Signer))
	require.NoError(t, err)

	return crlDER
}

// newTestService creates a Service with a populated mock for testing.
func newTestService(t *testing.T) (*Service, *mockXKMSCA) {
	t.Helper()

	cert, key := createTestCert(t)
	certPEM := createTestCertPEM(t, cert)
	crlDER := createTestCRL(t, cert, key)

	mock := &mockXKMSCA{
		caCert:      cert,
		caBundlePEM: certPEM,
		signCSRCert: cert,
		issuedCert: &ca.IssuedCertificate{
			Certificate:    cert,
			CertificatePEM: certPEM,
			ChainPEM:       certPEM,
			PrivateKeyPEM:  nil,
			SerialNumber:   cert.SerialNumber,
			NotBefore:      cert.NotBefore,
			NotAfter:       cert.NotAfter,
		},
		crlDER:         crlDER,
		revokedSerials: make(map[string]bool),
		initialized:    true,
		privateKey:     key,

		// TCG mock fields
		ekCert:        cert,
		akCert:        cert,
		iakCertDER:    cert.Raw,
		idevidCertDER: cert.Raw,
		enrollResult: &ca.TCGEnrollmentResult{
			IAKCertDER:      cert.Raw,
			IDevIDCertDER:   cert.Raw,
			CredentialBlob:  []byte("test-credential-blob"),
			EncryptedSecret: []byte("test-encrypted-secret"),
			PlainSecret:     []byte("test-plain-secret"),
		},
	}

	svc, err := NewService(&Config{
		HomeDir:             "/tmp/xkey-test",
		DefaultValidityDays: 365,
	}, mock)
	require.NoError(t, err)

	return svc, mock
}

// ============================================================================
// NewService Tests
// ============================================================================

func TestNewService_Success(t *testing.T) {
	cert, key := createTestCert(t)
	mock := &mockXKMSCA{caCert: cert, privateKey: key}

	svc, err := NewService(&Config{HomeDir: "/tmp/test"}, mock)
	require.NoError(t, err)
	assert.NotNil(t, svc)
	assert.Equal(t, mock, svc.CA())
}

func TestNewService_NilConfig(t *testing.T) {
	cert, key := createTestCert(t)
	mock := &mockXKMSCA{caCert: cert, privateKey: key}

	svc, err := NewService(nil, mock)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrNilConfig)
}

func TestNewService_NilCA(t *testing.T) {
	svc, err := NewService(&Config{HomeDir: "/tmp/test"}, nil)
	assert.Nil(t, svc)
	assert.ErrorIs(t, err, ErrNilCA)
}

// ============================================================================
// GetCABundle Tests
// ============================================================================

func TestGetCABundle_Success(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &transport.GetCABundleRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.BundlePEM)
	assert.NotEmpty(t, resp.Certificates)
	assert.Equal(t, ContentTypePEMCertificateChain, resp.ContentType)
}

func TestGetCABundle_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestGetCABundle_CABundleError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.caBundleErr = errors.New("storage failure")
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &transport.GetCABundleRequest{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrBundleGeneration)
}

func TestGetCABundle_WithAlgorithmFilter(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Filter for ECDSA should match our test cert.
	resp, err := svc.GetCABundle(ctx, &transport.GetCABundleRequest{
		Algorithm: "ECDSA",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.BundlePEM)
	assert.Len(t, resp.Certificates, 1)

	// Filter for RSA should return empty since our test cert is ECDSA.
	resp, err = svc.GetCABundle(ctx, &transport.GetCABundleRequest{
		Algorithm: "RSA",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Certificates)
}

// ============================================================================
// GetCACertificate Tests
// ============================================================================

func TestGetCACertificate_Success(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CertificatePEM)
	assert.Equal(t, "42", resp.SerialNumber)
	assert.True(t, resp.IsCA)
	assert.Contains(t, resp.Subject, "Test CA")
}

func TestGetCACertificate_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.GetCACertificate(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestGetCACertificate_CAError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.caCertErr = errors.New("key not found")
	ctx := context.Background()

	resp, err := svc.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrCACertificateRetrieval)
}

// ============================================================================
// SignCSR Tests
// ============================================================================

func TestSignCSR_Success(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:       []byte("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----"),
		Profile:      "server",
		ValidityDays: 90,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CertificatePEM)
	assert.NotEmpty(t, resp.ChainPEM)
	assert.Equal(t, "42", resp.SerialNumber)
}

func TestSignCSR_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestSignCSR_EmptyCSR(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM: nil,
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrEmptyCSR)
}

func TestSignCSR_SigningError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.signCSRErr = errors.New("invalid CSR")
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM: []byte("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrCSRSigning)
}

func TestSignCSR_ChainUnavailable(t *testing.T) {
	svc, mock := newTestService(t)
	mock.caBundleErr = errors.New("no chain")
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM: []byte("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CertificatePEM)
	assert.Nil(t, resp.ChainPEM)
}

// ============================================================================
// IssueCertificate Tests
// ============================================================================

func TestIssueCertificate_Success(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName:   "server.example.com",
		Organization: "Example Inc",
		SANs:         []string{"DNS:server.example.com", "IP:10.0.0.1"},
		ValidityDays: 365,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CertificatePEM)
	assert.Equal(t, "42", resp.SerialNumber)
}

func TestIssueCertificate_WithProfile(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName: "server.example.com",
		Profile:    "server",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CertificatePEM)
}

func TestIssueCertificate_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestIssueCertificate_EmptyCommonName(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName: "",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrEmptyCommonName)
}

func TestIssueCertificate_IssuanceError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.issueErr = errors.New("key generation failed")
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName: "server.example.com",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrCertificateIssuance)
}

func TestIssueCertificate_ProfileError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.issueProfileErr = errors.New("profile not found")
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName: "server.example.com",
		Profile:    "nonexistent",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrCertificateIssuance)
}

// ============================================================================
// RevokeCertificate Tests
// ============================================================================

func TestRevokeCertificate_Success(t *testing.T) {
	svc, mock := newTestService(t)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "123456",
		Reason:       1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.Equal(t, "certificate revoked", resp.Message)
	assert.True(t, mock.revokedSerials["123456"])
}

func TestRevokeCertificate_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestRevokeCertificate_EmptySerialNumber(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrEmptySerialNumber)
}

func TestRevokeCertificate_InvalidSerialNumber(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "not-a-number",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidSerialNumber)
}

func TestRevokeCertificate_RevocationError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.revokeErr = errors.New("already revoked")
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "123456",
		Reason:       0,
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrCertificateRevocation)
}

// ============================================================================
// GenerateCRL Tests
// ============================================================================

func TestGenerateCRL_Success(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.GenerateCRL(ctx, &transport.GenerateCRLRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CRLPEM)

	// Verify PEM structure.
	block, _ := pem.Decode(resp.CRLPEM)
	require.NotNil(t, block)
	assert.Equal(t, "X509 CRL", block.Type)
}

func TestGenerateCRL_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.GenerateCRL(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestGenerateCRL_GenerationError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.generateCRLErr = errors.New("CRL generation failed")
	ctx := context.Background()

	resp, err := svc.GenerateCRL(ctx, &transport.GenerateCRLRequest{})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrCRLGeneration)
}

// ============================================================================
// IsRevoked Tests
// ============================================================================

func TestIsRevoked_NotRevoked(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "999",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.False(t, resp.Revoked)
}

func TestIsRevoked_Revoked(t *testing.T) {
	svc, mock := newTestService(t)
	mock.revokedSerials["42"] = true
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "42",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Revoked)
}

func TestIsRevoked_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestIsRevoked_EmptySerialNumber(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrEmptySerialNumber)
}

func TestIsRevoked_InvalidSerialNumber(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "abc-invalid",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidSerialNumber)
}

func TestIsRevoked_CheckError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.isRevokedErr = errors.New("storage error")
	ctx := context.Background()

	resp, err := svc.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: "42",
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrRevocationCheck)
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestParseSANs(t *testing.T) {
	sans := parseSANs([]string{
		"DNS:example.com",
		"DNS:www.example.com",
		"IP:10.0.0.1",
		"IP:192.168.1.1",
		"Email:admin@example.com",
		"URI:https://example.com",
		"bare-domain.com",
	})

	require.NotNil(t, sans)
	assert.Equal(t, []string{"example.com", "www.example.com", "bare-domain.com"}, sans.DNS)
	assert.Equal(t, []string{"10.0.0.1", "192.168.1.1"}, sans.IPs)
	assert.Equal(t, []string{"admin@example.com"}, sans.Email)
	assert.Equal(t, []string{"https://example.com"}, sans.URIs)
}

func TestParseSANs_Empty(t *testing.T) {
	sans := parseSANs([]string{})
	require.NotNil(t, sans)
	assert.Empty(t, sans.DNS)
	assert.Empty(t, sans.IPs)
	assert.Empty(t, sans.Email)
	assert.Empty(t, sans.URIs)
}

func TestParsePEMCertificates(t *testing.T) {
	cert, _ := createTestCert(t)
	certPEM := createTestCertPEM(t, cert)

	// Two certificates concatenated.
	twoCerts := append(certPEM, certPEM...)
	result := parsePEMCertificates(twoCerts)
	assert.Len(t, result, 2)
}

func TestParsePEMCertificates_Empty(t *testing.T) {
	result := parsePEMCertificates(nil)
	assert.Empty(t, result)
}

func TestParsePEMCertificates_NonCertPEM(t *testing.T) {
	nonCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake-key-data"),
	})
	result := parsePEMCertificates(nonCertPEM)
	assert.Empty(t, result)
}

func TestFilterByAlgorithm_EmptyFilter(t *testing.T) {
	cert, _ := createTestCert(t)
	derCerts := [][]byte{cert.Raw}

	result := filterByAlgorithm(derCerts, "")
	assert.Len(t, result, 1)
}

func TestFilterByAlgorithm_MatchingFilter(t *testing.T) {
	cert, _ := createTestCert(t)
	derCerts := [][]byte{cert.Raw}

	result := filterByAlgorithm(derCerts, "ECDSA")
	assert.Len(t, result, 1)
}

func TestFilterByAlgorithm_NonMatchingFilter(t *testing.T) {
	cert, _ := createTestCert(t)
	derCerts := [][]byte{cert.Raw}

	result := filterByAlgorithm(derCerts, "RSA")
	assert.Empty(t, result)
}

func TestFilterByAlgorithm_InvalidDER(t *testing.T) {
	derCerts := [][]byte{[]byte("not-a-certificate")}

	result := filterByAlgorithm(derCerts, "ECDSA")
	assert.Empty(t, result)
}

func TestEncodeDERCertsToPEM(t *testing.T) {
	cert, _ := createTestCert(t)
	derCerts := [][]byte{cert.Raw}

	result := encodeDERCertsToPEM(derCerts)
	assert.NotEmpty(t, result)

	block, _ := pem.Decode(result)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
}

func TestEncodeDERCertsToPEM_Empty(t *testing.T) {
	result := encodeDERCertsToPEM(nil)
	assert.Empty(t, result)
}

func TestMatchesAlgorithmName(t *testing.T) {
	assert.True(t, matchesAlgorithmName("ECDSA", "ECDSA"))
	assert.True(t, matchesAlgorithmName("ecdsa", "ECDSA"))
	assert.True(t, matchesAlgorithmName("Ecdsa", "ECDSA"))
	assert.False(t, matchesAlgorithmName("RSA", "ECDSA"))
	assert.False(t, matchesAlgorithmName("", "ECDSA"))
}

// ============================================================================
// TCG Certificate Tests
// ============================================================================

func TestIssueEKCertificate_Success(t *testing.T) {
	svc, _ := newTestService(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, err := svc.IssueEKCertificate(&ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "EK Certificate"},
	}, &key.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "Test CA", cert.Subject.CommonName)
}

func TestIssueEKCertificate_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, err := svc.IssueEKCertificate(nil, &key.PublicKey)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestIssueEKCertificate_IssuanceError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.issueEKErr = errors.New("TPM EK extraction failed")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, err := svc.IssueEKCertificate(&ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "EK Certificate"},
	}, &key.PublicKey)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrTCGCertIssuance)
}

func TestIssueAKCertificate_Success(t *testing.T) {
	svc, _ := newTestService(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, err := svc.IssueAKCertificate(&ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "AK Certificate"},
	}, &key.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "Test CA", cert.Subject.CommonName)
}

func TestIssueAKCertificate_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, err := svc.IssueAKCertificate(nil, &key.PublicKey)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestIssueAKCertificate_IssuanceError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.issueAKErr = errors.New("AK policy violation")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert, err := svc.IssueAKCertificate(&ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "AK Certificate"},
	}, &key.PublicKey)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrTCGCertIssuance)
}

func TestSignTCGCSRIDevID_Success(t *testing.T) {
	svc, _ := newTestService(t)

	iakDER, idevidDER, err := svc.SignTCGCSRIDevID(&tpm2.TCG_CSR_IDEVID{}, &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "Device Identity"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, iakDER)
	assert.NotEmpty(t, idevidDER)
}

func TestSignTCGCSRIDevID_NilCSR(t *testing.T) {
	svc, _ := newTestService(t)

	iakDER, idevidDER, err := svc.SignTCGCSRIDevID(nil, &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "Device Identity"},
	})
	assert.Nil(t, iakDER)
	assert.Nil(t, idevidDER)
	assert.ErrorIs(t, err, ErrNilTCGCSR)
}

func TestSignTCGCSRIDevID_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)

	iakDER, idevidDER, err := svc.SignTCGCSRIDevID(&tpm2.TCG_CSR_IDEVID{}, nil)
	assert.Nil(t, iakDER)
	assert.Nil(t, idevidDER)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestSignTCGCSRIDevID_SigningError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.signTCGCSRErr = errors.New("CSR signature verification failed")

	iakDER, idevidDER, err := svc.SignTCGCSRIDevID(&tpm2.TCG_CSR_IDEVID{}, &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "Device Identity"},
	})
	assert.Nil(t, iakDER)
	assert.Nil(t, idevidDER)
	assert.ErrorIs(t, err, ErrTCGCSRSigning)
}

func TestEnrollDevice_Success(t *testing.T) {
	svc, _ := newTestService(t)

	result, err := svc.EnrollDevice([]byte("fake-packed-csr"), &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "Enrolled Device"},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.IAKCertDER)
	assert.NotEmpty(t, result.IDevIDCertDER)
	assert.NotEmpty(t, result.CredentialBlob)
	assert.NotEmpty(t, result.EncryptedSecret)
	assert.NotEmpty(t, result.PlainSecret)
}

func TestEnrollDevice_EmptyCSR(t *testing.T) {
	svc, _ := newTestService(t)

	result, err := svc.EnrollDevice([]byte{}, &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "Enrolled Device"},
	})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrEmptyPackedCSR)
}

func TestEnrollDevice_NilCSR(t *testing.T) {
	svc, _ := newTestService(t)

	result, err := svc.EnrollDevice(nil, &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "Enrolled Device"},
	})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrEmptyPackedCSR)
}

func TestEnrollDevice_NilRequest(t *testing.T) {
	svc, _ := newTestService(t)

	result, err := svc.EnrollDevice([]byte("fake-packed-csr"), nil)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestEnrollDevice_EnrollmentError(t *testing.T) {
	svc, mock := newTestService(t)
	mock.enrollErr = errors.New("MakeCredential failed")

	result, err := svc.EnrollDevice([]byte("fake-packed-csr"), &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "Enrolled Device"},
	})
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrTCGEnrollment)
}

func TestSetTPM(t *testing.T) {
	svc, mock := newTestService(t)

	assert.False(t, mock.tpmSet)
	svc.SetTPM(nil)
	assert.True(t, mock.tpmSet)
}

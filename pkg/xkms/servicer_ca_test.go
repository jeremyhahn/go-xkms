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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCA implements the provider.CA interface used by servicer_ca.go.
// Each method returns configurable values so tests can exercise both success
// and error paths without a real CA implementation.
type mockCA struct {
	bundlePEM   []byte
	bundleErr   error
	cert        *x509.Certificate
	certErr     error
	signCSRCert *x509.Certificate
	signCSRErr  error
	// signCSRTenant records the tenant SignCSRWithSPIFFE was asked to stamp.
	signCSRTenant string
	issueCertPEM  []byte
	issueChainPEM []byte
	issueKeyPEM   []byte
	issueSerial   string
	issueErr      error
	// issueTenant records the tenantID IssueCertificateRaw was asked to
	// stamp.
	issueTenant string
	revokeErr   error
	// certTenant and certTenantErr are what CertificateTenant returns for
	// the RevokeCertificate ownership check.
	certTenant    string
	certTenantErr error
	crlDER        []byte
	crlErr        error
	crlReadDER    []byte
	crlReadErr    error
	isRevoked     bool
	isRevokedErr  error
	identity      string
	initialized   bool
}

func (m *mockCA) CABundle() ([]byte, error)                 { return m.bundlePEM, m.bundleErr }
func (m *mockCA) CACertificate() (*x509.Certificate, error) { return m.cert, m.certErr }
func (m *mockCA) SignCSRRaw(_ context.Context, csrPEM []byte, profile string, validityDays int) (*x509.Certificate, error) {
	return m.signCSRCert, m.signCSRErr
}
func (m *mockCA) SignCSRWithSPIFFE(_ context.Context, csrPEM []byte, profile string, validityDays int, trustDomain, tenantID, kind, name string) (*x509.Certificate, error) {
	m.signCSRTenant = tenantID
	return m.signCSRCert, m.signCSRErr
}
func (m *mockCA) IssueCertificateRaw(_ context.Context, commonName, organization string, sans []string, validityDays int, profile, algorithm, tenantID string) (certPEM, chainPEM, keyPEM []byte, serialHex string, err error) {
	m.issueTenant = tenantID
	return m.issueCertPEM, m.issueChainPEM, m.issueKeyPEM, m.issueSerial, m.issueErr
}
func (m *mockCA) Revoke(_ context.Context, serial *big.Int, reason int) error { return m.revokeErr }
func (m *mockCA) CertificateTenant(_ context.Context, serial *big.Int) (string, error) {
	return m.certTenant, m.certTenantErr
}
func (m *mockCA) GenerateCRL(_ context.Context) ([]byte, error) { return m.crlDER, m.crlErr }
func (m *mockCA) CRL(_ context.Context) ([]byte, error)         { return m.crlReadDER, m.crlReadErr }
func (m *mockCA) IsRevoked(serial *big.Int) (bool, error)       { return m.isRevoked, m.isRevokedErr }
func (m *mockCA) Identity() string                              { return m.identity }
func (m *mockCA) IsInitialized() bool                           { return m.initialized }

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
// RevokeCertificate / IssueCertificate ownership (go-xkms#1229)
//
// RevokeCertificate's permission, certs:revoke, is enforced by the
// transports before dispatch, exactly like SignCSR's certs:issue (see
// "SignCSR authorization" above); pkg/api/grpc/service_authz_deny_test.go
// drives the permission-denial path. These tests drive the ownership check
// the servicer itself makes: the certificate's issuing tenant, recorded at
// issuance, against the caller's own tenant.
// ========================================================================

// TestRevokeCertificate_ForeignTenantRefused is the go-xkms#1229 exploit: a
// tenant-scoped caller could revoke a certificate issued for a different
// tenant. It must now be refused exactly like naming a foreign tenant
// anywhere else in this service (requireBindingRefusal), and the CA's
// Revoke must never be reached.
func TestRevokeCertificate_ForeignTenantRefused(t *testing.T) {
	ca := &mockCA{certTenant: "tenant-b", revokeErr: errors.New("must not be called")}
	svc := setupServiceWithCA(t, ca)
	ctx := tenantCtx("tenant-a")

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "abcdef01",
		Reason:       1,
	})
	assert.Nil(t, resp)
	requireBindingRefusal(t, err, "revoke certificate")
}

// TestRevokeCertificate_OwnTenantAllowed is the mirror: a tenant-scoped
// caller may revoke a certificate its own tenant owns.
func TestRevokeCertificate_OwnTenantAllowed(t *testing.T) {
	ca := &mockCA{certTenant: "tenant-a"}
	svc := setupServiceWithCA(t, ca)
	ctx := tenantCtx("tenant-a")

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "abcdef01",
		Reason:       1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Success)
}

// TestRevokeCertificate_SystemAdminRevokesAnyTenant proves a cross-tenant
// (system) caller may revoke a certificate belonging to any tenant,
// including the system/platform scope's own certificates.
func TestRevokeCertificate_SystemAdminRevokesAnyTenant(t *testing.T) {
	for _, certTenant := range []string{"", "tenant-a", "tenant-b"} {
		ca := &mockCA{certTenant: certTenant}
		svc := setupServiceWithCA(t, ca)
		ctx := systemCtx()

		resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
			SerialNumber: "abcdef01",
			Reason:       1,
		})
		require.NoError(t, err, "cert tenant %q", certTenant)
		require.NotNil(t, resp, "cert tenant %q", certTenant)
		assert.True(t, resp.Success, "cert tenant %q", certTenant)
	}
}

// TestRevokeCertificate_CertificateTenantError proves a storage fault
// resolving the issuing tenant aborts the revoke rather than being treated
// as an unowned (system-scope) certificate.
func TestRevokeCertificate_CertificateTenantError(t *testing.T) {
	lookupErr := errors.New("ca: storage fault")
	ca := &mockCA{certTenantErr: lookupErr, revokeErr: errors.New("must not be called")}
	svc := setupServiceWithCA(t, ca)
	ctx := tenantCtx("tenant-a")

	resp, err := svc.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: "abcdef01",
		Reason:       1,
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, lookupErr)
}

// TestIssueCertificate_ForeignTenantRefused proves a tenant-scoped caller
// cannot mint a certificate attributed to a different tenant, mirroring
// SignCSR's tenant binding.
func TestIssueCertificate_ForeignTenantRefused(t *testing.T) {
	ca := &mockCA{issueErr: errors.New("must not be called")}
	svc := setupServiceWithCA(t, ca)
	ctx := tenantCtx("tenant-a")

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName: "test.example.com",
		TenantID:   "tenant-b",
	})
	assert.Nil(t, resp)
	requireBindingRefusal(t, err, "issue certificate")
}

// TestIssueCertificate_OwnTenantRecorded proves a tenant-scoped caller may
// issue a certificate for its own tenant, and that the tenant is forwarded
// to the CA so it is recorded against the certificate's serial.
func TestIssueCertificate_OwnTenantRecorded(t *testing.T) {
	ca := &mockCA{issueSerial: "abcdef01"}
	svc := setupServiceWithCA(t, ca)
	ctx := tenantCtx("tenant-a")

	resp, err := svc.IssueCertificate(ctx, &transport.IssueCertificateRequest{
		CommonName: "test.example.com",
		TenantID:   "tenant-a",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "tenant-a", ca.issueTenant)
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

// ========================================================================
// SignCSR authorization
//
// SignCSR's permission, certs:issue, is enforced by the transports before
// dispatch (pkg/api/mcp authz_roleid_test.go drives it on a seeded node). The
// servicer itself must not make a second, role-based decision.
// ========================================================================

// signableCA returns a mock CA that signs every CSR.
func signableCA(t *testing.T) *mockCA {
	t.Helper()
	return &mockCA{signCSRCert: createSelfSignedCert(t), cert: createSelfSignedCert(t)}
}

// testCSRRequest is a CSR request the mock CA accepts.
func testCSRRequest() *transport.SignCSRRequest {
	return &transport.SignCSRRequest{
		CSRPEM:  []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
		Profile: "server",
	}
}

// TestSignCSR_SeededAdminRoleIDSigns is the #1074 regression: an identity
// carrying the Admin role by ID -- what every store-resolved identity carries
// -- was refused ErrCSRSigningDenied because the servicer compared role
// names. It must be signed.
func TestSignCSR_SeededAdminRoleIDSigns(t *testing.T) {
	svc := setupServiceWithCA(t, signableCA(t))
	n, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)
	adminID, err := n.RoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAdmin)
	require.NoError(t, err)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject:  "admin-user",
		TenantID: qrdbsdk.SystemTenantID,
		Roles:    []string{adminID},
	})
	resp, err := svc.SignCSR(ctx, testCSRRequest())
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertificatePEM)
}

// TestSignCSR_RoleNamesAreNotConsulted proves the servicer grants and refuses
// nothing on the strength of role strings: neither a role name that used to
// be admitted nor one that used to be refused changes the outcome, because
// the decision already happened at the transport.
func TestSignCSR_RoleNamesAreNotConsulted(t *testing.T) {
	svc := setupServiceWithCA(t, signableCA(t))

	for _, roles := range [][]string{{"admin"}, {"viewer"}, nil} {
		ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "caller", Roles: roles})
		resp, err := svc.SignCSR(ctx, testCSRRequest())
		require.NoError(t, err, "roles %v", roles)
		assert.NotEmpty(t, resp.CertificatePEM)
	}
}

func TestSignCSR_RBAC_LocalCallAllowed(t *testing.T) {
	signedCert := createSelfSignedCert(t)
	caCert := createSelfSignedCert(t)

	ca := &mockCA{
		signCSRCert: signedCert,
		cert:        caCert,
	}
	svc := setupServiceWithCA(t, ca)

	// No identity in context (nil) - local call should be allowed.
	ctx := context.Background()

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CertificatePEM)
}

// ========================================================================
// SignCSR Attestation Tests
//
// The attestation chain is entirely caller-supplied, so these tests assert the
// gate's only real security property: the chain must terminate at a trust
// anchor the operator configured for the requested format. A chain that is
// merely internally consistent — the classic forged-attestation attack, where
// the attacker mints their own root, intermediate and leaf — must be rejected.
// ========================================================================

// attestationChain is a generated hardware-attestation certificate chain
// shaped like the real ones: a vendor root (the trust anchor), a device
// attestation CA (the YubiKey f9 certificate / TPM manufacturer intermediate),
// and the leaf attestation certificate for the attested key.
type attestationChain struct {
	root     *x509.Certificate
	rootDER  []byte
	interDER []byte
	leafDER  []byte
	// leafKey is the key the leaf certifies, so a test can build a CSR that
	// the key-binding invariant accepts.
	leafKey *ecdsa.PrivateKey
}

// wire returns the chain as it travels on the wire: leaf first, then the
// intermediate. The root is the anchor and is never trusted from the wire.
func (c *attestationChain) wire() [][]byte {
	return [][]byte{c.leafDER, c.interDER}
}

// wireWithRoot returns the chain including the caller-supplied root. A caller
// that ships its own root must not thereby become trusted.
func (c *attestationChain) wireWithRoot() [][]byte {
	return [][]byte{c.leafDER, c.interDER, c.rootDER}
}

// newAttestationChain builds a three-level attestation chain. leafNotBefore and
// leafNotAfter control the validity window of the leaf so expiry can be tested.
//
// The root and intermediate are backdated well beyond any window a caller is
// likely to ask for, so that a leaf placed in the past is judged on its own
// dates rather than tripping over an anchor that had not been issued yet.
func newAttestationChain(t *testing.T, name string, leafNotBefore, leafNotAfter time.Time) *attestationChain {
	t.Helper()

	const anchorBackdate = 30 * 24 * time.Hour

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name + " Attestation Root CA"},
		IsCA:                  true,
		NotBefore:             time.Now().Add(-anchorBackdate),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: name + " Device Attestation CA"},
		IsCA:                  true,
		NotBefore:             time.Now().Add(-anchorBackdate),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	require.NoError(t, err)
	interCert, err := x509.ParseCertificate(interDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: name + " Slot Attestation"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert, &leafKey.PublicKey, interKey)
	require.NoError(t, err)

	return &attestationChain{
		root: rootCert, rootDER: rootDER, interDER: interDER,
		leafDER: leafDER, leafKey: leafKey,
	}
}

// newValidAttestationChain builds a chain whose leaf is currently valid.
func newValidAttestationChain(t *testing.T, name string) *attestationChain {
	t.Helper()
	return newAttestationChain(t, name, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// anchorFormats configures the service with the given per-format trust anchors.
func anchorFormats(t *testing.T, svc *XKMSService, anchors map[string][]*x509.Certificate) {
	t.Helper()
	verifiers := make(map[string]*attestation.Verifier, len(anchors))
	for format, roots := range anchors {
		verifiers[format] = attestation.NewVerifier(roots)
	}
	require.NoError(t, svc.SetAttestationVerifiers(verifiers))
}

// signCSRWithAttestation issues an attestation-gated SignCSR call.
//
// The CSR is built for key, which must be the key the leaf of chain certifies.
// It used to be a placeholder that did not parse, which meant these tests
// exercised chain anchoring and nothing else -- and a CA that only anchors the
// chain will certify a software key presented beside somebody else's genuine
// attestation. Passing a real, matching CSR is what makes them cover the path
// a caller actually takes.
func signCSRWithAttestation(
	t *testing.T,
	svc *XKMSService,
	format string,
	chain [][]byte,
	key *ecdsa.PrivateKey,
) (*transport.SignCSRResponse, error) {
	t.Helper()
	return svc.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM:            csrPEMFor(t, key),
		AttestationFormat: format,
		AttestationChain:  chain,
	})
}

// csrPEMFor builds a PEM CSR signed by key.
func csrPEMFor(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "attested device"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// signingServiceWithAnchor returns a service backed by a working mock CA whose
// only configured attestation anchor is the root of the returned chain.
func signingServiceWithAnchor(t *testing.T, format string) (*XKMSService, *attestationChain) {
	t.Helper()
	svc := setupServiceWithCA(t, &mockCA{
		signCSRCert: createSelfSignedCert(t),
		cert:        createSelfSignedCert(t),
	})
	genuine := newValidAttestationChain(t, "Vendor")
	anchorFormats(t, svc, map[string][]*x509.Certificate{format: {genuine.root}})
	return svc, genuine
}

func TestSignCSR_Attestation_Skipped(t *testing.T) {
	signedCert := createSelfSignedCert(t)
	caCert := createSelfSignedCert(t)

	ca := &mockCA{
		signCSRCert: signedCert,
		cert:        caCert,
	}
	svc := setupServiceWithCA(t, ca)
	ctx := context.Background()

	// Empty AttestationFormat - attestation verification should be skipped.
	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:            []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
		AttestationFormat: "",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CertificatePEM)
}

// TestSignCSR_Attestation_NoTrustAnchors_FailsClosed asserts the gate fails
// closed. With no anchors configured, even a perfectly formed chain is refused:
// a misconfigured server must never silently accept unverifiable attestations.
func TestSignCSR_Attestation_NoTrustAnchors_FailsClosed(t *testing.T) {
	svc := setupServiceWithCA(t, &mockCA{
		signCSRCert: createSelfSignedCert(t),
		cert:        createSelfSignedCert(t),
	})
	chain := newValidAttestationChain(t, "Vendor")

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", chain.wire(), chain.leafKey)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationNotConfigured)
}

// TestSignCSR_Attestation_UnconfiguredFormat_FailsClosed asserts a caller
// cannot pick an attestation format that has no anchors in order to slip past
// the gate.
func TestSignCSR_Attestation_UnconfiguredFormat_FailsClosed(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "tpm2")

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", genuine.wire(), genuine.leafKey)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationFormatNotConfigured)
}

// TestSignCSR_Attestation_AttackerMintedChain_Rejected is the regression test
// for the authentication bypass this gate previously allowed.
//
// The attack: an attacker with no hardware at all generates their own root CA,
// their own device-attestation intermediate, and their own leaf, signing each
// with the next so the chain is fully self-consistent, then submits it as the
// attestation for a software key. The old implementation only checked that
// certs[i] was signed by certs[i+1], which this chain satisfies by
// construction, so the forged attestation passed and the CSR was signed as if
// the key lived in genuine hardware.
//
// The chain must now be rejected because it terminates at the attacker's root
// rather than the configured vendor anchor. Both the leaf-plus-intermediate
// form and the form where the attacker also ships their own root are refused.
func TestSignCSR_Attestation_AttackerMintedChain_Rejected(t *testing.T) {
	svc, _ := signingServiceWithAnchor(t, "yubikey-piv")
	attacker := newValidAttestationChain(t, "Attacker")

	// Sanity check: the forged chain really is internally consistent, so the
	// old "each cert signed by the next" check would have accepted it.
	leaf, err := x509.ParseCertificate(attacker.leafDER)
	require.NoError(t, err)
	intermediate, err := x509.ParseCertificate(attacker.interDER)
	require.NoError(t, err)
	require.NoError(t, leaf.CheckSignatureFrom(intermediate))
	require.NoError(t, intermediate.CheckSignatureFrom(attacker.root))

	t.Run("without attacker root", func(t *testing.T) {
		resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", attacker.wire(), attacker.leafKey)
		assert.Nil(t, resp)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
	})

	t.Run("with attacker root appended", func(t *testing.T) {
		resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", attacker.wireWithRoot(), attacker.leafKey)
		assert.Nil(t, resp)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
	})
}

// TestSignCSR_Attestation_TrustedChain_Accepted asserts genuine hardware still
// works: a chain terminating at the configured anchor is accepted.
func TestSignCSR_Attestation_TrustedChain_Accepted(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", genuine.wire(), genuine.leafKey)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CertificatePEM)
}

// TestSignCSR_Attestation_TrustedChain_WithRootAccepted asserts a client that
// also ships the anchor certificate is accepted, since the anchor is matched
// from the configured trust store rather than from the wire.
func TestSignCSR_Attestation_TrustedChain_WithRootAccepted(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", genuine.wireWithRoot(), genuine.leafKey)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.CertificatePEM)
}

// TestSignCSR_Attestation_UntrustedRoot_Rejected asserts a well-formed chain
// anchored in a different, untrusted vendor root is rejected.
func TestSignCSR_Attestation_UntrustedRoot_Rejected(t *testing.T) {
	svc, _ := signingServiceWithAnchor(t, "yubikey-piv")
	other := newValidAttestationChain(t, "Other Vendor")

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", other.wire(), other.leafKey)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
}

// TestSignCSR_Attestation_CrossFormatAnchorRejected asserts anchors do not leak
// across attestation formats: a TPM manufacturer root cannot validate a chain
// presented as YubiKey PIV attestation.
func TestSignCSR_Attestation_CrossFormatAnchorRejected(t *testing.T) {
	svc := setupServiceWithCA(t, &mockCA{
		signCSRCert: createSelfSignedCert(t),
		cert:        createSelfSignedCert(t),
	})
	tpmChain := newValidAttestationChain(t, "TPM Manufacturer")
	yubiChain := newValidAttestationChain(t, "Yubico")
	anchorFormats(t, svc, map[string][]*x509.Certificate{
		"tpm2":        {tpmChain.root},
		"yubikey-piv": {yubiChain.root},
	})

	// The TPM chain is genuine, but presented under the YubiKey format.
	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", tpmChain.wire(), tpmChain.leafKey)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationVerificationFailed)

	// Presented under its own format it is accepted.
	svc.AllowUnboundAttestationFormats(true) // anchoring test; TPM2 binding is
	// unimplemented and refused by default.
	resp, err = signCSRWithAttestation(t, svc, "tpm2", tpmChain.wire(), tpmChain.leafKey)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// TestSignCSR_Attestation_FormatNormalized asserts format lookup is
// case- and whitespace-insensitive so a client cannot dodge the anchor set
// with a differently cased format string.
func TestSignCSR_Attestation_FormatNormalized(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")

	resp, err := signCSRWithAttestation(t, svc, "  YubiKey-PIV ", genuine.wire(), genuine.leafKey)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestSignCSR_Attestation_EmptyChain(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", [][]byte{}, genuine.leafKey)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
}

func TestSignCSR_Attestation_InvalidCert(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv",
		[][]byte{[]byte("not-valid-der")}, genuine.leafKey)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
}

// TestSignCSR_Attestation_MalformedTrailingCert asserts a malformed
// certificate anywhere in the chain is reported, not just at index 0.
func TestSignCSR_Attestation_MalformedTrailingCert(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv",
		[][]byte{genuine.leafDER, {0x30, 0x82, 0xff, 0xff}}, genuine.leafKey)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
}

// createAttestationChain generates a 2-cert chain: leaf signed by root.
// Returns (leafDER, rootDER) suitable for AttestationChain.
func createAttestationChain(t *testing.T) ([]byte, []byte, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate root CA key and self-signed cert.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(200),
		Subject:               pkix.Name{CommonName: "Attestation Root CA"},
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	// Generate leaf key and cert signed by root.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(201),
		Subject:      pkix.Name{CommonName: "Attestation Leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	return leafDER, rootDER, leafKey
}

// TestSignCSR_Attestation_TwoLevelChain covers the minimal leaf-plus-root
// shape: accepted when the root is the configured anchor, rejected when it is
// merely shipped by the caller.
func TestSignCSR_Attestation_TwoLevelChain(t *testing.T) {
	leafDER, rootDER, leafKey := createAttestationChain(t)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	t.Run("anchored", func(t *testing.T) {
		svc := setupServiceWithCA(t, &mockCA{
			signCSRCert: createSelfSignedCert(t),
			cert:        createSelfSignedCert(t),
		})
		anchorFormats(t, svc, map[string][]*x509.Certificate{"yubikey-piv": {root}})

		resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", [][]byte{leafDER, rootDER}, leafKey)
		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("caller supplied root only", func(t *testing.T) {
		svc, _ := signingServiceWithAnchor(t, "yubikey-piv")

		resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", [][]byte{leafDER, rootDER}, leafKey)
		assert.Nil(t, resp)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
	})
}

// TestSignCSR_Attestation_SingleSelfSignedCert_Rejected asserts a lone
// self-signed certificate is not an attestation. It is internally consistent by
// definition, so only the anchor check can reject it.
func TestSignCSR_Attestation_SingleSelfSignedCert_Rejected(t *testing.T) {
	svc, genuine := signingServiceWithAnchor(t, "yubikey-piv")
	selfSigned := createSelfSignedCert(t)

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", [][]byte{selfSigned.Raw}, genuine.leafKey)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
}

// TestSignCSR_Attestation_SingleAnchorCert_Accepted asserts the degenerate but
// legitimate case where the presented certificate is itself the anchor.
func TestSignCSR_Attestation_SingleAnchorCert_Accepted(t *testing.T) {
	svc := setupServiceWithCA(t, &mockCA{
		signCSRCert: createSelfSignedCert(t),
		cert:        createSelfSignedCert(t),
	})
	genuine := newValidAttestationChain(t, "Vendor")
	anchorFormats(t, svc, map[string][]*x509.Certificate{"tpm2": {genuine.root}})

	svc.AllowUnboundAttestationFormats(true) // anchoring test; TPM2 binding is
	// unimplemented and refused by default.
	resp, err := signCSRWithAttestation(t, svc, "tpm2", [][]byte{genuine.rootDER}, genuine.leafKey)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

func TestSignCSR_Attestation_BrokenChain(t *testing.T) {
	svc, _ := signingServiceWithAnchor(t, "yubikey-piv")

	// Create two independent self-signed certs (leaf is NOT signed by root).
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf1Template := &x509.Certificate{
		SerialNumber: big.NewInt(300),
		Subject:      pkix.Name{CommonName: "Unrelated Leaf"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leaf1DER, err := x509.CreateCertificate(rand.Reader, leaf1Template, leaf1Template, &key1.PublicKey, key1)
	require.NoError(t, err)

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	root2Template := &x509.Certificate{
		SerialNumber:          big.NewInt(301),
		Subject:               pkix.Name{CommonName: "Unrelated Root"},
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	root2DER, err := x509.CreateCertificate(rand.Reader, root2Template, root2Template, &key2.PublicKey, key2)
	require.NoError(t, err)

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", [][]byte{leaf1DER, root2DER}, key1)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
}

// TestSignCSR_Attestation_ExpiredLeaf_Rejected asserts an expired attestation
// leaf is rejected even though it chains to the configured anchor.
func TestSignCSR_Attestation_ExpiredLeaf_Rejected(t *testing.T) {
	svc := setupServiceWithCA(t, &mockCA{
		signCSRCert: createSelfSignedCert(t),
		cert:        createSelfSignedCert(t),
	})
	expired := newAttestationChain(t, "Vendor",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	anchorFormats(t, svc, map[string][]*x509.Certificate{"yubikey-piv": {expired.root}})

	resp, err := signCSRWithAttestation(t, svc, "yubikey-piv", expired.wire(), expired.leafKey)
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAttestationVerificationFailed)
}

// ========================================================================
// SetAttestationVerifiers
// ========================================================================

// TestSetAttestationVerifiers_RejectsUnusableVerifiers asserts a verifier that
// cannot enforce anchoring is refused at wiring time rather than accepted and
// then silently permitting everything.
func TestSetAttestationVerifiers_RejectsUnusableVerifiers(t *testing.T) {
	svc := setupServiceWithCA(t, &mockCA{})
	genuine := newValidAttestationChain(t, "Vendor")

	tests := []struct {
		name      string
		verifiers map[string]*attestation.Verifier
	}{
		{
			name:      "nil verifier",
			verifiers: map[string]*attestation.Verifier{"tpm2": nil},
		},
		{
			name:      "verifier without trust anchors",
			verifiers: map[string]*attestation.Verifier{"tpm2": attestation.NewVerifier(nil)},
		},
		{
			name:      "empty format",
			verifiers: map[string]*attestation.Verifier{"   ": attestation.NewVerifier([]*x509.Certificate{genuine.root})},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.SetAttestationVerifiers(tc.verifiers)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrAttestationVerifierInvalid)
			assert.Empty(t, svc.AttestationFormats())
		})
	}
}

// TestSetAttestationVerifiers_NormalizesAndReplaces asserts formats are stored
// normalized and that a later call replaces the previous anchor set.
func TestSetAttestationVerifiers_NormalizesAndReplaces(t *testing.T) {
	svc := setupServiceWithCA(t, &mockCA{})
	genuine := newValidAttestationChain(t, "Vendor")

	require.NoError(t, svc.SetAttestationVerifiers(map[string]*attestation.Verifier{
		" TPM2 ": attestation.NewVerifier([]*x509.Certificate{genuine.root}),
	}))
	assert.Equal(t, []string{"tpm2"}, svc.AttestationFormats())

	_, ok := svc.attestationVerifierFor("tpm2")
	assert.True(t, ok)

	require.NoError(t, svc.SetAttestationVerifiers(nil))
	assert.Empty(t, svc.AttestationFormats())
	_, ok = svc.attestationVerifierFor("tpm2")
	assert.False(t, ok)
}

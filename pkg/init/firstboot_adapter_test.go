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

package initialize

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// recordingCA wraps the ceremony mockCA and records the request and options
// the adapter passes down. The mock deliberately ignores SignOptions when
// self-signing, so the adapter's contract — WHAT it asks the CA for — has to
// be asserted on the recorded values, not on the mock's output.
type recordingCA struct {
	*mockCA

	lastIssueReq *ca.CertificateRequest
	lastSignOpts *ca.SignOptions
	issueErr     error
	signErr      error
}

func (r *recordingCA) IssueCertificate(ctx context.Context, req *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	r.lastIssueReq = req
	if r.issueErr != nil {
		return nil, r.issueErr
	}
	return r.mockCA.IssueCertificate(ctx, req)
}

func (r *recordingCA) IssueCertificateForKey(ctx context.Context, req *ca.CertificateRequest, publicKey crypto.PublicKey) (*ca.IssuedCertificate, error) {
	r.lastIssueReq = req
	if r.issueErr != nil {
		return nil, r.issueErr
	}
	return r.mockCA.IssueCertificateForKey(ctx, req, publicKey)
}

func (r *recordingCA) SignCSR(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
	r.lastSignOpts = opts
	if r.signErr != nil {
		return nil, r.signErr
	}
	return r.mockCA.SignCSR(ctx, csrPEM, opts)
}

func newRecordingCA(t *testing.T) *recordingCA {
	t.Helper()
	return &recordingCA{mockCA: newMockCA(t)}
}

// adminCSR builds a PEM-encoded CSR the way a Path B admin would: their own
// key, their own subject.
func adminCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestGenerateAdminCert_PathA proves the generate-and-distribute seam: both
// PEM blobs come back, the key is generated OUTSIDE the CA (the CA sees only
// a CSR — the admin's credential never enters platform key custody), the
// CSR's subject encodes tenant (OU) and admin (CN) per the qrdb contract,
// the requested certificate shape comes from the canonical client profile,
// and the SPIFFE identity carries the admin's own tenant — not the system
// tenant the ceremony path pins.
func TestGenerateAdminCert_PathA(t *testing.T) {
	rec := newRecordingCA(t)
	adapter := NewCAAdapter(rec, "example.org")

	certPEM, keyPEM, err := adapter.GenerateAdminCert(context.Background(), "tenant-42", "admin")
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM, "Path A must return the certificate PEM")
	assert.NotEmpty(t, keyPEM, "Path A must return the private key PEM (generate-and-distribute)")

	// The key must be a parseable PKCS#8 private key whose public half matches
	// the issued certificate — the pair the admin actually authenticates with.
	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock, "the admin key must be PEM")
	require.Equal(t, "PRIVATE KEY", keyBlock.Type)
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	ecKey, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok, "the admin key is ECDSA")

	certBlock, _ := pem.Decode(certPEM)
	require.NotNil(t, certBlock)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)
	assert.True(t, ecKey.PublicKey.Equal(cert.PublicKey),
		"the certificate must certify the key that was generated for the admin")
	assert.Equal(t, "admin", cert.Subject.CommonName)
	require.Len(t, cert.Subject.OrganizationalUnit, 1)
	assert.Equal(t, "tenant-42", cert.Subject.OrganizationalUnit[0],
		"the seam contract says tenantID identifies the OU")

	// The CA must have been asked to SIGN, never to generate or hold the key,
	// with the canonical client profile's shape and the admin's own tenant.
	assert.Nil(t, rec.lastIssueReq, "Path A must not route through IssueCertificate")
	opts := rec.lastSignOpts
	require.NotNil(t, opts, "Path A signs a locally built CSR")
	profile := ca.NewClientProfile()
	assert.Equal(t, profile.KeyUsage(), opts.KeyUsage)
	assert.Equal(t, profile.ExtKeyUsage(), opts.ExtKeyUsage)
	assert.Equal(t, "example.org", opts.SPIFFETrustDomain)
	assert.Equal(t, "tenant-42", opts.TenantID,
		"the admin cert must carry the admin's tenant, not the system tenant")
	assert.Equal(t, "admin", opts.SPIFFEName)
}

// TestGenerateAdminCert_EmptyTenantFallsBackToSystem pins the fallback: an
// admin cert with no tenant is a control-plane identity and lands in the
// system tenant, matching the ceremony SO certificates.
func TestGenerateAdminCert_EmptyTenantFallsBackToSystem(t *testing.T) {
	rec := newRecordingCA(t)
	adapter := NewCAAdapter(rec, "example.org")

	_, _, err := adapter.GenerateAdminCert(context.Background(), "", "admin")
	require.NoError(t, err)

	require.NotNil(t, rec.lastSignOpts)
	assert.Equal(t, "system", rec.lastSignOpts.TenantID)
}

// TestGenerateAdminCert_PropagatesSignError proves a CA failure surfaces
// instead of returning empty blobs as success.
func TestGenerateAdminCert_PropagatesSignError(t *testing.T) {
	rec := newRecordingCA(t)
	rec.signErr = errors.New("keystore sealed")
	adapter := NewCAAdapter(rec, "xkms.example.com")

	certPEM, keyPEM, err := adapter.GenerateAdminCert(context.Background(), "t", "admin")

	require.Error(t, err)
	assert.True(t, errors.Is(err, rec.signErr))
	assert.Nil(t, certPEM)
	assert.Nil(t, keyPEM)
}

// TestSignAdminCSR_PathB proves the CSR-sign seam: the result is a PEM
// certificate over the CSR's own subject and key (the private key never
// leaves the admin), the requested shape comes from the canonical client
// profile, and the SPIFFE identity carries the admin's tenant and name.
func TestSignAdminCSR_PathB(t *testing.T) {
	rec := newRecordingCA(t)
	adapter := NewCAAdapter(rec, "example.org")

	certPEM, err := adapter.SignAdminCSR(context.Background(), "tenant-7", "ops-admin", adminCSR(t, "ops-admin"))
	require.NoError(t, err)

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "SignAdminCSR must return PEM")
	require.Equal(t, "CERTIFICATE", block.Type)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "ops-admin", cert.Subject.CommonName,
		"Path B keeps the CSR's subject; the CA must not rewrite it")

	opts := rec.lastSignOpts
	require.NotNil(t, opts)
	profile := ca.NewClientProfile()
	assert.Equal(t, profile.KeyUsage(), opts.KeyUsage)
	assert.Equal(t, profile.ExtKeyUsage(), opts.ExtKeyUsage)
	assert.Equal(t, "example.org", opts.SPIFFETrustDomain)
	assert.Equal(t, "tenant-7", opts.TenantID, "the admin's own tenant, not system")
	assert.Equal(t, "ops-admin", opts.SPIFFEName)
}

// TestSignAdminCSR_NoTrustDomainOmitsSPIFFE pins that, with no trust domain
// configured, no SPIFFE fields are requested; the admin's tenant is still
// requested, as the subject's first organizational unit.
func TestCAAdapter_LoginCertificatesRequireATrustDomain(t *testing.T) {
	rec := newRecordingCA(t)
	adapter := NewCAAdapter(rec, "")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = adapter.SignAdminCSR(context.Background(), "tenant-7", "ops-admin", adminCSR(t, "ops-admin"))
	require.ErrorIs(t, err, ErrNoSPIFFETrustDomain)
	_, _, err = adapter.GenerateAdminCert(context.Background(), "tenant-7", "ops-admin")
	require.ErrorIs(t, err, ErrNoSPIFFETrustDomain)
	_, err = adapter.IssueCertificate(context.Background(), &qrdbsdk.IssueCertRequest{CommonName: "so-officer", PublicKey: key.Public()})
	require.ErrorIs(t, err, ErrNoSPIFFETrustDomain)
	assert.Nil(t, rec.lastSignOpts, "nothing reached the CA")
	assert.Nil(t, rec.lastIssueReq, "nothing reached the CA")
}

// TestSignAdminCSR_NoTenantIssuesForTheSystemTenant pins that a bootstrap
// admin named without a tenant is the system tenant's.
func TestSignAdminCSR_NoTenantIssuesForTheSystemTenant(t *testing.T) {
	rec := newRecordingCA(t)
	adapter := NewCAAdapter(rec, "xkms.example.com")

	_, err := adapter.SignAdminCSR(context.Background(), "", "ops-admin", adminCSR(t, "ops-admin"))
	require.NoError(t, err)

	require.NotNil(t, rec.lastSignOpts)
	assert.Equal(t, qrdbsdk.SystemTenantID, rec.lastSignOpts.TenantID)
}

// TestSignAdminCSR_PropagatesSignError proves a signing failure surfaces.
func TestSignAdminCSR_PropagatesSignError(t *testing.T) {
	rec := newRecordingCA(t)
	rec.signErr = errors.New("csr rejected")
	adapter := NewCAAdapter(rec, "xkms.example.com")

	certPEM, err := adapter.SignAdminCSR(context.Background(), "t", "a", adminCSR(t, "a"))

	require.Error(t, err)
	assert.True(t, errors.Is(err, rec.signErr))
	assert.Nil(t, certPEM)
}

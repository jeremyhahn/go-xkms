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
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mockCA implements ca.TrustedCA with a real self-signed ECDSA root cert.
// ---------------------------------------------------------------------------

type mockCA struct {
	cert       *x509.Certificate
	certPEM    []byte
	privateKey *ecdsa.PrivateKey
}

// Compile-time interface check.
var _ ca.TrustedCA = (*mockCA)(nil)

func newMockCA(t *testing.T) *mockCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &mockCA{
		cert:       cert,
		certPEM:    certPEM,
		privateKey: key,
	}
}

// --- crypto.Signer ---

func (m *mockCA) Public() crypto.PublicKey { return &m.privateKey.PublicKey }

func (m *mockCA) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(randReader, m.privateKey, digest)
}

// --- Lifecycle ---

func (m *mockCA) Init(_ context.Context) error { return nil }
func (m *mockCA) Load(_ context.Context) error { return nil }
func (m *mockCA) IsInitialized() bool          { return true }
func (m *mockCA) Identity() string             { return m.cert.Subject.CommonName }
func (m *mockCA) Config() *ca.Identity {
	return &ca.Identity{Subject: ca.Subject{CommonName: m.cert.Subject.CommonName}}
}
func (m *mockCA) KeyStore() xkms.Backend         { return nil }
func (m *mockCA) CertStore() certstore.CertStore { return nil }

// --- Certificate accessors ---

func (m *mockCA) CACertificate() (*x509.Certificate, error) { return m.cert, nil }

func (m *mockCA) CABundle() ([]byte, error) { return m.certPEM, nil }

// --- CSR operations ---

func (m *mockCA) CreateCSR(_ context.Context, _ *ca.CertificateRequest) ([]byte, error) {
	return nil, nil
}

// SignCSR signs as the real CA does under go-qrdb's holder contract: a raw
// subject in the options is the whole Subject and the CSR contributes only
// its key; without one the CSR's subject is copied.
func (m *mockCA) ReserveSerial(_ context.Context) (*big.Int, error) {
	return big.NewInt(time.Now().UnixNano()), nil
}

func (m *mockCA) SignCSR(_ context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("mockCA: invalid PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	serial := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if opts != nil && opts.RawSubject != nil {
		template.RawSubject = opts.RawSubject
		template.URIs = opts.RawSubjectURIs
	}
	// Like the TrustedCA, requested usages override the defaults: go-qrdb's
	// ceremony refuses a holder certificate whose usages differ from the ones
	// it asked for.
	if opts != nil && opts.KeyUsage != 0 {
		template.KeyUsage = opts.KeyUsage
	}
	if opts != nil && opts.ExtKeyUsage != nil {
		template.ExtKeyUsage = opts.ExtKeyUsage
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, m.cert, csr.PublicKey, m.privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func (m *mockCA) IssueCertificate(ctx context.Context, req *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	issued, err := m.IssueCertificateForKey(ctx, req, key.Public())
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	issued.PrivateKey = key
	issued.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return issued, nil
}

func (m *mockCA) IssueCertificateForKey(_ context.Context, req *ca.CertificateRequest, publicKey crypto.PublicKey) (*ca.IssuedCertificate, error) {
	if publicKey == nil {
		return nil, ca.ErrPublicKeyRequired
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: req.Subject.CommonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     req.KeyUsage,
		ExtKeyUsage:  req.ExtKeyUsage,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, m.cert, publicKey, m.privateKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return &ca.IssuedCertificate{
		Certificate:    cert,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
	}, nil
}

func (m *mockCA) IssueCertificateWithProfile(ctx context.Context, req *ca.CertificateRequest, _ string) (*ca.IssuedCertificate, error) {
	return m.IssueCertificate(ctx, req)
}

// --- Trust chain / revocation ---

func (m *mockCA) Verify(_ *x509.Certificate, _ ...crypto.Signer) ([][]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCA) Revoke(_ context.Context, _ *big.Int, _ int) error { return nil }
func (m *mockCA) GenerateCRL(_ context.Context) ([]byte, error)     { return nil, nil }
func (m *mockCA) CRL(_ context.Context) ([]byte, error)             { return nil, nil }
func (m *mockCA) IsRevoked(_ *big.Int) (bool, error)                { return false, nil }

// --- TLS ---

func (m *mockCA) TLSCertificate(_ context.Context, _ *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *mockCA) TLSConfig(_ context.Context, _ *types.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *mockCA) ServerTLSConfig(_ context.Context, _ *types.KeyAttributes, _ bool) (*tls.Config, error) {
	return nil, nil
}
func (m *mockCA) ClientTLSConfig(_ context.Context, _ *types.KeyAttributes, _ string) (*tls.Config, error) {
	return nil, nil
}

// --- Trust pool builders ---

func (m *mockCA) CABundleCertPool() (*x509.CertPool, error)                       { return nil, nil }
func (m *mockCA) TrustedRootCertPool(_ *x509.Certificate) (*x509.CertPool, error) { return nil, nil }
func (m *mockCA) TrustedIntermediateCertPool(_ *x509.Certificate) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCA) OSTrustStore() (*x509.CertPool, error) { return nil, nil }
func (m *mockCA) Blob(_ []byte) ([]byte, error)         { return nil, nil }
func (m *mockCA) CABundleFiltered(_ types.StoreType, _ x509.PublicKeyAlgorithm) ([]byte, error) {
	return m.certPEM, nil
}

// --- Compile-shim methods (added for TrustedCA interface growth) ---
func (m *mockCA) CAConfig() ca.CAConfig                                           { return ca.CAConfig{} }
func (m *mockCA) CAKeyAttributes(_ types.StoreType) (*types.KeyAttributes, error) { return nil, nil }
func (m *mockCA) CASigner(_ context.Context, _ types.StoreType, _ x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	return nil, nil
}
func (m *mockCA) Certificate(_ context.Context, _ *types.KeyAttributes) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCA) CertificatePEM(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (m *mockCA) CrossSignedPEM(_ *types.KeyAttributes) ([]byte, error)      { return nil, nil }
func (m *mockCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm               { return 0 }
func (m *mockCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm         { return 0 }
func (m *mockCA) DefaultValidityPeriod() int                                 { return 0 }
func (m *mockCA) Exists(_ context.Context, _ string, _ x509.PublicKeyAlgorithm) (bool, error) {
	return false, nil
}
func (m *mockCA) Hash() crypto.Hash { return 0 }
func (m *mockCA) ImportAttestation(_ context.Context, _ *types.KeyAttributes, _ string, _ []byte) error {
	return nil
}
func (m *mockCA) ImportAttestationEventLog(_ context.Context, _ *types.KeyAttributes, _ []byte) error {
	return nil
}
func (m *mockCA) ImportAttestationKeyCertificate(_ context.Context, _ *types.KeyAttributes, _ []byte) error {
	return nil
}
func (m *mockCA) ImportAttestationPCRs(_ context.Context, _ *types.KeyAttributes, _ []byte) error {
	return nil
}
func (m *mockCA) ImportAttestationQuote(_ context.Context, _ *types.KeyAttributes, _ []byte) error {
	return nil
}
func (m *mockCA) ImportBlob(_, _ []byte) error                                     { return nil }
func (m *mockCA) ImportCertificate(_ context.Context, _ *x509.Certificate) error   { return nil }
func (m *mockCA) ImportCertificatePEM(_ context.Context, _ string, _ []byte) error { return nil }
func (m *mockCA) ImportDistributionCRLs(_ *x509.Certificate) error                 { return nil }
func (m *mockCA) ImportIssuingCAs(_ context.Context, _ *x509.Certificate) error    { return nil }
func (m *mockCA) ImportLocalAttestation(_ context.Context, _ *types.KeyAttributes, _ *tpm2.Quote) error {
	return nil
}
func (m *mockCA) ImportXSignedCertificate(_ string, _ *x509.Certificate) error  { return nil }
func (m *mockCA) IsAutoImportingIssuerCAs() bool                                { return false }
func (m *mockCA) Issued(_ context.Context, _ string) (bool, error)              { return false, nil }
func (m *mockCA) IssuingIdentity() ca.Identity                                  { return ca.Identity{} }
func (m *mockCA) PEM(_ context.Context, _ *types.KeyAttributes) ([]byte, error) { return nil, nil }
func (m *mockCA) ParseBundle(_ []byte) ([]*x509.Certificate, error)             { return nil, nil }
func (m *mockCA) PrivateKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (m *mockCA) PubKey(_ context.Context, _ *types.KeyAttributes) (crypto.PublicKey, error) {
	return nil, nil
}
func (m *mockCA) RevokeCert(_ context.Context, _ *x509.Certificate, _ ca.RevokeOptions) error {
	return nil
}
func (m *mockCA) RootCertificate(_ *x509.Certificate) (*x509.Certificate, error) { return nil, nil }
func (m *mockCA) SignedBlob(_ context.Context, _ []byte) ([]byte, error)         { return nil, nil }
func (m *mockCA) Signer(_ context.Context) (crypto.Signer, error)                { return nil, nil }
func (m *mockCA) TLSBundle(_ context.Context, _ *types.KeyAttributes) ([]byte, error) {
	return nil, nil
}
func (m *mockCA) TLSBundleWithCrossSigner(_ context.Context, _ *types.KeyAttributes, _ crypto.Signer) ([]byte, error) {
	return nil, nil
}
func (m *mockCA) TLSConfigWithXSigner(_ context.Context, _ *types.KeyAttributes, _ crypto.Signer) (*tls.Config, error) {
	return nil, nil
}
func (m *mockCA) TrustedIntermediate() (*x509.Certificate, error) { return nil, nil }
func (m *mockCA) TrustedIntermediateCertPoolWithXSigner(_ *x509.Certificate, _ crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCA) TrustedRoot() (*x509.Certificate, error) { return nil, nil }
func (m *mockCA) TrustedRootCertPoolWithXSigner(_ *x509.Certificate, _ crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCA) VerifyAttestationEventLog(_ *types.KeyAttributes, _ []byte) error { return nil }
func (m *mockCA) VerifyAttestationPCRs(_ *types.KeyAttributes, _ []byte) error     { return nil }
func (m *mockCA) VerifyAttestationQuote(_ *types.KeyAttributes, _ []byte) error    { return nil }
func (m *mockCA) XSignedCertificate(_ string, _ *types.KeyAttributes) (*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCA) XSignedIntermediateCertificates(_ string, _ *x509.Certificate) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *mockCA) XSignedRootCertificate(_ string, _ *x509.Certificate) (*x509.Certificate, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// errorCA wraps mockCA but fails CABundle with caBundleErr when it is set.
// ---------------------------------------------------------------------------

type errorCA struct {
	*mockCA
	caBundleErr error
}

func (e *errorCA) CABundle() ([]byte, error) {
	if e.caBundleErr != nil {
		return nil, e.caBundleErr
	}
	return e.mockCA.CABundle()
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func generateTestCSR(t *testing.T, cn string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, key
}

func (m *mockCA) VerifyTCG_CSR_IDevIDBytes(_ []byte, _ x509.SignatureAlgorithm) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}

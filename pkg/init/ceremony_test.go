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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
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
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, m.cert, csr.PublicKey, m.privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func (m *mockCA) IssueCertificate(_ context.Context, req *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.Subject.CommonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     req.KeyUsage,
		ExtKeyUsage:  req.ExtKeyUsage,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, m.cert, &key.PublicKey, m.privateKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return &ca.IssuedCertificate{
		Certificate:    cert,
		CertificatePEM: certPEM,
		PrivateKey:     key,
		PrivateKeyPEM:  keyPEM,
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
// errorCA wraps mockCA but returns errors for selected operations.
// ---------------------------------------------------------------------------

type errorCA struct {
	*mockCA
	caCertErr    error
	caBundleErr  error
	signCSRErr   error
	issueCertErr error
}

func (e *errorCA) CACertificate() (*x509.Certificate, error) {
	if e.caCertErr != nil {
		return nil, e.caCertErr
	}
	return e.mockCA.CACertificate()
}

func (e *errorCA) CABundle() ([]byte, error) {
	if e.caBundleErr != nil {
		return nil, e.caBundleErr
	}
	return e.mockCA.CABundle()
}

func (e *errorCA) SignCSR(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
	if e.signCSRErr != nil {
		return nil, e.signCSRErr
	}
	return e.mockCA.SignCSR(ctx, csrPEM, opts)
}

func (e *errorCA) IssueCertificate(ctx context.Context, req *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	if e.issueCertErr != nil {
		return nil, e.issueCertErr
	}
	return e.mockCA.IssueCertificate(ctx, req)
}

func (e *errorCA) IssueCertificateWithProfile(ctx context.Context, req *ca.CertificateRequest, profile string) (*ca.IssuedCertificate, error) {
	if e.issueCertErr != nil {
		return nil, e.issueCertErr
	}
	return e.mockCA.IssueCertificateWithProfile(ctx, req, profile)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func testBarrier(t *testing.T) *seal.Barrier {
	t.Helper()
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(testLogger(), base, seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	return barrier
}

func testCredService(t *testing.T) *credentials.Service {
	t.Helper()
	svc, err := credentials.New(
		&credentials.Config{Strategy: credentials.StrategyManual},
		nil, nil, testLogger(),
	)
	require.NoError(t, err)
	return svc
}

func validConfig() *CeremonyConfig {
	return &CeremonyConfig{
		SOPin:                  "test-so-pin",
		UserPin:                "test-user-pin",
		CredentialSealStrategy: credentials.StrategyManual,
		Hostname:               "localhost",
	}
}

func validMofNConfig(t *testing.T, threshold, numOfficers int) (*CeremonyConfig, []*ecdsa.PrivateKey) {
	t.Helper()
	officers := make([]OfficerConfig, numOfficers)
	keys := make([]*ecdsa.PrivateKey, numOfficers)
	for i := 0; i < numOfficers; i++ {
		csrPEM, key := generateTestCSR(t, "officer-"+string(rune('A'+i)))
		officers[i] = OfficerConfig{
			Username: "officer-" + string(rune('A'+i)),
			CSRPEM:   csrPEM,
		}
		keys[i] = key
	}
	return &CeremonyConfig{
		SOPin:                  "test-so-pin",
		UserPin:                "test-user-pin",
		CredentialSealStrategy: credentials.StrategyManual,
		Threshold:              threshold,
		Officers:               officers,
		Hostname:               "localhost",
	}, keys
}

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

func generateTestRSACSR(t *testing.T, cn string) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, key
}

func generateTestEd25519CSR(t *testing.T, cn string) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	require.NoError(t, err)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, priv
}

// initServiceMofN creates and initializes a ceremony service in M-of-N mode.
// Returns the service, the officer private keys, and the mock CA.
func initServiceMofN(t *testing.T, threshold, numOfficers int) (*CeremonyService, []*ecdsa.PrivateKey, *mockCA) {
	t.Helper()
	cfg, keys := validMofNConfig(t, threshold, numOfficers)
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	_, err = svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)

	return svc, keys, mockCA
}

// claimOfficerCertThumbprint runs the certificate claim handshake for username
// and returns the thumbprint of the issued certificate — exactly the value the
// officer's mTLS peer certificate hashes to on the next request.
func claimOfficerCertThumbprint(t *testing.T, svc *CeremonyService, username string, key *ecdsa.PrivateKey) string {
	t.Helper()
	ctx := context.Background()

	challenge, err := svc.BeginClaimCert(ctx, username)
	require.NoError(t, err)

	hash := sha256.Sum256(challenge.Nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	require.NoError(t, err)

	result, err := svc.CompleteClaimCert(ctx, username, hex.EncodeToString(challenge.Nonce), sig)
	require.NoError(t, err)

	block, _ := pem.Decode(result.CertPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	return CertThumbprint(cert.Raw)
}

// claimOfficerShare runs the two-round-trip officer share claim, signing the
// challenge nonce with key and presenting thumbprint as the caller certificate
// thumbprint the transport would have derived from the TLS handshake.
func claimOfficerShare(t *testing.T, svc *CeremonyService, username string, key *ecdsa.PrivateKey, thumbprint string) (*ShareClaimResult, error) {
	t.Helper()
	ctx := context.Background()

	challenge, err := svc.BeginClaimShare(ctx, username, thumbprint)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(challenge.Nonce)
	sig, signErr := ecdsa.SignASN1(rand.Reader, key, hash[:])
	require.NoError(t, signErr)

	return svc.CompleteClaimShare(ctx, username, hex.EncodeToString(challenge.Nonce), sig, thumbprint)
}

// officerUsernames is the fixed username order validMofNConfig produces.
var officerUsernames = []string{"officer-A", "officer-B", "officer-C"}

// initServiceSingleAdmin creates and initializes a ceremony service in
// single-admin mode. Returns the service and the mock CA.
func initServiceSingleAdmin(t *testing.T) (*CeremonyService, *mockCA) {
	t.Helper()
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	_, err = svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)

	return svc, mockCA
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNewCeremonyService_Success(t *testing.T) {
	svc, err := NewCeremonyService(
		validConfig(),
		testBarrier(t),
		testCredService(t),
		testLogger(),
	)
	require.NoError(t, err)
	assert.NotNil(t, svc)
	assert.Equal(t, StateAwaitingInit, svc.State())
}

func TestNewCeremonyService_NilConfig(t *testing.T) {
	_, err := NewCeremonyService(nil, testBarrier(t), testCredService(t), testLogger())
	assert.ErrorIs(t, err, ErrNilConfig)
}

func TestNewCeremonyService_NilBarrier(t *testing.T) {
	_, err := NewCeremonyService(validConfig(), nil, testCredService(t), testLogger())
	assert.ErrorIs(t, err, ErrNilBarrier)
}

func TestNewCeremonyService_NilLogger(t *testing.T) {
	_, err := NewCeremonyService(validConfig(), testBarrier(t), testCredService(t), nil)
	assert.ErrorIs(t, err, ErrNilLogger)
}

func TestNewCeremonyService_EmptySOPin(t *testing.T) {
	cfg := validConfig()
	cfg.SOPin = ""
	_, err := NewCeremonyService(cfg, testBarrier(t), testCredService(t), testLogger())
	assert.ErrorIs(t, err, ErrInvalidSOPIN)
}

func TestNewCeremonyService_EmptyUserPin(t *testing.T) {
	cfg := validConfig()
	cfg.UserPin = ""
	_, err := NewCeremonyService(cfg, testBarrier(t), testCredService(t), testLogger())
	assert.ErrorIs(t, err, ErrInvalidUserPIN)
}

func TestNewCeremonyService_ThresholdWithNoOfficers(t *testing.T) {
	cfg := validConfig()
	cfg.Threshold = 2
	cfg.Officers = nil
	_, err := NewCeremonyService(cfg, testBarrier(t), testCredService(t), testLogger())
	assert.ErrorIs(t, err, ErrNoOfficers)
}

func TestNewCeremonyService_ThresholdExceedsOfficers(t *testing.T) {
	csr1, _ := generateTestCSR(t, "officer-A")
	csr2, _ := generateTestCSR(t, "officer-B")
	cfg := validConfig()
	cfg.Threshold = 3
	cfg.Officers = []OfficerConfig{
		{Username: "officer-A", CSRPEM: csr1},
		{Username: "officer-B", CSRPEM: csr2},
	}
	_, err := NewCeremonyService(cfg, testBarrier(t), testCredService(t), testLogger())
	assert.ErrorIs(t, err, ErrInvalidThreshold)
}

func TestNewCeremonyService_DuplicateOfficerUsernames(t *testing.T) {
	csr1, _ := generateTestCSR(t, "dup")
	csr2, _ := generateTestCSR(t, "dup")
	cfg := validConfig()
	cfg.Threshold = 2
	cfg.Officers = []OfficerConfig{
		{Username: "dup", CSRPEM: csr1},
		{Username: "dup", CSRPEM: csr2},
	}
	_, err := NewCeremonyService(cfg, testBarrier(t), testCredService(t), testLogger())
	assert.ErrorIs(t, err, ErrDuplicateUsername)
}

func TestNewCeremonyService_NilCredServiceReturnsError(t *testing.T) {
	// go-qrdb ceremony requires a non-nil credential service.
	_, err := NewCeremonyService(validConfig(), testBarrier(t), nil, testLogger())
	assert.ErrorIs(t, err, ErrNilCredentialService)
}

// ---------------------------------------------------------------------------
// Initialize - single admin
// ---------------------------------------------------------------------------

func TestInitialize_SingleAdmin_Success(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	result, err := svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)

	assert.Equal(t, StateOperational, result.State)
	assert.Equal(t, StateOperational, svc.State())
	assert.NotEmpty(t, result.SPKIPin)
	assert.NotEmpty(t, result.CACertPEM)
	assert.Equal(t, 0, result.ShareCount)
}

func TestInitialize_AlreadyInitialized(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	_, err = svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), mockCA)
	assert.ErrorIs(t, err, ErrAlreadyInitialized)
}

// ---------------------------------------------------------------------------
// Initialize - M-of-N
// ---------------------------------------------------------------------------

func TestInitialize_MofN_Success(t *testing.T) {
	cfg, _ := validMofNConfig(t, 2, 3)
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	result, err := svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)

	assert.Equal(t, StateEnrolling, result.State)
	assert.Equal(t, StateEnrolling, svc.State())
	assert.NotEmpty(t, result.SPKIPin)
	assert.NotEmpty(t, result.CACertPEM)
	assert.Equal(t, 3, result.ShareCount)
}

func TestInitialize_MofN_SharesSealed(t *testing.T) {
	cfg, keys := validMofNConfig(t, 2, 3)
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	result, err := svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)

	// Shares are now stored internally in go-qrdb's memguard share store.
	// Verify shares were created by checking the result share count.
	assert.Equal(t, len(cfg.Officers), result.ShareCount)

	// Verify shares can be claimed via the public API by the enrolled officers.
	for i, officer := range cfg.Officers {
		thumb := claimOfficerCertThumbprint(t, svc, officer.Username, keys[i])
		claimed, claimErr := claimOfficerShare(t, svc, officer.Username, keys[i], thumb)
		require.NoError(t, claimErr)
		assert.NotEmpty(t, claimed.ShareBytes)
	}
}

func TestInitialize_MofN_InvalidCSR(t *testing.T) {
	cfg := validConfig()
	cfg.Threshold = 2
	cfg.Officers = []OfficerConfig{
		{Username: "officer-A", CSRPEM: []byte("not a valid PEM")},
		{Username: "officer-B", CSRPEM: []byte("also invalid")},
	}
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	_, err = svc.Initialize(context.Background(), mockCA)
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

// ---------------------------------------------------------------------------
// Initialize - error paths with failing CA
// ---------------------------------------------------------------------------

func TestInitialize_CACertificateError(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	errCA := &errorCA{
		mockCA:    newMockCA(t),
		caCertErr: errors.New("ca cert unavailable"),
	}
	_, err = svc.Initialize(context.Background(), errCA)
	assert.ErrorIs(t, err, ErrInitFailed)
}

func TestInitialize_CABundleError(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	errCA := &errorCA{
		mockCA:      newMockCA(t),
		caBundleErr: errors.New("ca bundle unavailable"),
	}
	_, err = svc.Initialize(context.Background(), errCA)
	assert.ErrorIs(t, err, ErrInitFailed)
}

func TestInitialize_SingleAdmin_IssueCertError(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	errCA := &errorCA{
		mockCA:       newMockCA(t),
		issueCertErr: errors.New("issuance failed"),
	}
	_, err = svc.Initialize(context.Background(), errCA)
	assert.ErrorIs(t, err, ErrInitFailed)
}

func TestInitialize_MofN_SignCSRError(t *testing.T) {
	cfg, _ := validMofNConfig(t, 2, 3)
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	errCA := &errorCA{
		mockCA:     newMockCA(t),
		signCSRErr: errors.New("signing failed"),
	}
	_, err = svc.Initialize(context.Background(), errCA)
	assert.ErrorIs(t, err, ErrInitFailed)
}

func TestSignCSRInit_CASignCSRError(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	// Initialize with a CA that errors on SignCSR.
	errCA := &errorCA{
		mockCA:     newMockCA(t),
		signCSRErr: errors.New("signing failed"),
	}
	// Initialize succeeds (IssueCertificate works, not SignCSR) for single admin.
	_, err = svc.Initialize(context.Background(), errCA)
	require.NoError(t, err)

	csrPEM, _ := generateTestCSR(t, "test-cn")
	_, err = svc.SignCSRInit(context.Background(), "admin", "test-so-pin", string(csrPEM), "admin")
	assert.ErrorIs(t, err, ErrCSRSigningFailed)
}

// ---------------------------------------------------------------------------
// SPKIPin - CA certificate error after initialization
// ---------------------------------------------------------------------------

func TestSPKIPin_CACertificateError(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	errCA := &errorCA{mockCA: newMockCA(t)}
	_, err = svc.Initialize(context.Background(), errCA)
	require.NoError(t, err)

	// Now make CACertificate fail.
	errCA.caCertErr = errors.New("cert unavailable")

	_, err = svc.SPKIPin()
	assert.ErrorIs(t, err, ErrInitFailed)
}

// ---------------------------------------------------------------------------
// CompleteClaimCert - CA bundle error during completion
// ---------------------------------------------------------------------------

func TestCompleteClaimCert_CABundleError(t *testing.T) {
	cfg, keys := validMofNConfig(t, 2, 3)
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	errCA := &errorCA{mockCA: newMockCA(t)}
	_, err = svc.Initialize(context.Background(), errCA)
	require.NoError(t, err)

	ctx := context.Background()
	challenge, err := svc.BeginClaimCert(ctx, "officer-A")
	require.NoError(t, err)

	hash := sha256.Sum256(challenge.Nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[0], hash[:])
	require.NoError(t, err)

	// Make CA bundle fail before completing.
	errCA.caBundleErr = errors.New("bundle unavailable")

	nonceHex := hex.EncodeToString(challenge.Nonce)
	_, err = svc.CompleteClaimCert(ctx, "officer-A", nonceHex, sig)
	assert.ErrorIs(t, err, ErrInitFailed)
}

// ---------------------------------------------------------------------------
// Adapter - ClaimCertComplete with valid base64 but inner error
// ---------------------------------------------------------------------------

func TestCeremonyAdapter_ClaimCertComplete_InnerError(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)

	// Valid base64 but wrong nonce -- CompleteClaimCert returns error after decode.
	completeReq := &transport.ClaimCertCompleteRequest{
		Username:  "officer-A",
		Nonce:     "deadbeefdeadbeef",
		Signature: base64.StdEncoding.EncodeToString([]byte("valid-base64-but-bad-sig")),
	}
	_, err := adapter.ClaimCertComplete(context.Background(), completeReq)
	assert.ErrorIs(t, err, ErrChallengeVerificationFailed)
}

// ---------------------------------------------------------------------------
// BeginClaimCert
// ---------------------------------------------------------------------------

func TestBeginClaimCert_Success(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)

	challenge, err := svc.BeginClaimCert(context.Background(), "officer-A")
	require.NoError(t, err)
	assert.NotNil(t, challenge)
	assert.NotEmpty(t, challenge.Nonce)
	assert.Equal(t, "officer-A", challenge.Username)
	assert.True(t, challenge.ExpiresAt.After(time.Now()))
}

func TestBeginClaimCert_NotEnrolling(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	_, err = svc.BeginClaimCert(context.Background(), "anyone")
	assert.ErrorIs(t, err, ErrNotInEnrollingState)
}

func TestBeginClaimCert_UnknownUsername(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)

	_, err := svc.BeginClaimCert(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, ErrPendingCertNotFound)
}

func TestBeginClaimCert_AlreadyClaimed(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	// Claim officer-A's cert first.
	challenge, err := svc.BeginClaimCert(ctx, "officer-A")
	require.NoError(t, err)

	hash := sha256.Sum256(challenge.Nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[0], hash[:])
	require.NoError(t, err)

	nonceHex := hex.EncodeToString(challenge.Nonce)
	_, err = svc.CompleteClaimCert(ctx, "officer-A", nonceHex, sig)
	require.NoError(t, err)

	// Attempt to begin claim again.
	_, err = svc.BeginClaimCert(ctx, "officer-A")
	assert.ErrorIs(t, err, ErrCertAlreadyClaimed)
}

// ---------------------------------------------------------------------------
// CompleteClaimCert
// ---------------------------------------------------------------------------

func TestCompleteClaimCert_Success(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	challenge, err := svc.BeginClaimCert(ctx, "officer-A")
	require.NoError(t, err)

	hash := sha256.Sum256(challenge.Nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[0], hash[:])
	require.NoError(t, err)

	nonceHex := hex.EncodeToString(challenge.Nonce)
	result, err := svc.CompleteClaimCert(ctx, "officer-A", nonceHex, sig)
	require.NoError(t, err)

	assert.NotEmpty(t, result.CertPEM)
	assert.NotEmpty(t, result.CACertPEM)

	// Verify the certificate is parseable.
	block, _ := pem.Decode(result.CertPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "officer-A", cert.Subject.CommonName)
}

func TestCompleteClaimCert_WrongSignature(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	challenge, err := svc.BeginClaimCert(ctx, "officer-A")
	require.NoError(t, err)

	// Sign with a different key.
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	hash := sha256.Sum256(challenge.Nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, wrongKey, hash[:])
	require.NoError(t, err)

	nonceHex := hex.EncodeToString(challenge.Nonce)
	_, err = svc.CompleteClaimCert(ctx, "officer-A", nonceHex, sig)
	assert.ErrorIs(t, err, ErrChallengeVerificationFailed)
}

func TestCompleteClaimCert_BadNonce(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	_, err := svc.BeginClaimCert(ctx, "officer-A")
	require.NoError(t, err)

	fakeNonce := make([]byte, 32)
	_, err = rand.Read(fakeNonce)
	require.NoError(t, err)
	hash := sha256.Sum256(fakeNonce)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[0], hash[:])
	require.NoError(t, err)

	fakeHex := hex.EncodeToString(fakeNonce)
	_, err = svc.CompleteClaimCert(ctx, "officer-A", fakeHex, sig)
	assert.ErrorIs(t, err, ErrChallengeVerificationFailed)
}

func TestCompleteClaimCert_UsernameMismatch(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	challenge, err := svc.BeginClaimCert(ctx, "officer-A")
	require.NoError(t, err)

	hash := sha256.Sum256(challenge.Nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[0], hash[:])
	require.NoError(t, err)

	nonceHex := hex.EncodeToString(challenge.Nonce)
	// Use a different username than what the challenge was issued for.
	_, err = svc.CompleteClaimCert(ctx, "officer-B", nonceHex, sig)
	assert.ErrorIs(t, err, ErrChallengeVerificationFailed)
}

func TestCompleteClaimCert_AlreadyClaimed(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	// Successfully claim the cert.
	challenge1, err := svc.BeginClaimCert(ctx, "officer-A")
	require.NoError(t, err)

	hash1 := sha256.Sum256(challenge1.Nonce)
	sig1, err := ecdsa.SignASN1(rand.Reader, keys[0], hash1[:])
	require.NoError(t, err)
	nonceHex1 := hex.EncodeToString(challenge1.Nonce)
	_, err = svc.CompleteClaimCert(ctx, "officer-A", nonceHex1, sig1)
	require.NoError(t, err)

	// Try to begin claim again for the same user - should fail.
	_, err = svc.BeginClaimCert(ctx, "officer-A")
	assert.ErrorIs(t, err, ErrCertAlreadyClaimed)
}

// ---------------------------------------------------------------------------
// Officer share claim (BeginClaimShare / CompleteClaimShare)
// ---------------------------------------------------------------------------

func TestClaimShare_Success(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)

	thumb := claimOfficerCertThumbprint(t, svc, "officer-A", keys[0])
	claimed, err := claimOfficerShare(t, svc, "officer-A", keys[0], thumb)
	require.NoError(t, err)
	assert.NotEmpty(t, claimed.ShareBytes)
	assert.Equal(t, 1, claimed.ShareIndex)

	// The share is released exactly once.
	again, err := claimOfficerShare(t, svc, "officer-A", keys[0], thumb)
	require.Error(t, err)
	assert.Nil(t, again, "the share must never be released twice")
}

// TestClaimShare_NoCallerCertificateRefused is the security regression test for
// the username-only share release: an enrolled officer who presents no
// certificate is refused and receives no share bytes.
func TestClaimShare_NoCallerCertificateRefused(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)

	claimOfficerCertThumbprint(t, svc, "officer-A", keys[0])

	// An empty thumbprint is what a transport produces for a request that
	// carries no mTLS peer certificate.
	stolen, err := claimOfficerShare(t, svc, "officer-A", keys[0], "")
	assert.ErrorIs(t, err, ErrCertThumbprintMismatch)
	assert.Nil(t, stolen, "no share material may accompany a refusal")
}

// TestClaimShare_WrongOfficerCertificateRefused proves officer-B cannot take
// officer-A's share by naming officer-A while presenting its own certificate.
func TestClaimShare_WrongOfficerCertificateRefused(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)

	victimThumb := claimOfficerCertThumbprint(t, svc, "officer-A", keys[0])
	attackerThumb := claimOfficerCertThumbprint(t, svc, "officer-B", keys[1])
	require.NotEqual(t, victimThumb, attackerThumb)

	stolen, err := claimOfficerShare(t, svc, "officer-A", keys[1], attackerThumb)
	assert.ErrorIs(t, err, ErrCertThumbprintMismatch)
	assert.Nil(t, stolen, "no share material may accompany a refusal")

	// The victim's share is untouched and still claimable by the victim.
	legit, err := claimOfficerShare(t, svc, "officer-A", keys[0], victimThumb)
	require.NoError(t, err)
	assert.NotEmpty(t, legit.ShareBytes)
}

// TestClaimShare_NonceReplayRejected proves a nonce is single-use.
func TestClaimShare_NonceReplayRejected(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	thumb := claimOfficerCertThumbprint(t, svc, "officer-A", keys[0])

	challenge, err := svc.BeginClaimShare(ctx, "officer-A", thumb)
	require.NoError(t, err)
	nonceHex := hex.EncodeToString(challenge.Nonce)
	hash := sha256.Sum256(challenge.Nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[0], hash[:])
	require.NoError(t, err)

	_, err = svc.CompleteClaimShare(ctx, "officer-A", nonceHex, sig, thumb)
	require.NoError(t, err)

	replayed, err := svc.CompleteClaimShare(ctx, "officer-A", nonceHex, sig, thumb)
	require.Error(t, err)
	assert.Nil(t, replayed, "a replayed nonce must not release the share again")
}

// TestClaimShare_SupersededNonceRejected proves a re-begin invalidates the
// previously issued nonce.
func TestClaimShare_SupersededNonceRejected(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	thumb := claimOfficerCertThumbprint(t, svc, "officer-A", keys[0])

	first, err := svc.BeginClaimShare(ctx, "officer-A", thumb)
	require.NoError(t, err)
	firstHex := hex.EncodeToString(first.Nonce)
	firstHash := sha256.Sum256(first.Nonce)
	firstSig, err := ecdsa.SignASN1(rand.Reader, keys[0], firstHash[:])
	require.NoError(t, err)

	second, err := svc.BeginClaimShare(ctx, "officer-A", thumb)
	require.NoError(t, err)
	require.NotEqual(t, firstHex, hex.EncodeToString(second.Nonce))

	stale, err := svc.CompleteClaimShare(ctx, "officer-A", firstHex, firstSig, thumb)
	assert.ErrorIs(t, err, ErrChallengeVerificationFailed)
	assert.Nil(t, stale, "a superseded nonce must not release the share")

	// The current nonce still works.
	secondHash := sha256.Sum256(second.Nonce)
	secondSig, err := ecdsa.SignASN1(rand.Reader, keys[0], secondHash[:])
	require.NoError(t, err)
	fresh, err := svc.CompleteClaimShare(ctx, "officer-A", hex.EncodeToString(second.Nonce), secondSig, thumb)
	require.NoError(t, err)
	assert.NotEmpty(t, fresh.ShareBytes)
}

// TestClaimShare_WrongSignatureRejected proves the nonce must be signed by the
// key matching the officer's enrolled public key.
func TestClaimShare_WrongSignatureRejected(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	thumb := claimOfficerCertThumbprint(t, svc, "officer-A", keys[0])

	challenge, err := svc.BeginClaimShare(ctx, "officer-A", thumb)
	require.NoError(t, err)

	hash := sha256.Sum256(challenge.Nonce)
	wrongSig, err := ecdsa.SignASN1(rand.Reader, keys[1], hash[:])
	require.NoError(t, err)

	result, err := svc.CompleteClaimShare(ctx, "officer-A", hex.EncodeToString(challenge.Nonce), wrongSig, thumb)
	require.Error(t, err)
	assert.Nil(t, result, "no share material may accompany a refusal")
}

func TestClaimShare_NotEnrolling(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	_, err = svc.BeginClaimShare(context.Background(), "anyone", "some-thumbprint")
	assert.ErrorIs(t, err, ErrOfficerNotFound)
}

func TestClaimShare_UnknownUsername(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)

	_, err := svc.BeginClaimShare(context.Background(), "nonexistent", "some-thumbprint")
	assert.ErrorIs(t, err, ErrOfficerNotFound)
}

func TestClaimShare_EmptyUsername(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)

	_, err := svc.BeginClaimShare(context.Background(), "", "some-thumbprint")
	assert.ErrorIs(t, err, ErrMissingUsername)
}

func TestClaimShare_AlreadyClaimed(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)

	thumb := claimOfficerCertThumbprint(t, svc, "officer-A", keys[0])
	_, err := claimOfficerShare(t, svc, "officer-A", keys[0], thumb)
	require.NoError(t, err)

	_, err = svc.BeginClaimShare(context.Background(), "officer-A", thumb)
	assert.ErrorIs(t, err, ErrNoPendingShare)
}

// TestClaimShare_AllClaimedTransitionsToOperational drives the whole M-of-N
// ceremony through the strong claim flow and asserts it lands operational.
func TestClaimShare_AllClaimedTransitionsToOperational(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)

	require.Equal(t, StateEnrolling, svc.State())

	for i, username := range officerUsernames {
		thumb := claimOfficerCertThumbprint(t, svc, username, keys[i])
		claimed, err := claimOfficerShare(t, svc, username, keys[i], thumb)
		require.NoError(t, err)
		assert.NotEmpty(t, claimed.ShareBytes)
	}

	assert.Equal(t, StateOperational, svc.State())
}

// ---------------------------------------------------------------------------
// State and utility tests
// ---------------------------------------------------------------------------

func TestState_InitialState(t *testing.T) {
	svc, err := NewCeremonyService(validConfig(), testBarrier(t), testCredService(t), testLogger())
	require.NoError(t, err)
	assert.Equal(t, StateAwaitingInit, svc.State())
}

func TestSPKIPin_BeforeInit(t *testing.T) {
	svc, err := NewCeremonyService(validConfig(), testBarrier(t), testCredService(t), testLogger())
	require.NoError(t, err)

	_, err = svc.SPKIPin()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInitFailed)
}

func TestSPKIPin_AfterInit(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	_, err = svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)

	pin, err := svc.SPKIPin()
	require.NoError(t, err)
	assert.NotEmpty(t, pin)

	// Verify the pin is a valid hex-encoded SHA-256 hash (64 hex chars).
	assert.Len(t, pin, 64)
}

func TestThresholdRegistry_Accessible(t *testing.T) {
	svc, err := NewCeremonyService(validConfig(), testBarrier(t), testCredService(t), testLogger())
	require.NoError(t, err)
	assert.NotNil(t, svc.ThresholdRegistry())
}

// ---------------------------------------------------------------------------
// CompleteClaimCert - not in enrolling state
// ---------------------------------------------------------------------------

func TestCompleteClaimCert_NotEnrolling(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	_, err = svc.CompleteClaimCert(context.Background(), "anyone", "nonce", []byte("sig"))
	assert.ErrorIs(t, err, ErrNotInEnrollingState)
}

// ---------------------------------------------------------------------------
// allClaimsComplete - partial claims don't transition
// ---------------------------------------------------------------------------

func TestPartialClaimsDoNotTransition(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)

	// Claim only one officer's cert and share.
	thumb := claimOfficerCertThumbprint(t, svc, "officer-A", keys[0])
	_, err := claimOfficerShare(t, svc, "officer-A", keys[0], thumb)
	require.NoError(t, err)

	// State should still be enrolling because other officers haven't claimed.
	assert.Equal(t, StateEnrolling, svc.State())
}

// ---------------------------------------------------------------------------
// Edge case: M-of-N with threshold equal to officers count
// ---------------------------------------------------------------------------

func TestInitialize_MofN_ThresholdEqualsOfficers(t *testing.T) {
	cfg, _ := validMofNConfig(t, 3, 3)
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	result, err := svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)
	assert.Equal(t, StateEnrolling, result.State)
	assert.Equal(t, 3, result.ShareCount)
}

// ---------------------------------------------------------------------------
// Edge case: threshold of exactly 2
// ---------------------------------------------------------------------------

func TestNewCeremonyService_ThresholdBoundary(t *testing.T) {
	csr1, _ := generateTestCSR(t, "officer-A")
	csr2, _ := generateTestCSR(t, "officer-B")
	cfg := validConfig()
	cfg.Threshold = 2
	cfg.Officers = []OfficerConfig{
		{Username: "officer-A", CSRPEM: csr1},
		{Username: "officer-B", CSRPEM: csr2},
	}
	svc, err := NewCeremonyService(cfg, testBarrier(t), testCredService(t), testLogger())
	require.NoError(t, err)
	assert.NotNil(t, svc)
}

// ---------------------------------------------------------------------------
// Edge case: threshold < 2 treated as single admin
// ---------------------------------------------------------------------------

func TestInitialize_ThresholdOneTreatedAsSingleAdmin(t *testing.T) {
	cfg := validConfig()
	cfg.Threshold = 1
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	result, err := svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)
	assert.Equal(t, StateOperational, result.State)
}

// ---------------------------------------------------------------------------
// SignCSRInit - success cases
// ---------------------------------------------------------------------------

func TestSignCSRInit_Success_SingleAdmin(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)
	ctx := context.Background()

	csrPEM, _ := generateTestCSR(t, "new-operator")

	result, err := svc.SignCSRInit(ctx, "admin-user", "test-so-pin", string(csrPEM), "operator")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.CertPEM)

	// Parse and verify the issued certificate.
	block, _ := pem.Decode(result.CertPEM)
	require.NotNil(t, block, "result CertPEM should contain valid PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	// go-qrdb v0.28 holder contract: the certificate names the registered
	// holder and the scope's tenant, never the CSR's own subject, so a CSR
	// for another account cannot mint a login as it.
	assert.Equal(t, "admin-user", cert.Subject.CommonName, "the CSR's CN is not copied")
	require.NotEmpty(t, cert.Subject.OrganizationalUnit)
	assert.Equal(t, systemTenantID, cert.Subject.OrganizationalUnit[0])
	assert.Empty(t, cert.DNSNames)
	assert.Empty(t, cert.URIs)
}

func TestSignCSRInit_Success_MofN_Enrolling(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	// In enrolling state, SignCSRInit should also work.
	csrPEM, _ := generateTestCSR(t, "extra-officer")

	result, err := svc.SignCSRInit(ctx, "admin-user", "test-so-pin", string(csrPEM), "so")
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.CertPEM)

	block, _ := pem.Decode(result.CertPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "admin-user", cert.Subject.CommonName, "the registered holder, not the CSR's CN")
}

func TestSignCSRInit_AllRoles(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)
	ctx := context.Background()

	roles := []string{"so", "admin", "operator", "user", "auditor", "custodian"}
	for _, role := range roles {
		csrPEM, _ := generateTestCSR(t, "user-for-"+role)
		result, err := svc.SignCSRInit(ctx, "test-user", "test-so-pin", string(csrPEM), role)
		require.NoError(t, err, "role %s should succeed", role)
		assert.NotEmpty(t, result.CertPEM, "role %s should produce a certificate", role)
	}
}

// ---------------------------------------------------------------------------
// SignCSRInit - error cases
// ---------------------------------------------------------------------------

func TestSignCSRInit_AwaitingInit(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	csrPEM, _ := generateTestCSR(t, "test-user")
	_, err = svc.SignCSRInit(context.Background(), "admin", "test-so-pin", string(csrPEM), "admin")
	assert.ErrorIs(t, err, ErrNotInitializedOrEnrolling)
}

func TestSignCSRInit_EmptyUsername(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)

	csrPEM, _ := generateTestCSR(t, "test-cn")
	_, err := svc.SignCSRInit(context.Background(), "", "test-so-pin", string(csrPEM), "admin")
	assert.ErrorIs(t, err, ErrMissingUsername)
}

func TestSignCSRInit_EmptyCSRPEM(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)

	_, err := svc.SignCSRInit(context.Background(), "admin", "test-so-pin", "", "admin")
	assert.ErrorIs(t, err, ErrMissingCSRPEM)
}

func TestSignCSRInit_EmptyRole(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)

	csrPEM, _ := generateTestCSR(t, "test-cn")
	_, err := svc.SignCSRInit(context.Background(), "admin", "test-so-pin", string(csrPEM), "")
	assert.ErrorIs(t, err, ErrMissingRole)
}

func TestSignCSRInit_WrongSOPin(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)

	csrPEM, _ := generateTestCSR(t, "test-cn")
	_, err := svc.SignCSRInit(context.Background(), "admin", "wrong-pin", string(csrPEM), "admin")
	assert.ErrorIs(t, err, ErrSOPINMismatch)
}

func TestSignCSRInit_InvalidRole(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)

	csrPEM, _ := generateTestCSR(t, "test-cn")
	_, err := svc.SignCSRInit(context.Background(), "admin", "test-so-pin", string(csrPEM), "not-a-real-role")
	assert.ErrorIs(t, err, ErrInvalidRole)
}

func TestSignCSRInit_InvalidCSRPEM(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)

	_, err := svc.SignCSRInit(context.Background(), "admin", "test-so-pin", "not-valid-pem", "admin")
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

func TestSignCSRInit_MalformedCSRDER(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)

	// Valid PEM wrapper but garbage DER content.
	badCSR := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: []byte("this is not valid DER"),
	})

	_, err := svc.SignCSRInit(context.Background(), "admin", "test-so-pin", string(badCSR), "admin")
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

func TestSignCSRInit_CSRWithBadSignature(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)

	// Create a CSR, then tamper with its DER to invalidate the signature.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "tampered"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	require.NoError(t, err)

	// Tamper with the last byte of the DER (modifies the signature).
	csrDER[len(csrDER)-1] ^= 0xFF

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	_, err = svc.SignCSRInit(context.Background(), "admin", "test-so-pin", string(csrPEM), "admin")
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

// ---------------------------------------------------------------------------
// CeremonyAdapter tests
// ---------------------------------------------------------------------------

func TestCeremonyAdapter_NewCeremonyAdapter(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)
	adapter := NewCeremonyAdapter(svc)
	assert.NotNil(t, adapter)
}

func TestCeremonyAdapter_GetInitStatus(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)
	adapter := NewCeremonyAdapter(svc)

	resp, err := adapter.GetInitStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, string(StateOperational), resp.State)
}

func TestCeremonyAdapter_GetInitStatus_AwaitingInit(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	adapter := NewCeremonyAdapter(svc)
	resp, err := adapter.GetInitStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, string(StateAwaitingInit), resp.State)
}

func TestCeremonyAdapter_ClaimCertBegin_Success(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)

	req := &transport.ClaimCertBeginRequest{Username: "officer-A"}
	resp, err := adapter.ClaimCertBegin(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Nonce)
	assert.Equal(t, "officer-A", resp.Username)
	assert.True(t, resp.ExpiresAt.After(time.Now()))
}

func TestCeremonyAdapter_ClaimCertBegin_UnknownUser(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)

	req := &transport.ClaimCertBeginRequest{Username: "nonexistent"}
	_, err := adapter.ClaimCertBegin(context.Background(), req)
	assert.ErrorIs(t, err, ErrPendingCertNotFound)
}

func TestCeremonyAdapter_ClaimCertComplete_Success(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)
	ctx := context.Background()

	// Begin the claim.
	beginReq := &transport.ClaimCertBeginRequest{Username: "officer-A"}
	beginResp, err := adapter.ClaimCertBegin(ctx, beginReq)
	require.NoError(t, err)

	// Decode the nonce hex, sign it.
	nonceBytes, err := hex.DecodeString(beginResp.Nonce)
	require.NoError(t, err)
	hash := sha256.Sum256(nonceBytes)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[0], hash[:])
	require.NoError(t, err)

	completeReq := &transport.ClaimCertCompleteRequest{
		Username:  "officer-A",
		Nonce:     beginResp.Nonce,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	resp, err := adapter.ClaimCertComplete(ctx, completeReq)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertPEM)
	assert.NotEmpty(t, resp.CACertPEM)
}

func TestCeremonyAdapter_ClaimCertComplete_InvalidBase64Signature(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)

	completeReq := &transport.ClaimCertCompleteRequest{
		Username:  "officer-A",
		Nonce:     "somenonce",
		Signature: "not-valid-base64!!!",
	}
	_, err := adapter.ClaimCertComplete(context.Background(), completeReq)
	assert.ErrorIs(t, err, ErrChallengeVerificationFailed)
}

func TestCeremonyAdapter_ClaimCertComplete_InnerCompleteError(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)

	// Valid base64 signature, but the nonce doesn't match any challenge.
	// This causes CompleteClaimCert to return an error (after base64 decode succeeds).
	completeReq := &transport.ClaimCertCompleteRequest{
		Username:  "officer-A",
		Nonce:     "deadbeefdeadbeef",
		Signature: base64.StdEncoding.EncodeToString([]byte("valid-b64-bad-sig")),
	}
	_, err := adapter.ClaimCertComplete(context.Background(), completeReq)
	assert.ErrorIs(t, err, ErrChallengeVerificationFailed)
}

func TestCeremonyAdapter_ClaimShare_Success(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)
	ctx := context.Background()

	thumb := claimOfficerCertThumbprint(t, svc, "officer-A", keys[0])

	begun, err := adapter.ClaimShareBegin(ctx, &transport.ClaimShareBeginRequest{
		Username:             "officer-A",
		CallerCertThumbprint: thumb,
	})
	require.NoError(t, err)
	require.NotEmpty(t, begun.Nonce)

	nonce, err := hex.DecodeString(begun.Nonce)
	require.NoError(t, err)
	hash := sha256.Sum256(nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[0], hash[:])
	require.NoError(t, err)

	resp, err := adapter.ClaimShareComplete(ctx, &transport.ClaimShareCompleteRequest{
		Username:             "officer-A",
		Nonce:                begun.Nonce,
		Signature:            base64.StdEncoding.EncodeToString(sig),
		CallerCertThumbprint: thumb,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Share)
	assert.Equal(t, 1, resp.ShareIndex)
}

// TestCeremonyAdapter_ClaimShareComplete_InvalidBase64Signature verifies
// ClaimShareComplete rejects a malformed signature before ever consulting the
// service, mirroring ClaimCertComplete's own base64 guard.
func TestCeremonyAdapter_ClaimShareComplete_InvalidBase64Signature(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)

	resp, err := adapter.ClaimShareComplete(context.Background(), &transport.ClaimShareCompleteRequest{
		Username:             "officer-A",
		Nonce:                "somenonce",
		Signature:            "not-valid-base64!!!",
		CallerCertThumbprint: "thumb",
	})
	assert.ErrorIs(t, err, ErrChallengeVerificationFailed)
	assert.Nil(t, resp)
}

// TestCeremonyService_RegisterOfficer_MissingUsernameRejected verifies
// RegisterOfficer forwards the request (and the underlying rejection) rather
// than swallowing or reshaping it: an officer with no username could never be
// looked up again to claim their share.
func TestCeremonyService_RegisterOfficer_MissingUsernameRejected(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)

	result, err := svc.RegisterOfficer(context.Background(), RegisterOfficerRequest{
		CSRPEM: []byte("irrelevant"),
	})
	require.Error(t, err)
	assert.Nil(t, result)
}

// TestCeremonyService_OfficerClaimStatus_ReportsEnrolledOfficers verifies the
// delegation returns real per-officer status rather than an empty/nil result,
// for a service that actually enrolled officers via Initialize.
func TestCeremonyService_OfficerClaimStatus_ReportsEnrolledOfficers(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)

	statuses, err := svc.OfficerClaimStatus(context.Background())
	require.NoError(t, err)
	assert.Len(t, statuses, len(officerUsernames))
}

// TestCeremonyService_EnrollExternalOfficer_InvalidShareIndexRejected
// verifies EnrollExternalOfficer forwards the underlying validation error for
// a structurally invalid request (a share index must be 1-based) rather than
// enrolling a broken officer record.
func TestCeremonyService_EnrollExternalOfficer_InvalidShareIndexRejected(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)

	resp, err := svc.EnrollExternalOfficer(context.Background(), EnrollExternalOfficerRequest{
		Username:   "officer-new",
		ShareIndex: 0,
		AuthFactor: "mtls",
	})
	require.Error(t, err)
	assert.Nil(t, resp)
}

func TestCeremonyAdapter_ClaimShare_NotFound(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)

	req := &transport.ClaimShareBeginRequest{Username: "nonexistent", CallerCertThumbprint: "thumb"}
	_, err := adapter.ClaimShareBegin(context.Background(), req)
	assert.ErrorIs(t, err, ErrOfficerNotFound)
}

// TestCeremonyAdapter_ClaimShare_WrongThumbprintRefused proves the adapter
// forwards the caller thumbprint verbatim and refuses a mismatch without
// returning any share material.
func TestCeremonyAdapter_ClaimShare_WrongThumbprintRefused(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)
	ctx := context.Background()

	claimOfficerCertThumbprint(t, svc, "officer-A", keys[0])
	attackerThumb := claimOfficerCertThumbprint(t, svc, "officer-B", keys[1])

	_, err := adapter.ClaimShareBegin(ctx, &transport.ClaimShareBeginRequest{
		Username:             "officer-A",
		CallerCertThumbprint: attackerThumb,
	})
	assert.ErrorIs(t, err, ErrCertThumbprintMismatch)

	resp, err := adapter.ClaimShareComplete(ctx, &transport.ClaimShareCompleteRequest{
		Username:             "officer-A",
		Nonce:                "deadbeef",
		Signature:            base64.StdEncoding.EncodeToString([]byte("sig")),
		CallerCertThumbprint: attackerThumb,
	})
	require.Error(t, err)
	assert.Nil(t, resp, "no share material may accompany a refusal")
}

func TestCeremonyAdapter_SignCSRInit_Success(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)
	adapter := NewCeremonyAdapter(svc)

	csrPEM, _ := generateTestCSR(t, "adapter-test-user")
	req := &transport.SignCSRInitRequest{
		Username: "admin-user",
		SOPin:    "test-so-pin",
		CSRPEM:   string(csrPEM),
		Role:     "admin",
	}
	resp, err := adapter.SignCSRInit(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.CertPEM)
}

func TestCeremonyAdapter_SignCSRInit_WrongSOPin(t *testing.T) {
	svc, _ := initServiceSingleAdmin(t)
	adapter := NewCeremonyAdapter(svc)

	csrPEM, _ := generateTestCSR(t, "adapter-test-user")
	req := &transport.SignCSRInitRequest{
		Username: "admin-user",
		SOPin:    "wrong-pin",
		CSRPEM:   string(csrPEM),
		Role:     "admin",
	}
	_, err := adapter.SignCSRInit(context.Background(), req)
	assert.ErrorIs(t, err, ErrSOPINMismatch)
}

// ---------------------------------------------------------------------------
// Initialize - M-of-N with RSA CSR (covers RSA branch in initializeMofN)
// ---------------------------------------------------------------------------

func TestInitialize_MofN_WithRSACSR(t *testing.T) {
	csrPEM, _ := generateTestRSACSR(t, "rsa-officer-A")
	csrPEM2, _ := generateTestCSR(t, "officer-B")
	cfg := validConfig()
	cfg.Threshold = 2
	cfg.Officers = []OfficerConfig{
		{Username: "rsa-officer-A", CSRPEM: csrPEM},
		{Username: "officer-B", CSRPEM: csrPEM2},
	}
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	result, err := svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)
	assert.Equal(t, StateEnrolling, result.State)
	assert.Equal(t, 2, result.ShareCount)
}

// ---------------------------------------------------------------------------
// Initialize - M-of-N with Ed25519 CSR
// ---------------------------------------------------------------------------

func TestInitialize_MofN_WithEd25519CSR(t *testing.T) {
	csrPEM, _ := generateTestEd25519CSR(t, "ed-officer-A")
	csrPEM2, _ := generateTestCSR(t, "officer-B")
	cfg := validConfig()
	cfg.Threshold = 2
	cfg.Officers = []OfficerConfig{
		{Username: "ed-officer-A", CSRPEM: csrPEM},
		{Username: "officer-B", CSRPEM: csrPEM2},
	}
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	result, err := svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)
	assert.Equal(t, StateEnrolling, result.State)
}

func (m *mockCA) VerifyTCG_CSR_IDevIDBytes(_ []byte, _ x509.SignatureAlgorithm) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}

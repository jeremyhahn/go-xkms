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
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mockCA implements ca.XKMSCA with a real self-signed ECDSA root cert.
// ---------------------------------------------------------------------------

type mockCA struct {
	cert       *x509.Certificate
	certPEM    []byte
	privateKey *ecdsa.PrivateKey
}

// Compile-time interface check.
var _ ca.XKMSCA = (*mockCA)(nil)

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

func (m *mockCA) Init() error         { return nil }
func (m *mockCA) Load() error         { return nil }
func (m *mockCA) IsInitialized() bool { return true }
func (m *mockCA) Identity() string    { return m.cert.Subject.CommonName }
func (m *mockCA) Config() *ca.Identity {
	return &ca.Identity{Subject: ca.Subject{CommonName: m.cert.Subject.CommonName}}
}
func (m *mockCA) KeyStore() xkms.Backend         { return nil }
func (m *mockCA) CertStore() certstore.CertStore { return nil }

// --- Certificate accessors ---

func (m *mockCA) CACertificate() (*x509.Certificate, error) { return m.cert, nil }

func (m *mockCA) CABundle() ([]byte, error) { return m.certPEM, nil }

// --- CSR operations ---

func (m *mockCA) CreateCSR(_ *ca.CertificateRequest) ([]byte, error) { return nil, nil }

func (m *mockCA) SignCSR(csrPEM []byte, _ *ca.SignOptions) (*x509.Certificate, error) {
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
	certDER, err := x509.CreateCertificate(rand.Reader, template, m.cert, csr.PublicKey, m.privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func (m *mockCA) IssueCertificate(req *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
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

func (m *mockCA) IssueCertificateWithProfile(req *ca.CertificateRequest, _ string) (*ca.IssuedCertificate, error) {
	return m.IssueCertificate(req)
}

// --- Trust chain / revocation ---

func (m *mockCA) Verify(_ *x509.Certificate) ([][]*x509.Certificate, error) { return nil, nil }
func (m *mockCA) Revoke(_ *big.Int, _ int) error                            { return nil }
func (m *mockCA) GenerateCRL() ([]byte, error)                              { return nil, nil }
func (m *mockCA) IsRevoked(_ *big.Int) (bool, error)                        { return false, nil }

// --- TLS ---

func (m *mockCA) TLSCertificate(_ *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *mockCA) TLSConfig(_ *types.KeyAttributes) (*tls.Config, error) { return nil, nil }
func (m *mockCA) QuantumSafeTLSConfig(_ *types.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}

// --- Trust pool builders ---

func (m *mockCA) CABundleCertPool() (*x509.CertPool, error)                              { return nil, nil }
func (m *mockCA) TrustedRootCertPool(_ *x509.Certificate) (*x509.CertPool, error)        { return nil, nil }
func (m *mockCA) TrustedIntermediateCertPool(_ *x509.Certificate) (*x509.CertPool, error) {
	return nil, nil
}
func (m *mockCA) OSTrustStore() (*x509.CertPool, error) { return nil, nil }

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

func (e *errorCA) SignCSR(csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
	if e.signCSRErr != nil {
		return nil, e.signCSRErr
	}
	return e.mockCA.SignCSR(csrPEM, opts)
}

func (e *errorCA) IssueCertificate(req *ca.CertificateRequest) (*ca.IssuedCertificate, error) {
	if e.issueCertErr != nil {
		return nil, e.issueCertErr
	}
	return e.mockCA.IssueCertificate(req)
}

func (e *errorCA) IssueCertificateWithProfile(req *ca.CertificateRequest, profile string) (*ca.IssuedCertificate, error) {
	if e.issueCertErr != nil {
		return nil, e.issueCertErr
	}
	return e.mockCA.IssueCertificateWithProfile(req, profile)
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
		PreferenceOrder: []seal.StrategyID{seal.StrategySoftware},
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
	assert.NotEmpty(t, result.SOCertPEM)
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
	// SOCertPEM/SOKeyPEM should be empty for M-of-N mode.
	assert.Empty(t, result.SOCertPEM)
	assert.Empty(t, result.SOKeyPEM)
}

func TestInitialize_MofN_SharesSealed(t *testing.T) {
	cfg, _ := validMofNConfig(t, 2, 3)
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	mockCA := newMockCA(t)
	result, err := svc.Initialize(context.Background(), mockCA)
	require.NoError(t, err)

	// Shares are now stored internally in go-qrdb's memguard share store.
	// Verify shares were created by checking the result share count.
	assert.Equal(t, len(cfg.Officers), result.ShareCount)

	// Verify shares can be claimed via the public API.
	for _, officer := range cfg.Officers {
		shareJSON, claimErr := svc.ClaimShare(context.Background(), officer.Username)
		require.NoError(t, claimErr)
		assert.NotEmpty(t, shareJSON)
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
// ClaimShare
// ---------------------------------------------------------------------------

func TestClaimShare_Success(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	shareJSON, err := svc.ClaimShare(ctx, "officer-A")
	require.NoError(t, err)
	assert.NotEmpty(t, shareJSON)

	// Shares are managed internally by go-qrdb's memguard share store.
	// Verify the share cannot be claimed again (already claimed).
	_, err = svc.ClaimShare(ctx, "officer-A")
	assert.ErrorIs(t, err, ErrShareAlreadyClaimed)
}

func TestClaimShare_NotEnrolling(t *testing.T) {
	cfg := validConfig()
	barrier := testBarrier(t)
	svc, err := NewCeremonyService(cfg, barrier, testCredService(t), testLogger())
	require.NoError(t, err)

	_, err = svc.ClaimShare(context.Background(), "anyone")
	assert.ErrorIs(t, err, ErrNotInEnrollingState)
}

func TestClaimShare_UnknownUsername(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)

	_, err := svc.ClaimShare(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, ErrShareNotFound)
}

func TestClaimShare_AlreadyClaimed(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	_, err := svc.ClaimShare(ctx, "officer-A")
	require.NoError(t, err)

	_, err = svc.ClaimShare(ctx, "officer-A")
	assert.ErrorIs(t, err, ErrShareAlreadyClaimed)
}

func TestClaimShare_AllClaimedTransitionsToOperational(t *testing.T) {
	svc, keys, _ := initServiceMofN(t, 2, 3)
	ctx := context.Background()

	require.Equal(t, StateEnrolling, svc.State())

	// Claim all certs for all officers.
	officers := []string{"officer-A", "officer-B", "officer-C"}
	for i, username := range officers {
		challenge, err := svc.BeginClaimCert(ctx, username)
		require.NoError(t, err)

		hash := sha256.Sum256(challenge.Nonce)
		sig, err := ecdsa.SignASN1(rand.Reader, keys[i], hash[:])
		require.NoError(t, err)

		nonceHex := hex.EncodeToString(challenge.Nonce)
		_, err = svc.CompleteClaimCert(ctx, username, nonceHex, sig)
		require.NoError(t, err)
	}

	// Claim all shares.
	for _, username := range officers {
		shareJSON, err := svc.ClaimShare(ctx, username)
		require.NoError(t, err)
		assert.NotEmpty(t, shareJSON)
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
	ctx := context.Background()

	// Claim only one officer's cert and share.
	challenge, err := svc.BeginClaimCert(ctx, "officer-A")
	require.NoError(t, err)
	hash := sha256.Sum256(challenge.Nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, keys[0], hash[:])
	require.NoError(t, err)
	nonceHex := hex.EncodeToString(challenge.Nonce)
	_, err = svc.CompleteClaimCert(ctx, "officer-A", nonceHex, sig)
	require.NoError(t, err)

	_, err = svc.ClaimShare(ctx, "officer-A")
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
	assert.Equal(t, "new-operator", cert.Subject.CommonName)
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
	assert.Equal(t, "extra-officer", cert.Subject.CommonName)
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
	_, err := svc.SignCSRInit(context.Background(), "admin", "test-so-pin", string(csrPEM), "superadmin")
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
	svc, _, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)

	req := &transport.ClaimShareRequest{Username: "officer-A"}
	resp, err := adapter.ClaimShare(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Share)
}

func TestCeremonyAdapter_ClaimShare_NotFound(t *testing.T) {
	svc, _, _ := initServiceMofN(t, 2, 3)
	adapter := NewCeremonyAdapter(svc)

	req := &transport.ClaimShareRequest{Username: "nonexistent"}
	_, err := adapter.ClaimShare(context.Background(), req)
	assert.ErrorIs(t, err, ErrShareNotFound)
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

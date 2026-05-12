// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package issuance

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSigner implements CertificateSigner for testing.
type mockSigner struct {
	key        *ecdsa.PrivateKey
	cert       *x509.Certificate
	signErr    error
	signerErr  error
	certErr    error
	signCertFn func(template, parent *x509.Certificate, pub, priv interface{}) ([]byte, error)
}

func newMockSigner(t *testing.T) *mockSigner {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return &mockSigner{
		key:  key,
		cert: cert,
	}
}

func (m *mockSigner) Signer() (crypto.Signer, error) {
	if m.signerErr != nil {
		return nil, m.signerErr
	}
	return m.key, nil
}

func (m *mockSigner) Certificate() (*x509.Certificate, error) {
	if m.certErr != nil {
		return nil, m.certErr
	}
	return m.cert, nil
}

func (m *mockSigner) SignCertificate(template, parent *x509.Certificate, pub, priv interface{}) ([]byte, error) {
	if m.signCertFn != nil {
		return m.signCertFn(template, parent, pub, priv)
	}
	if m.signErr != nil {
		return nil, m.signErr
	}
	return x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
}

// mockKeyValidator implements KeyValidator for testing.
type mockKeyValidator struct {
	err error
}

func (m *mockKeyValidator) CheckKey(ctx context.Context, key crypto.PublicKey) error {
	return m.err
}

// mockLinter implements CertificateLinter for testing.
type mockLinter struct {
	passed   bool
	summary  string
	errors   []string
	warnings []string
	lintErr  error
}

func (m *mockLinter) LintCertificate(cert *x509.Certificate) (LintResult, error) {
	if m.lintErr != nil {
		return nil, m.lintErr
	}
	return &mockLintResult{
		passed:   m.passed,
		summary:  m.summary,
		errors:   m.errors,
		warnings: m.warnings,
	}, nil
}

func (m *mockLinter) LintDER(der []byte) (LintResult, error) {
	if m.lintErr != nil {
		return nil, m.lintErr
	}
	return &mockLintResult{
		passed:   m.passed,
		summary:  m.summary,
		errors:   m.errors,
		warnings: m.warnings,
	}, nil
}

type mockLintResult struct {
	passed   bool
	summary  string
	errors   []string
	warnings []string
}

func (r *mockLintResult) Passed() bool       { return r.passed }
func (r *mockLintResult) Summary() string    { return r.summary }
func (r *mockLintResult) Errors() []string   { return r.errors }
func (r *mockLintResult) Warnings() []string { return r.warnings }

// mockCTSubmitter implements CTSubmitter for testing.
type mockCTSubmitter struct {
	scts []ct.SignedCertificateTimestamp
	err  error
}

func (m *mockCTSubmitter) GetSCTs(ctx context.Context, precertDER []byte, chain [][]byte, expiry time.Time) ([]ct.SignedCertificateTimestamp, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.scts != nil {
		return m.scts, nil
	}
	// Return mock SCTs
	return []ct.SignedCertificateTimestamp{
		{Version: ct.V1, Timestamp: uint64(time.Now().UnixMilli())},
		{Version: ct.V1, Timestamp: uint64(time.Now().UnixMilli())},
	}, nil
}

// mockSerialStorage implements SerialStorage for testing.
type mockSerialStorage struct {
	reserved map[string]bool
	err      error
}

func newMockSerialStorage() *mockSerialStorage {
	return &mockSerialStorage{reserved: make(map[string]bool)}
}

func (m *mockSerialStorage) ReserveSerial(ctx context.Context, serial *big.Int, metadata SerialMetadata) error {
	if m.err != nil {
		return m.err
	}
	key := serial.String()
	if m.reserved[key] {
		return ErrSerialPersistenceFailed
	}
	m.reserved[key] = true
	return nil
}

func (m *mockSerialStorage) ConfirmSerial(ctx context.Context, serial *big.Int) error {
	return nil
}

func (m *mockSerialStorage) RevokeReservation(ctx context.Context, serial *big.Int) error {
	delete(m.reserved, serial.String())
	return nil
}

func (m *mockSerialStorage) IsSerialUsed(ctx context.Context, serial *big.Int) (bool, error) {
	return m.reserved[serial.String()], nil
}

// mockCertStorage implements CertificateStorage for testing.
type mockCertStorage struct {
	certs    map[string]*x509.Certificate
	precerts map[string]*x509.Certificate
	storeErr error
}

func newMockCertStorage() *mockCertStorage {
	return &mockCertStorage{
		certs:    make(map[string]*x509.Certificate),
		precerts: make(map[string]*x509.Certificate),
	}
}

func (m *mockCertStorage) StoreCertificate(ctx context.Context, cert *x509.Certificate) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	m.certs[cert.SerialNumber.String()] = cert
	return nil
}

func (m *mockCertStorage) StorePrecert(ctx context.Context, precert *x509.Certificate) error {
	m.precerts[precert.SerialNumber.String()] = precert
	return nil
}

func (m *mockCertStorage) GetCertificateBySerial(ctx context.Context, serial *big.Int) (*x509.Certificate, error) {
	cert, ok := m.certs[serial.String()]
	if !ok {
		return nil, ErrCertificatePersistenceFailed
	}
	return cert, nil
}

// mockAuditLogger implements AuditLogger for testing.
type mockAuditLogger struct {
	intents   int
	precerts  int
	cts       int
	completes int
	failures  int
}

func (m *mockAuditLogger) LogIssuanceIntent(ctx context.Context, req *Request, serial *big.Int) error {
	m.intents++
	return nil
}

func (m *mockAuditLogger) LogPrecertCreated(ctx context.Context, precert *x509.Certificate) error {
	m.precerts++
	return nil
}

func (m *mockAuditLogger) LogCTSubmission(ctx context.Context, scts []ct.SignedCertificateTimestamp, errors []error) error {
	m.cts++
	return nil
}

func (m *mockAuditLogger) LogIssuanceComplete(ctx context.Context, result *Result) error {
	m.completes++
	return nil
}

func (m *mockAuditLogger) LogIssuanceFailure(ctx context.Context, req *Request, phase IssuancePhase, err error) error {
	m.failures++
	return nil
}

// Helper to create a test CSR
func createTestCSR(t *testing.T) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		DNSNames: []string{"test.example.com", "www.test.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	return csr, key
}

func TestNewIssuer(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		signer := newMockSigner(t)
		config := Config{
			Signer:  signer,
			Enabled: true,
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)
		require.NotNil(t, issuer)
	})

	t.Run("nil signer", func(t *testing.T) {
		config := Config{
			Signer:  nil,
			Enabled: true,
		}

		_, err := NewIssuer(config)
		assert.Error(t, err)
	})
}

func TestIssuer_Issue(t *testing.T) {
	t.Run("disabled issuer", func(t *testing.T) {
		signer := newMockSigner(t)
		config := Config{
			Signer:  signer,
			Enabled: false,
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
		}

		_, err = issuer.Issue(context.Background(), req)
		assert.ErrorIs(t, err, ErrIssuanceDisabled)
	})

	t.Run("nil request", func(t *testing.T) {
		signer := newMockSigner(t)
		config := Config{
			Signer:  signer,
			Enabled: true,
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		_, err = issuer.Issue(context.Background(), nil)
		assert.ErrorIs(t, err, ErrNilInput)
	})

	t.Run("nil CSR", func(t *testing.T) {
		signer := newMockSigner(t)
		config := Config{
			Signer:  signer,
			Enabled: true,
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		_, err = issuer.Issue(context.Background(), &Request{})
		assert.ErrorIs(t, err, ErrNilInput)
	})

	t.Run("successful issuance without CT", func(t *testing.T) {
		signer := newMockSigner(t)
		linter := &mockLinter{passed: true}
		certStorage := newMockCertStorage()
		serialStorage := newMockSerialStorage()
		auditLogger := &mockAuditLogger{}

		config := Config{
			Signer:        signer,
			Linter:        linter,
			CertStorage:   certStorage,
			SerialStorage: serialStorage,
			AuditLogger:   auditLogger,
			Enabled:       true,
			Profiles: map[string]Profile{
				"internal": InternalProfile(),
			},
			DefaultProfile: "internal",
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
			Profile:   "internal",
			SkipCT:    true,
		}

		result, err := issuer.Issue(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.NotNil(t, result.Precert)
		assert.NotNil(t, result.FinalCert)
		assert.NotNil(t, result.Serial)
		assert.NotEmpty(t, result.IssuanceID)
		assert.NotZero(t, result.IssuanceTime)

		// Verify audit logging was called
		assert.Equal(t, 1, auditLogger.intents)
		assert.Equal(t, 1, auditLogger.precerts)
		assert.Equal(t, 1, auditLogger.completes)
	})

	t.Run("successful issuance with CT", func(t *testing.T) {
		signer := newMockSigner(t)
		linter := &mockLinter{passed: true}
		ctSubmitter := &mockCTSubmitter{}
		certStorage := newMockCertStorage()

		config := Config{
			Signer:      signer,
			Linter:      linter,
			CTSubmitter: ctSubmitter,
			CertStorage: certStorage,
			Enabled:     true,
			Profiles: map[string]Profile{
				"default": DefaultProfile(),
			},
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
		}

		result, err := issuer.Issue(context.Background(), req)
		require.NoError(t, err)

		assert.Len(t, result.SCTs, 2)
	})

	t.Run("lint failure", func(t *testing.T) {
		signer := newMockSigner(t)
		linter := &mockLinter{
			passed:  false,
			summary: "Certificate failed linting",
			errors:  []string{"e_sub_cert_not_is_ca"},
		}

		config := Config{
			Signer:  signer,
			Linter:  linter,
			Enabled: true,
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
		}

		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)

		var lintErr *LintError
		assert.ErrorAs(t, err, &lintErr)
	})

	t.Run("key validation failure", func(t *testing.T) {
		signer := newMockSigner(t)
		keyValidator := &mockKeyValidator{err: ErrKeyValidationFailed}

		config := Config{
			Signer:       signer,
			KeyValidator: keyValidator,
			Enabled:      true,
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
		}

		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("validity period too long", func(t *testing.T) {
		signer := newMockSigner(t)
		config := Config{
			Signer:  signer,
			Enabled: true,
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(5, 0, 0), // 5 years, exceeds 398 days
		}

		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)

		var csrErr *CSRValidationError
		assert.ErrorAs(t, err, &csrErr)
	})

	t.Run("notAfter before notBefore", func(t *testing.T) {
		signer := newMockSigner(t)
		config := Config{
			Signer:  signer,
			Enabled: true,
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, -1), // In the past
		}

		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("profile not found", func(t *testing.T) {
		signer := newMockSigner(t)
		config := Config{
			Signer:  signer,
			Enabled: true,
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
			Profile:   "nonexistent",
		}

		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("CT submission failure", func(t *testing.T) {
		signer := newMockSigner(t)
		linter := &mockLinter{passed: true}
		ctSubmitter := &mockCTSubmitter{err: ErrCTSubmissionFailed}

		config := Config{
			Signer:      signer,
			Linter:      linter,
			CTSubmitter: ctSubmitter,
			Enabled:     true,
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
		}

		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)
	})

	t.Run("certificate storage failure", func(t *testing.T) {
		signer := newMockSigner(t)
		linter := &mockLinter{passed: true}
		certStorage := newMockCertStorage()
		certStorage.storeErr = ErrCertificatePersistenceFailed

		config := Config{
			Signer:      signer,
			Linter:      linter,
			CertStorage: certStorage,
			Enabled:     true,
			Profiles: map[string]Profile{
				"internal": InternalProfile(),
			},
			DefaultProfile: "internal",
		}

		issuer, err := NewIssuer(config)
		require.NoError(t, err)

		csr, _ := createTestCSR(t)
		req := &Request{
			CSR:       csr,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(0, 0, 90),
			Profile:   "internal",
			SkipCT:    true,
		}

		_, err = issuer.Issue(context.Background(), req)
		assert.Error(t, err)
	})
}

func TestProfiles(t *testing.T) {
	t.Run("DefaultProfile", func(t *testing.T) {
		p := DefaultProfile()
		assert.Equal(t, "default", p.Name)
		assert.Equal(t, 398, p.MaxValidityDays)
		assert.True(t, p.RequireCT)
	})

	t.Run("TLSProfile", func(t *testing.T) {
		p := TLSProfile()
		assert.Equal(t, "tls", p.Name)
		assert.True(t, p.RequireCT)
	})

	t.Run("InternalProfile", func(t *testing.T) {
		p := InternalProfile()
		assert.Equal(t, "internal", p.Name)
		assert.False(t, p.RequireCT)
		assert.Greater(t, p.MaxValidityDays, 398)
	})
}

func TestGenerateIssuanceID(t *testing.T) {
	id1 := generateIssuanceID()
	id2 := generateIssuanceID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
}

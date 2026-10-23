package issuance_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"log/slog"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/acme/goodkey"
	"github.com/jeremyhahn/go-xkms/pkg/acme/issuance"
	"github.com/jeremyhahn/go-xkms/pkg/acme/linter"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

const testTenant = "tenant-issuance"

// auditRecord is one event a recordingAudit received.
type auditRecord struct {
	event   audit.EventType
	result  audit.Result
	details map[string]interface{}
}

// recordingAudit is an audit.AuditLogger that keeps its events in memory and
// fails with err when err is set.
type recordingAudit struct {
	mu      sync.Mutex
	records []auditRecord
	err     error
}

func (a *recordingAudit) Log(context.Context, *audit.AuditEvent) error { return a.err }

func (a *recordingAudit) LogWithContext(_ context.Context, event audit.EventType, _, _, _ string,
	result audit.Result, details map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	a.records = append(a.records, auditRecord{event: event, result: result, details: details})
	return nil
}

func (a *recordingAudit) Flush() error  { return nil }
func (a *recordingAudit) Close() error  { return nil }
func (a *recordingAudit) Enabled() bool { return true }

func (a *recordingAudit) events(event audit.EventType) []auditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	var found []auditRecord
	for _, r := range a.records {
		if r.event == event {
			found = append(found, r)
		}
	}
	return found
}

// lintFunc is an issuance.CertificateLinter backed by a function.
type lintFunc func(der []byte) (*linter.Result, error)

func (f lintFunc) Lint(der []byte) (*linter.Result, error) { return f(der) }

func cleanLint([]byte) (*linter.Result, error) { return &linter.Result{}, nil }

// serialFunc is an issuance.SerialStorage backed by a function.
type serialFunc func(context.Context) (*big.Int, error)

func (f serialFunc) ReserveSerial(ctx context.Context) (*big.Int, error) { return f(ctx) }

// signerFunc is an issuance.CertificateSigner backed by a function.
type signerFunc func(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error)

func (f signerFunc) SignCSR(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
	return f(ctx, csrPEM, opts)
}

// fixture is an Issuer over a real in-memory CA, with its audit log and
// log output.
type fixture struct {
	ca     ca.TrustedCA
	audit  *recordingAudit
	logs   *bytes.Buffer
	config issuance.Config
}

func newFixture(t *testing.T, lint issuance.CertificateLinter) *fixture {
	t.Helper()
	trustedCA := newTestCA(t)
	logs := &bytes.Buffer{}
	f := &fixture{ca: trustedCA, audit: &recordingAudit{}, logs: logs}
	f.config = issuance.Config{
		Signer:       trustedCA,
		Serials:      trustedCA,
		KeyValidator: goodkey.New(goodkey.DefaultPolicy()),
		Linter:       lint,
		AuditLogger:  f.audit,
		Logger:       slog.New(slog.NewTextHandler(logs, nil)),
	}
	return f
}

func (f *fixture) issuer(t *testing.T) *issuance.Issuer {
	t.Helper()
	iss, err := issuance.New(f.config)
	require.NoError(t, err)
	return iss
}

func newTestCA(t *testing.T) ca.TrustedCA {
	t.Helper()
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{Backend: swBackend, CertStorage: storage.NewMemory()})
	require.NoError(t, err)
	certStore, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)

	config := ca.DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Issuance Test CA"
	config.Identity[0].Keys[0].KeyType = "CA"
	trustedCA, err := ca.NewFromMultiIdentityConfig(&ca.MultiIdentityParams{
		Config:   config,
		KeyStore: backend,
		BackendForStore: func(string, types.StoreType) (xkms.Backend, error) {
			return backend, nil
		},
		RevocationStore: storage.NewMemory(),
		CertStore:       certStore,
		Profiles:        ca.NewDefaultProfileRegistry(),
	})
	require.NoError(t, err)
	require.NoError(t, trustedCA.Init(context.Background()))
	return trustedCA
}

func newRequest(t *testing.T, curve elliptic.Curve, cn string) *issuance.Request {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return &issuance.Request{
		CSR:      csr,
		Options:  ca.SignOptions{TenantID: testTenant},
		Actor:    "account:1",
		Resource: "order:1",
	}
}

func hasExtension(cert *x509.Certificate, id asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(id) {
			return true
		}
	}
	return false
}

func TestNewRequiresEveryDependency(t *testing.T) {
	valid := issuance.Config{
		Signer:       signerFunc(nil),
		Serials:      serialFunc(nil),
		KeyValidator: goodkey.New(goodkey.DefaultPolicy()),
		Linter:       lintFunc(cleanLint),
		AuditLogger:  &recordingAudit{},
		Logger:       slog.Default(),
	}
	_, err := issuance.New(valid)
	require.NoError(t, err)

	for name, clear := range map[string]func(*issuance.Config){
		"Signer":       func(c *issuance.Config) { c.Signer = nil },
		"Serials":      func(c *issuance.Config) { c.Serials = nil },
		"KeyValidator": func(c *issuance.Config) { c.KeyValidator = nil },
		"Linter":       func(c *issuance.Config) { c.Linter = nil },
		"AuditLogger":  func(c *issuance.Config) { c.AuditLogger = nil },
		"Logger":       func(c *issuance.Config) { c.Logger = nil },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			clear(&config)
			_, err := issuance.New(config)
			require.ErrorIs(t, err, issuance.ErrInvalidConfig)
			assert.Contains(t, err.Error(), name)
		})
	}
}

func TestIssueSignsPrecertificateThenCertificate(t *testing.T) {
	f := newFixture(t, lintFunc(cleanLint))
	req := newRequest(t, elliptic.P256(), "issue.example.com")

	result, err := f.issuer(t).Issue(context.Background(), req)
	require.NoError(t, err)

	assert.True(t, hasExtension(result.Precertificate, ct.OIDPrecertPoison))
	assert.False(t, hasExtension(result.Certificate, ct.OIDPrecertPoison))
	assert.Equal(t, 0, result.Precertificate.SerialNumber.Cmp(result.Certificate.SerialNumber))
	assert.Equal(t, result.Precertificate.NotBefore, result.Certificate.NotBefore)
	assert.Equal(t, result.Precertificate.NotAfter, result.Certificate.NotAfter)
	assert.Equal(t, []string{"issue.example.com"}, result.Certificate.DNSNames)

	precerts := f.audit.events(audit.EventPrecertificateSigned)
	require.Len(t, precerts, 1)
	assert.Equal(t, result.Certificate.SerialNumber.Text(16), precerts[0].details["serial"])
	assert.Empty(t, f.audit.events(audit.EventCertificateLinted), "a clean lint is not audited")
}

func TestIssueLintsBothCertificatesBeforeSigning(t *testing.T) {
	var linted [][]byte
	f := newFixture(t, lintFunc(func(der []byte) (*linter.Result, error) {
		linted = append(linted, der)
		return &linter.Result{}, nil
	}))

	result, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "lint.example.com"))
	require.NoError(t, err)

	require.Len(t, linted, 2)
	precertLint, err := x509.ParseCertificate(linted[0])
	require.NoError(t, err)
	certLint, err := x509.ParseCertificate(linted[1])
	require.NoError(t, err)
	assert.Equal(t, result.Precertificate.RawTBSCertificate, precertLint.RawTBSCertificate)
	assert.Equal(t, result.Certificate.RawTBSCertificate, certLint.RawTBSCertificate)
}

func TestIssueRefusesWeakKey(t *testing.T) {
	f := newFixture(t, lintFunc(cleanLint))

	_, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P224(), "weak.example.com"))
	require.ErrorIs(t, err, issuance.ErrBadPublicKey)
	require.ErrorIs(t, err, goodkey.ErrCurveNotAllowed)
	assert.Empty(t, f.audit.events(audit.EventPrecertificateSigned))
}

func TestIssueRefusesNilRequest(t *testing.T) {
	iss := newFixture(t, lintFunc(cleanLint)).issuer(t)

	_, err := iss.Issue(context.Background(), nil)
	require.ErrorIs(t, err, issuance.ErrNilRequest)
	_, err = iss.Issue(context.Background(), &issuance.Request{})
	require.ErrorIs(t, err, issuance.ErrNilRequest)
}

func TestIssueRefusesLintErrors(t *testing.T) {
	refusal := &linter.Result{Errors: []linter.Finding{{Lint: "e_test", Status: "error"}}}
	f := newFixture(t, lintFunc(func([]byte) (*linter.Result, error) {
		return refusal, linter.ErrRefused
	}))
	req := newRequest(t, elliptic.P256(), "refused.example.com")

	_, err := f.issuer(t).Issue(context.Background(), req)
	require.ErrorIs(t, err, issuance.ErrPrecertificate)
	require.ErrorIs(t, err, ca.ErrLintFailed)
	require.ErrorIs(t, err, linter.ErrRefused)

	linted := f.audit.events(audit.EventCertificateLinted)
	require.Len(t, linted, 1)
	assert.Equal(t, audit.ResultFailure, linted[0].result)
	assert.Equal(t, "e_test", linted[0].details["errors"])
	assert.Empty(t, f.audit.events(audit.EventPrecertificateSigned), "nothing is signed after a refusal")
	assert.Contains(t, f.logs.String(), "lint refused certificate")
}

func TestIssueRefusesLintErrorOfFinalCertificate(t *testing.T) {
	calls := 0
	f := newFixture(t, lintFunc(func([]byte) (*linter.Result, error) {
		calls++
		if calls == 1 {
			return &linter.Result{}, nil
		}
		return &linter.Result{Errors: []linter.Finding{{Lint: "e_final", Status: "fatal"}}}, linter.ErrRefused
	}))

	_, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "final.example.com"))
	require.ErrorIs(t, err, issuance.ErrCertificate)
	require.ErrorIs(t, err, linter.ErrRefused)
}

func TestIssueLogsAndAuditsLintWarnings(t *testing.T) {
	warnings := &linter.Result{Warnings: []linter.Finding{{Lint: "w_test", Status: "warn", Details: "advice"}}}
	f := newFixture(t, lintFunc(func([]byte) (*linter.Result, error) { return warnings, nil }))

	result, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "warn.example.com"))
	require.NoError(t, err)
	require.NotNil(t, result.Certificate)

	linted := f.audit.events(audit.EventCertificateLinted)
	require.Len(t, linted, 2, "the precertificate and the certificate are each audited")
	for i, stage := range []string{"precertificate", "certificate"} {
		assert.Equal(t, audit.ResultSuccess, linted[i].result)
		assert.Equal(t, stage, linted[i].details["stage"])
		assert.Equal(t, "w_test: advice", linted[i].details["warnings"])
	}
	assert.Contains(t, f.logs.String(), "lint warnings")
}

func TestIssueStopsWhenLintAuditFails(t *testing.T) {
	warnings := &linter.Result{Warnings: []linter.Finding{{Lint: "w_test", Status: "warn"}}}
	f := newFixture(t, lintFunc(func([]byte) (*linter.Result, error) { return warnings, nil }))
	errStore := errors.New("audit store down")
	f.audit.err = errStore

	_, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "audit.example.com"))
	require.ErrorIs(t, err, issuance.ErrAudit)
	require.ErrorIs(t, err, errStore)
	require.ErrorIs(t, err, ca.ErrLintFailed)
}

func TestIssueStopsWhenPrecertificateAuditFails(t *testing.T) {
	f := newFixture(t, lintFunc(cleanLint))
	errStore := errors.New("audit store down")
	f.audit.err = errStore

	_, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "precert-audit.example.com"))
	require.ErrorIs(t, err, issuance.ErrAudit)
	require.ErrorIs(t, err, errStore)
}

func TestIssueRefusalAuditFailureKeepsBothCauses(t *testing.T) {
	f := newFixture(t, lintFunc(func([]byte) (*linter.Result, error) { return nil, linter.ErrRefused }))
	errStore := errors.New("audit store down")
	f.audit.err = errStore

	_, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "both.example.com"))
	require.ErrorIs(t, err, linter.ErrRefused)
	require.ErrorIs(t, err, issuance.ErrAudit)
	require.ErrorIs(t, err, errStore)
}

func TestIssueReportsSerialReservationFailure(t *testing.T) {
	f := newFixture(t, lintFunc(cleanLint))
	errSerials := errors.New("serial store down")
	f.config.Serials = serialFunc(func(context.Context) (*big.Int, error) { return nil, errSerials })

	_, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "serial.example.com"))
	require.ErrorIs(t, err, issuance.ErrSerialReservation)
	require.ErrorIs(t, err, errSerials)
}

func TestIssueRefusesMismatchedCertificate(t *testing.T) {
	f := newFixture(t, lintFunc(cleanLint))
	signer := f.config.Signer
	f.config.Signer = signerFunc(func(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
		if !opts.Precertificate {
			// The final certificate gains a name its precertificate lacked.
			opts.SANS = &ca.SubjectAlternativeNames{DNS: []string{"extra.example.com"}}
		}
		return signer.SignCSR(ctx, csrPEM, opts)
	})

	_, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "mismatch.example.com"))
	require.ErrorIs(t, err, issuance.ErrTBSMismatch)
}

func TestIssueAcceptsSCTListDifference(t *testing.T) {
	f := newFixture(t, lintFunc(cleanLint))
	signer := f.config.Signer
	f.config.Signer = signerFunc(func(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
		if !opts.Precertificate {
			// RFC 6962 §3.3: the final certificate carries the SCT list.
			opts.ExtraExtensions = append(opts.ExtraExtensions, pkix.Extension{Id: ct.OIDSCTList, Value: []byte{0x04, 0x00}})
		}
		return signer.SignCSR(ctx, csrPEM, opts)
	})

	result, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "sct.example.com"))
	require.NoError(t, err)
	assert.True(t, hasExtension(result.Certificate, ct.OIDSCTList))
}

func TestIssueReportsSignerFailures(t *testing.T) {
	errSign := errors.New("signer down")
	for name, tt := range map[string]struct {
		failPrecert bool
		want        error
	}{
		"precertificate": {failPrecert: true, want: issuance.ErrPrecertificate},
		"certificate":    {failPrecert: false, want: issuance.ErrCertificate},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, lintFunc(cleanLint))
			signer := f.config.Signer
			f.config.Signer = signerFunc(func(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
				if opts.Precertificate == tt.failPrecert {
					return nil, errSign
				}
				return signer.SignCSR(ctx, csrPEM, opts)
			})

			_, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "signer.example.com"))
			require.ErrorIs(t, err, tt.want)
			require.ErrorIs(t, err, errSign)
		})
	}
}

func TestIssueRefusesMalformedTBS(t *testing.T) {
	f := newFixture(t, lintFunc(cleanLint))
	signer := f.config.Signer
	f.config.Signer = signerFunc(func(ctx context.Context, csrPEM []byte, opts *ca.SignOptions) (*x509.Certificate, error) {
		cert, err := signer.SignCSR(ctx, csrPEM, opts)
		if err != nil || opts.Precertificate {
			return cert, err
		}
		broken := *cert
		broken.RawTBSCertificate = append(append([]byte{}, cert.RawTBSCertificate...), 0x00)
		return &broken, nil
	})

	_, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "malformed.example.com"))
	require.ErrorIs(t, err, issuance.ErrTBSMismatch)
}

func TestIssueKeepsCallerNotBefore(t *testing.T) {
	f := newFixture(t, lintFunc(cleanLint))
	req := newRequest(t, elliptic.P256(), "notbefore.example.com")
	req.Options.NotBefore = time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	result, err := f.issuer(t).Issue(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, req.Options.NotBefore.Equal(result.Certificate.NotBefore))
	assert.Nil(t, req.Options.Serial, "the caller's options are not modified")
}

// TestIssueWithZlint issues through the real zlint registry under
// linter.PrivatePKIConfig, the configuration of the ACME CA: its default
// leaf profile lints free of errors.
func TestIssueWithZlint(t *testing.T) {
	lint, err := linter.New(linter.PrivatePKIConfig())
	require.NoError(t, err)
	f := newFixture(t, lint)

	result, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "zlint.example.com"))
	require.NoError(t, err)
	assert.Equal(t, x509.KeyUsageDigitalSignature, result.Certificate.KeyUsage)
}

// TestIssueWithZlintRefusesBRDefaults shows the strict registry refusing the
// same leaf: lint errors stop issuance before anything is signed.
func TestIssueWithZlintRefusesBRDefaults(t *testing.T) {
	lint, err := linter.New(linter.Config{})
	require.NoError(t, err)
	f := newFixture(t, lint)

	_, err = f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "strict.example.com"))
	require.ErrorIs(t, err, linter.ErrRefused)
	assert.Empty(t, f.audit.events(audit.EventPrecertificateSigned))
}

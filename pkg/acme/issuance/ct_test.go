package issuance_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ct/cttest"
	"github.com/jeremyhahn/go-xkms/pkg/acme/issuance"
)

// ctFixture is a fixture whose Issuer submits to logs under policy.
func ctFixture(t *testing.T, policy ct.PolicyConfig) *fixture {
	t.Helper()
	f := newFixture(t, lintFunc(cleanLint))
	ctPolicy, err := ct.NewCTPolicy(policy, ct.NewHTTPLogSubmitter(nil))
	require.NoError(t, err)
	f.config.CT = ctPolicy
	f.config.Chain = f.ca
	return f
}

// oneLog is a policy needing one SCT from logs.
func oneLog(logs ...ct.LogGroup) ct.PolicyConfig {
	return ct.PolicyConfig{LogGroups: logs, MinSCTs: 1, MinOperators: 1, SubmissionTimeout: time.Minute}
}

func embeddedSCTs(t *testing.T, cert *x509.Certificate) []ct.SignedCertificateTimestamp {
	t.Helper()
	ext := ct.GetSCTListExtension(cert.Extensions)
	require.NotNil(t, ext, "the certificate carries the SCT list extension")
	assert.False(t, ext.Critical, "RFC 6962 §3.3: the SCT list extension is not critical")
	scts, err := ct.ParseSCTList(ext.Value)
	require.NoError(t, err)
	return scts
}

func TestIssueEmbedsVerifiedSCTs(t *testing.T) {
	log := cttest.NewLog(t, cttest.Issues)
	group := log.Group("log-a", "operator-a")
	f := ctFixture(t, oneLog(group))
	req := newRequest(t, elliptic.P256(), "ct.example.com")

	result, err := f.issuer(t).Issue(context.Background(), req)
	require.NoError(t, err)

	caCert, err := f.ca.CACertificate()
	require.NoError(t, err)
	chains := log.Submitted()
	require.Len(t, chains, 1)
	assert.Equal(t, result.Precertificate.Raw, chains[0][0], "the precertificate leads the chain")
	assert.Equal(t, caCert.Raw, chains[0][1], "its issuer follows it")

	scts := embeddedSCTs(t, result.Certificate)
	require.Len(t, scts, 1)
	sct := scts[0]
	assert.Equal(t, log.ID(), sct.LogID)
	require.NoError(t, ct.VerifySCT(&sct, group, result.Precertificate.Raw, [][]byte{caCert.Raw}))

	// RFC 6962 §3.2: the SCT signs the final certificate's tbsCertificate
	// without the SCT list, under the issuer's key hash.
	tbs, err := cttest.WithoutExtension(result.Certificate.RawTBSCertificate, ct.OIDSCTList)
	require.NoError(t, err)
	digest := sha256.Sum256(cttest.SignedEntry(sct.Timestamp, sha256.Sum256(caCert.RawSubjectPublicKeyInfo), tbs))
	assert.True(t, ecdsa.VerifyASN1(log.PublicKey(), digest[:], sct.Signature.Signature))

	assert.Equal(t, 0, result.Precertificate.SerialNumber.Cmp(result.Certificate.SerialNumber))
	assert.Equal(t, result.Precertificate.DNSNames, result.Certificate.DNSNames)
	assert.Equal(t, []string{"ct.example.com"}, result.Certificate.DNSNames)
	assert.Equal(t, result.Precertificate.RawSubject, result.Certificate.RawSubject)
	assert.False(t, hasExtension(result.Certificate, ct.OIDPrecertPoison))
	assert.Empty(t, req.Options.ExtraExtensions, "the request's extensions are left as they were")

	events := f.audit.events(audit.EventCertificateTransparency)
	require.Len(t, events, 1)
	assert.Equal(t, audit.ResultSuccess, events[0].result)
	assert.Equal(t, 1, events[0].details["scts"])
	assert.Empty(t, events[0].details["failed_logs"])
}

func TestIssueWithoutCTEmbedsNoSCTs(t *testing.T) {
	f := newFixture(t, lintFunc(cleanLint))

	result, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "no-ct.example.com"))
	require.NoError(t, err)

	assert.False(t, ct.HasSCTList(result.Certificate.Extensions))
	assert.Empty(t, f.audit.events(audit.EventCertificateTransparency))
}

func TestIssueProceedsPastAFailedLog(t *testing.T) {
	tests := []struct {
		name string
		mode cttest.Mode
		want error
	}{
		{"refusing log", cttest.Refuses, nil},
		{"bad signature", cttest.BadSignature, ct.ErrInvalidSignature},
		{"timed-out log", cttest.Hangs, ct.ErrCTSubmissionTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			good := cttest.NewLog(t, cttest.Issues)
			failing := cttest.NewLog(t, tt.mode)
			policy := oneLog(good.Group("good", "operator-a"), failing.Group("failing", "operator-b"))
			policy.SubmissionTimeout = 500 * time.Millisecond
			f := ctFixture(t, policy)

			result, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "partial.example.com"))
			require.NoError(t, err, "one verified SCT meets the policy")

			scts := embeddedSCTs(t, result.Certificate)
			require.Len(t, scts, 1)
			assert.Equal(t, good.ID(), scts[0].LogID, "the failed log's SCT is not embedded")

			events := f.audit.events(audit.EventCertificateTransparency)
			require.Len(t, events, 1)
			failed, ok := events[0].details["failed_logs"].([]string)
			require.True(t, ok)
			require.Len(t, failed, 1)
			assert.Contains(t, failed[0], "failing")
			assert.Contains(t, f.logs.String(), "certificate transparency log failed")
			if tt.want != nil {
				assert.Contains(t, failed[0], tt.want.Error())
			}
		})
	}
}

func TestIssueRefusesUnmetCTPolicy(t *testing.T) {
	tests := []struct {
		name string
		mode cttest.Mode
		want error
	}{
		{"refusing log", cttest.Refuses, nil},
		{"bad signature", cttest.BadSignature, ct.ErrInvalidSignature},
		{"timed-out log", cttest.Hangs, ct.ErrCTSubmissionTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := cttest.NewLog(t, tt.mode)
			policy := oneLog(log.Group("only", "operator-a"))
			policy.SubmissionTimeout = 500 * time.Millisecond
			f := ctFixture(t, policy)

			result, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "refused.example.com"))
			require.ErrorIs(t, err, issuance.ErrCertificateTransparency)
			assert.Nil(t, result)

			var submission *ct.CTSubmissionError
			require.ErrorAs(t, err, &submission)
			assert.Equal(t, "only", submission.LogName)
			if tt.want != nil {
				assert.ErrorIs(t, err, tt.want)
			}

			events := f.audit.events(audit.EventCertificateTransparency)
			require.Len(t, events, 1)
			assert.Equal(t, audit.ResultFailure, events[0].result)
			assert.Contains(t, f.logs.String(), "certificate transparency refused issuance")
		})
	}
}

// chainFunc is an issuance.IssuerChain backed by a function.
type chainFunc func() ([]byte, error)

func (f chainFunc) CABundle() ([]byte, error) { return f() }

func TestIssueReportsIssuingChainFailures(t *testing.T) {
	errBundle := errors.New("bundle unavailable")
	tests := []struct {
		name  string
		chain chainFunc
	}{
		{"bundle error", func() ([]byte, error) { return nil, errBundle }},
		{"empty bundle", func() ([]byte, error) { return []byte("no certificates"), nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := cttest.NewLog(t, cttest.Issues)
			f := ctFixture(t, oneLog(log.Group("log-a", "operator-a")))
			f.config.Chain = tt.chain

			_, err := f.issuer(t).Issue(context.Background(), newRequest(t, elliptic.P256(), "chain.example.com"))
			require.ErrorIs(t, err, issuance.ErrCertificateTransparency)
			assert.Empty(t, log.Submitted(), "nothing is submitted without a chain")
		})
	}
}

// newTenantIssuer returns a tenant CA key and its certificate.
func newTenantIssuer(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "Tenant Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

func TestIssueSubmitsTenantIssuerFirst(t *testing.T) {
	log := cttest.NewLog(t, cttest.Issues)
	group := log.Group("log-a", "operator-a")
	f := ctFixture(t, oneLog(group))
	caCert, err := f.ca.CACertificate()
	require.NoError(t, err)
	tenantKey, tenantCert := newTenantIssuer(t)
	req := newRequest(t, elliptic.P256(), "tenant.example.com")
	req.Options.Signer = tenantKey
	req.Options.IssuerCert = tenantCert

	result, err := f.issuer(t).Issue(context.Background(), req)
	require.NoError(t, err)

	chains := log.Submitted()
	require.Len(t, chains, 1)
	assert.Equal(t, [][]byte{result.Precertificate.Raw, tenantCert.Raw, caCert.Raw}, chains[0])
	scts := embeddedSCTs(t, result.Certificate)
	require.Len(t, scts, 1)
	assert.NoError(t, ct.VerifySCT(&scts[0], group, result.Precertificate.Raw, [][]byte{tenantCert.Raw}),
		"the SCT is over the tenant issuer's key hash")
}

func TestNewRequiresChainWithCT(t *testing.T) {
	log := cttest.NewLog(t, cttest.Issues)
	f := ctFixture(t, oneLog(log.Group("log-a", "operator-a")))
	f.config.Chain = nil

	_, err := issuance.New(f.config)
	require.ErrorIs(t, err, issuance.ErrInvalidConfig)
	assert.Contains(t, err.Error(), "Chain")
}

// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build qrdb_vlog

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
)

// tlogFixture is a CA wired to a transparency log on a real in-memory
// go-qrdb node. ctx carries the node's service principal, which holds the
// vlog actions the CA's appends need.
type tlogFixture struct {
	ca      *CA
	log     *tlog.Log
	ctx     context.Context
	missing *tlog.Log
}

// newTLogFixture builds a CA and a log whose heads the CA's own key signs,
// and sets the log on the CA. missing is a log of the same node that was
// never created: every append to it fails at the node.
func newTLogFixture(t *testing.T) *tlogFixture {
	t.Helper()
	c := setupTestCA(t)
	caCert, err := c.CACertificate()
	require.NoError(t, err)
	keys, err := qrdbsdk.NewCAKeyStaticProvider(c, caCert)
	require.NoError(t, err)
	signers, err := tlog.NewHeadSignerProvider(keys, "ca-tlog")
	require.NoError(t, err)

	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false
	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil,
		serviceprincipal.Option(), qrdbnode.WithHeadSignerProvider(signers))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	ctx, err := node.ServiceContext(t.Context())
	require.NoError(t, err)

	client := node.Client().Vlog()
	l, err := tlog.Create(ctx, client, tlog.Config{Name: "certs", Origin: "ca.test/tlog"}, signers)
	require.NoError(t, err)
	v, err := signers.Verifier(ctx)
	require.NoError(t, err)
	missing, err := tlog.Open(client, tlog.Config{Name: "missing", Origin: "ca.test/tlog"}, v)
	require.NoError(t, err)

	c.SetTransparencyLog(l)
	return &tlogFixture{ca: c, log: l, ctx: ctx, missing: missing}
}

// size returns the log's current tree size.
func (f *tlogFixture) size(t *testing.T) uint64 {
	t.Helper()
	head, err := f.log.SignedTreeHead(f.ctx)
	require.NoError(t, err)
	return head.Checkpoint.Size
}

// requireOneEntry checks the log grew by exactly one entry since before,
// that the entry is want, and that its inclusion proof verifies against
// the signed tree head.
func (f *tlogFixture) requireOneEntry(t *testing.T, before uint64, want tlog.Entry) {
	t.Helper()
	head, err := f.log.SignedTreeHead(f.ctx)
	require.NoError(t, err)
	require.Equal(t, before+1, head.Checkpoint.Size, "exactly one entry appended")

	got, body, err := f.log.Entry(f.ctx, before)
	require.NoError(t, err)
	require.Equal(t, want, got)

	hashes, err := f.log.InclusionProof(f.ctx, before, head.Checkpoint.Size)
	require.NoError(t, err)
	leaf := rfc6962.DefaultHasher.HashLeaf(body)
	require.NoError(t, proof.VerifyInclusion(rfc6962.DefaultHasher, before, head.Checkpoint.Size, leaf, hashes, head.Checkpoint.Hash))
}

// certIssued is the entry the CA appends for cert.
func certIssued(cert *x509.Certificate, profile, tenant string) tlog.CertIssued {
	return tlog.CertIssued{CertSHA256: sha256.Sum256(cert.Raw), Serial: cert.SerialNumber, Profile: profile, Tenant: tenant}
}

func newTLogTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func parsePEMCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func TestTransparencyLog_IssuePathsAppendOnce(t *testing.T) {
	f := newTLogFixture(t)

	// Each path issues one certificate and returns it with the profile and
	// tenant its entry must carry.
	paths := map[string]func(t *testing.T) (*x509.Certificate, string, string){
		"IssueCertificate": func(t *testing.T) (*x509.Certificate, string, string) {
			issued, err := f.ca.IssueCertificate(f.ctx, &CertificateRequest{Subject: Subject{CommonName: "tlog-issue"}, Valid: 30, TenantID: testTenant})
			require.NoError(t, err)
			return issued.Certificate, "tls-leaf", testTenant
		},
		"IssueCertificateWithProfile": func(t *testing.T) (*x509.Certificate, string, string) {
			issued, err := f.ca.IssueCertificateWithProfile(f.ctx, &CertificateRequest{Subject: Subject{CommonName: "tlog-profile"}, Valid: 30, TenantID: testTenant}, "client")
			require.NoError(t, err)
			return issued.Certificate, "client", testTenant
		},
		"IssueCertificateForKey": func(t *testing.T) (*x509.Certificate, string, string) {
			key := newTLogTestKey(t)
			issued, err := f.ca.IssueCertificateForKey(f.ctx, &CertificateRequest{Subject: Subject{CommonName: "tlog-for-key"}, Valid: 30, TenantID: testTenant}, &key.PublicKey)
			require.NoError(t, err)
			return issued.Certificate, "tls-leaf", testTenant
		},
		"IssueCertificateRaw": func(t *testing.T) (*x509.Certificate, string, string) {
			certPEM, _, _, _, err := f.ca.IssueCertificateRaw(f.ctx, "tlog-raw", "Test Org", []string{"DNS:tlog-raw.example.com"}, 30, "server", "", testTenant)
			require.NoError(t, err)
			return parsePEMCert(t, certPEM), "server", testTenant
		},
		"IssueEKCertificateRaw": func(t *testing.T) (*x509.Certificate, string, string) {
			key := newTLogTestKey(t)
			pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			require.NoError(t, err)
			der, err := f.ca.IssueEKCertificateRaw(f.ctx, "tlog-ek", "Test Org", pubDER, testTenant)
			require.NoError(t, err)
			cert, err := x509.ParseCertificate(der)
			require.NoError(t, err)
			return cert, ProfileNameTCGEndorsementKey, testTenant
		},
		"IssueSubordinateCA": func(t *testing.T) (*x509.Certificate, string, string) {
			key := newTLogTestKey(t)
			cert, err := f.ca.IssueSubordinateCA(f.ctx, &SubordinateCARequest{
				Subject:         pkix.Name{CommonName: "tlog-subordinate"},
				PublicKey:       key.Public(),
				NameConstraints: &NameConstraints{Critical: true, PermittedDNSDomains: []string{"example.com"}},
				Validity:        30 * 24 * time.Hour,
			})
			require.NoError(t, err)
			return cert, ProfileNameCA, qrdbsdk.SystemTenantID
		},
	}
	for name, issue := range paths {
		t.Run(name, func(t *testing.T) {
			before := f.size(t)
			cert, profile, tenant := issue(t)
			f.requireOneEntry(t, before, certIssued(cert, profile, tenant))
		})
	}
}

func TestTransparencyLog_RevokePathsAppendOnce(t *testing.T) {
	f := newTLogFixture(t)
	issue := func(t *testing.T, cn string) *x509.Certificate {
		issued, err := f.ca.IssueCertificate(f.ctx, &CertificateRequest{Subject: Subject{CommonName: cn}, Valid: 30, TenantID: testTenant})
		require.NoError(t, err)
		return issued.Certificate
	}

	t.Run("Revoke", func(t *testing.T) {
		cert := issue(t, "tlog-revoke")
		before := f.size(t)
		require.NoError(t, f.ca.Revoke(f.ctx, cert.SerialNumber, 1))
		f.requireOneEntry(t, before, tlog.Revoked{Serial: cert.SerialNumber, Reason: 1})
	})
	t.Run("RevokeCert", func(t *testing.T) {
		cert := issue(t, "tlog-revoke-cert")
		before := f.size(t)
		require.NoError(t, f.ca.RevokeCert(f.ctx, cert, RevokeOptions{Reason: 4}))
		f.requireOneEntry(t, before, tlog.Revoked{Serial: cert.SerialNumber, Reason: 4})
	})
	t.Run("already revoked appends nothing", func(t *testing.T) {
		cert := issue(t, "tlog-revoke-twice")
		require.NoError(t, f.ca.Revoke(f.ctx, cert.SerialNumber, 0))
		before := f.size(t)
		require.ErrorIs(t, f.ca.Revoke(f.ctx, cert.SerialNumber, 0), ErrAlreadyRevoked)
		require.Equal(t, before, f.size(t))
	})
}

func TestTransparencyLog_AppendFailureFailsIssuance(t *testing.T) {
	f := newTLogFixture(t)
	f.ca.SetTransparencyLog(f.missing)

	_, err := f.ca.IssueCertificate(f.ctx, &CertificateRequest{Subject: Subject{CommonName: "tlog-fail"}, Valid: 30, TenantID: testTenant})
	require.ErrorIs(t, err, ErrTransparencyLogAppend)
	require.ErrorIs(t, err, tlog.ErrLogRequest)
	_, err = f.ca.certStore.GetCertificate("tlog-fail")
	require.Error(t, err, "a certificate the log does not hold is never stored")

	key := newTLogTestKey(t)
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	der, err := f.ca.IssueEKCertificateRaw(f.ctx, "tlog-fail-ek", "Test Org", pubDER, testTenant)
	require.ErrorIs(t, err, ErrTransparencyLogAppend)
	require.Nil(t, der)
	_, err = f.ca.certStore.GetCertificate("tlog-fail-ek")
	require.Error(t, err)

	cert, err := f.ca.IssueSubordinateCA(f.ctx, &SubordinateCARequest{
		Subject:         pkix.Name{CommonName: "tlog-fail-subordinate"},
		PublicKey:       key.Public(),
		NameConstraints: &NameConstraints{Critical: true, PermittedDNSDomains: []string{"example.com"}},
		Validity:        30 * 24 * time.Hour,
	})
	require.ErrorIs(t, err, ErrTransparencyLogAppend)
	require.Nil(t, cert)
}

func TestTransparencyLog_AppendFailureLeavesRevocation(t *testing.T) {
	f := newTLogFixture(t)
	issue := func(t *testing.T, cn string) *x509.Certificate {
		issued, err := f.ca.IssueCertificate(f.ctx, &CertificateRequest{Subject: Subject{CommonName: cn}, Valid: 30, TenantID: testTenant})
		require.NoError(t, err)
		return issued.Certificate
	}
	revoke := issue(t, "tlog-revoke-fail")
	revokeCert := issue(t, "tlog-revoke-cert-fail")
	f.ca.SetTransparencyLog(f.missing)

	err := f.ca.Revoke(f.ctx, revoke.SerialNumber, 1)
	require.ErrorIs(t, err, ErrTransparencyLogEntryMissing)
	require.ErrorIs(t, err, tlog.ErrLogRequest)
	revoked, err := f.ca.IsRevoked(revoke.SerialNumber)
	require.NoError(t, err)
	require.True(t, revoked, "a revocation is never undone")

	err = f.ca.RevokeCert(f.ctx, revokeCert, RevokeOptions{Reason: 1, DeleteKeys: true})
	require.ErrorIs(t, err, ErrTransparencyLogEntryMissing)
	revoked, err = f.ca.IsRevoked(revokeCert.SerialNumber)
	require.NoError(t, err)
	require.True(t, revoked)
	_, err = f.ca.certStore.GetCertificate("tlog-revoke-cert-fail")
	require.Error(t, err, "the revocation's cleanup still runs")
}

func TestTransparencyLog_RevocationReasonOutOfRange(t *testing.T) {
	f := newTLogFixture(t)
	issued, err := f.ca.IssueCertificate(f.ctx, &CertificateRequest{Subject: Subject{CommonName: "tlog-reason"}, Valid: 30, TenantID: testTenant})
	require.NoError(t, err)
	before := f.size(t)

	err = f.ca.Revoke(f.ctx, issued.Certificate.SerialNumber, 256)
	require.ErrorIs(t, err, ErrTransparencyLogEntryMissing)
	require.Equal(t, before, f.size(t))
	revoked, err := f.ca.IsRevoked(issued.Certificate.SerialNumber)
	require.NoError(t, err)
	require.True(t, revoked)
}

func TestTransparencyLog_NoLogRecordsNothing(t *testing.T) {
	f := newTLogFixture(t)
	f.ca.SetTransparencyLog(nil)
	before := f.size(t)

	issued, err := f.ca.IssueCertificate(f.ctx, &CertificateRequest{Subject: Subject{CommonName: "tlog-none"}, Valid: 30, TenantID: testTenant})
	require.NoError(t, err)
	require.NoError(t, f.ca.Revoke(f.ctx, issued.Certificate.SerialNumber, 1))
	require.Equal(t, before, f.size(t))
	require.Nil(t, f.ca.currentTransparencyLog())
}

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

// go-qrdb serves verifiable logs only when built with its qrdb_vlog tag.
//go:build qrdb_vlog

package xkms_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tlogtest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// tlogPKI is a self-signed CA that signs the log's heads and issues the
// certificates the log records.
type tlogPKI struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTLogPKI(t *testing.T) *tlogPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tlog test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &tlogPKI{key: key, cert: cert}
}

// issue signs a leaf certificate for serial and returns it as the log's
// cert-issued entry.
func (p *tlogPKI) issue(t *testing.T, serial int64) tlog.CertIssued {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, leafKey.Public(), p.key)
	require.NoError(t, err)
	return tlog.CertIssued{CertSHA256: sha256.Sum256(der), Serial: big.NewInt(serial), Profile: "tls-leaf", Tenant: "tenant-a"}
}

// newTLogService returns a service reading a real log on an in-memory node,
// with one issued certificate already recorded.
func newTLogService(t *testing.T) (*xkms.XKMSService, *tlogtest.Fixture, *tlogPKI) {
	t.Helper()
	pki := newTLogPKI(t)
	f := tlogtest.New(t, pki.key, pki.cert)
	_, err := f.Log.AppendCertIssued(f.Ctx, pki.issue(t, 100))
	require.NoError(t, err)
	svc := &xkms.XKMSService{}
	svc.SetTransparencyLog(f.Log)
	return svc, f, pki
}

// The service serves the signed head, the entry an issuance appended, and
// inclusion and consistency proofs that verify against the heads it signed.
func TestGetTransparencyLog_HeadEntryAndProofsVerify(t *testing.T) {
	svc, f, pki := newTLogService(t)

	first, err := svc.GetTransparencyLogHead(f.Ctx, &transport.GetTransparencyLogHeadRequest{})
	require.NoError(t, err)
	require.Equal(t, tlogtest.Origin, first.Origin)
	require.Equal(t, uint64(1), first.Size)
	checkpoint, err := f.Log.VerifyCheckpoint(first.Checkpoint)
	require.NoError(t, err, "the head's checkpoint carries the CA's signature")
	require.Equal(t, first.RootHash, checkpoint.Hash)

	want := pki.issue(t, 101)
	_, err = f.Log.AppendCertIssued(f.Ctx, want)
	require.NoError(t, err)
	second, err := svc.GetTransparencyLogHead(f.Ctx, &transport.GetTransparencyLogHeadRequest{})
	require.NoError(t, err)
	require.Equal(t, uint64(2), second.Size)

	entry, err := svc.GetTransparencyLogEntry(f.Ctx, &transport.GetTransparencyLogEntryRequest{Index: 1})
	require.NoError(t, err)
	require.Equal(t, uint64(1), entry.Index)
	_, body, err := f.Log.Entry(f.Ctx, 1)
	require.NoError(t, err)
	require.Equal(t, body, entry.Entry, "the entry is the issuance's encoded record")

	inclusion, err := svc.GetTransparencyLogInclusionProof(f.Ctx, &transport.GetTransparencyLogInclusionProofRequest{Index: 1, TreeSize: 2})
	require.NoError(t, err)
	leaf := rfc6962.DefaultHasher.HashLeaf(entry.Entry)
	require.NoError(t, proof.VerifyInclusion(rfc6962.DefaultHasher, 1, 2, leaf, inclusion.Hashes, second.RootHash))

	consistency, err := svc.GetTransparencyLogConsistencyProof(f.Ctx, &transport.GetTransparencyLogConsistencyProofRequest{FirstSize: 1, SecondSize: 2})
	require.NoError(t, err)
	require.Equal(t, uint64(1), consistency.FirstSize)
	require.Equal(t, uint64(2), consistency.SecondSize)
	require.NoError(t, proof.VerifyConsistency(rfc6962.DefaultHasher, 1, 2, consistency.Hashes, first.RootHash, second.RootHash))
}

// Without a log every verb answers ErrTransparencyLogNotConfigured.
func TestGetTransparencyLog_NotConfigured(t *testing.T) {
	svc := &xkms.XKMSService{}
	ctx := t.Context()

	_, err := svc.GetTransparencyLogHead(ctx, &transport.GetTransparencyLogHeadRequest{})
	require.ErrorIs(t, err, xkms.ErrTransparencyLogNotConfigured)
	_, err = svc.GetTransparencyLogEntry(ctx, &transport.GetTransparencyLogEntryRequest{})
	require.ErrorIs(t, err, xkms.ErrTransparencyLogNotConfigured)
	_, err = svc.GetTransparencyLogInclusionProof(ctx, &transport.GetTransparencyLogInclusionProofRequest{Index: 0, TreeSize: 1})
	require.ErrorIs(t, err, xkms.ErrTransparencyLogNotConfigured)
	_, err = svc.GetTransparencyLogConsistencyProof(ctx, &transport.GetTransparencyLogConsistencyProofRequest{FirstSize: 1, SecondSize: 1})
	require.ErrorIs(t, err, xkms.ErrTransparencyLogNotConfigured)

	svc.SetTransparencyLog(nil)
	_, err = svc.GetTransparencyLogHead(ctx, &transport.GetTransparencyLogHeadRequest{})
	require.ErrorIs(t, err, xkms.ErrTransparencyLogNotConfigured, "nil removes the log")
}

// An index or size outside the signed tree head is ErrTransparencyLogRange.
func TestGetTransparencyLog_OutOfRange(t *testing.T) {
	svc, f, _ := newTLogService(t)

	tests := []struct {
		name string
		call func() error
	}{
		{"entry index at the tree size", func() error {
			_, err := svc.GetTransparencyLogEntry(f.Ctx, &transport.GetTransparencyLogEntryRequest{Index: 1})
			return err
		}},
		{"inclusion tree size zero", func() error {
			_, err := svc.GetTransparencyLogInclusionProof(f.Ctx, &transport.GetTransparencyLogInclusionProofRequest{Index: 0, TreeSize: 0})
			return err
		}},
		{"inclusion tree size beyond the head", func() error {
			_, err := svc.GetTransparencyLogInclusionProof(f.Ctx, &transport.GetTransparencyLogInclusionProofRequest{Index: 0, TreeSize: 2})
			return err
		}},
		{"inclusion index at the tree size", func() error {
			_, err := svc.GetTransparencyLogInclusionProof(f.Ctx, &transport.GetTransparencyLogInclusionProofRequest{Index: 1, TreeSize: 1})
			return err
		}},
		{"consistency first size zero", func() error {
			_, err := svc.GetTransparencyLogConsistencyProof(f.Ctx, &transport.GetTransparencyLogConsistencyProofRequest{FirstSize: 0, SecondSize: 1})
			return err
		}},
		{"consistency second below first", func() error {
			_, err := svc.GetTransparencyLogConsistencyProof(f.Ctx, &transport.GetTransparencyLogConsistencyProofRequest{FirstSize: 1, SecondSize: 0})
			return err
		}},
		{"consistency second beyond the head", func() error {
			_, err := svc.GetTransparencyLogConsistencyProof(f.Ctx, &transport.GetTransparencyLogConsistencyProofRequest{FirstSize: 1, SecondSize: 2})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, tt.call(), xkms.ErrTransparencyLogRange)
		})
	}
}

// A nil request is ErrNilRequest, before the log is consulted.
func TestGetTransparencyLog_NilRequest(t *testing.T) {
	svc := &xkms.XKMSService{}
	_, err := svc.GetTransparencyLogEntry(t.Context(), nil)
	require.ErrorIs(t, err, xkms.ErrNilRequest)
	_, err = svc.GetTransparencyLogInclusionProof(t.Context(), nil)
	require.ErrorIs(t, err, xkms.ErrNilRequest)
	_, err = svc.GetTransparencyLogConsistencyProof(t.Context(), nil)
	require.ErrorIs(t, err, xkms.ErrNilRequest)
}

// A read the node refuses (here a context without the service principal) is
// returned to the caller, not mapped to a range or configuration error.
func TestGetTransparencyLog_ReadRefused(t *testing.T) {
	svc, _, _ := newTLogService(t)
	ctx := t.Context()

	_, err := svc.GetTransparencyLogHead(ctx, &transport.GetTransparencyLogHeadRequest{})
	require.Error(t, err)
	require.NotErrorIs(t, err, xkms.ErrTransparencyLogRange)
	require.NotErrorIs(t, err, xkms.ErrTransparencyLogNotConfigured)
	_, err = svc.GetTransparencyLogEntry(ctx, &transport.GetTransparencyLogEntryRequest{})
	require.Error(t, err)
	_, err = svc.GetTransparencyLogInclusionProof(ctx, &transport.GetTransparencyLogInclusionProofRequest{TreeSize: 1})
	require.Error(t, err)
	_, err = svc.GetTransparencyLogConsistencyProof(ctx, &transport.GetTransparencyLogConsistencyProofRequest{FirstSize: 1, SecondSize: 1})
	require.Error(t, err)
}

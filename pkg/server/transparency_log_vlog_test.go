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

// go-qrdb serves verifiable logs only when built with its qrdb_vlog tag.
//go:build qrdb_vlog

package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tlogtest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// startTLogNode gives s a real in-memory embedded node with xkms's service
// principal and the given node options, as initEmbeddedQRDBNode builds it.
func startTLogNode(t *testing.T, s *Server, opts []qrdbnode.NodeOption) {
	t.Helper()
	s.qrdbNode = newTLogNode(t, append([]qrdbnode.NodeOption{serviceprincipal.Option()}, opts...))
}

// newTLogNode builds a real in-memory standalone node with exactly the given
// node options, so a test can leave the service principal out.
func newTLogNode(t *testing.T, opts []qrdbnode.NodeOption) *qrdbnode.Node {
	t.Helper()
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false
	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	return node
}

// The wired server's CA appends a cert-issued entry for every certificate
// it issues and a revoked entry for every revocation, each with an inclusion
// proof that verifies against the signed head. Both run on a bare context,
// which the node refuses: the entries are there only because the log carries
// the node's service principal.
func TestInitializeCA_TransparencyLogRecordsIssuanceAndRevocation(t *testing.T) {
	s := newTLogCAServer(t, true)
	opts, err := s.transparencyLogNodeOptions()
	require.NoError(t, err)
	startTLogNode(t, s, opts)
	require.NoError(t, s.initializeCA())

	ctx, err := s.qrdbNode.ServiceContext(context.Background())
	require.NoError(t, err)
	verifier, err := s.tlogSigners.Verifier(ctx)
	require.NoError(t, err)
	reader, err := tlog.Open(s.qrdbNode.Client().Vlog(),
		tlog.Config{Name: caTransparencyLogName, Origin: s.transparencyLogOrigin()}, verifier)
	require.NoError(t, err)
	before := tlogtest.Size(ctx, t, reader)

	_, err = reader.AppendCertIssued(context.Background(), tlog.CertIssued{})
	require.Error(t, err, "the node refuses an append without the service principal")

	issued, err := s.ca.IssueCertificate(context.Background(), &ca.CertificateRequest{
		Subject: ca.Subject{CommonName: "tlog-wired"}, Valid: 30, TenantID: "tenant-a"})
	require.NoError(t, err)
	cert := issued.Certificate
	tlogtest.RequireOneEntry(ctx, t, reader, before, tlog.CertIssued{
		CertSHA256: sha256.Sum256(cert.Raw), Serial: cert.SerialNumber, Profile: "tls-leaf", Tenant: "tenant-a"})

	before = tlogtest.Size(ctx, t, reader)
	require.NoError(t, s.ca.Revoke(context.Background(), cert.SerialNumber, 1))
	tlogtest.RequireOneEntry(ctx, t, reader, before, tlog.Revoked{Serial: cert.SerialNumber, Reason: 1})
}

// A restart opens the log it created rather than creating a second one.
func TestInitializeCA_TransparencyLogReopens(t *testing.T) {
	s := newTLogCAServer(t, true)
	opts, err := s.transparencyLogNodeOptions()
	require.NoError(t, err)
	startTLogNode(t, s, opts)
	require.NoError(t, s.initializeCA())
	require.NoError(t, s.openTransparencyLog(s.ca), "the second open finds the log")
}

// Switched on over a node built without the log's head signer, start-up
// fails with the typed error.
func TestInitializeCA_TransparencyLogNodeWithoutHeadSigner(t *testing.T) {
	s := newTLogCAServer(t, true)
	startTLogNode(t, s, nil)
	err := s.initializeCA()
	require.ErrorIs(t, err, ErrTransparencyLogUnavailable)
}

// TestInitializeCA_TransparencyLogNodeWithoutServicePrincipal proves start-up
// fails closed when the node has the head signer but no service principal:
// the CA could never append, so it must not start issuing unlogged.
func TestInitializeCA_TransparencyLogNodeWithoutServicePrincipal(t *testing.T) {
	s := newTLogCAServer(t, true)
	opts, err := s.transparencyLogNodeOptions()
	require.NoError(t, err)
	s.qrdbNode = newTLogNode(t, opts)

	err = s.initializeCA()
	var tlogErr *ErrTransparencyLog
	require.True(t, errors.As(err, &tlogErr), "got %v", err)
	require.ErrorIs(t, err, qrdbnode.ErrNoServicePrincipal)
	require.Equal(t, "open the CA log", tlogErr.Operation)
}

// TestOpenTransparencyLog_CAUnsupported proves a composed CA that is not a
// *ca.CA (here none at all) is refused before the head-signing key is bound
// to it, since nothing could record its issuance.
func TestOpenTransparencyLog_CAUnsupported(t *testing.T) {
	s := newTLogCAServer(t, true)
	opts, err := s.transparencyLogNodeOptions()
	require.NoError(t, err)
	startTLogNode(t, s, opts)

	err = s.openTransparencyLog(nil)
	require.ErrorIs(t, err, ErrTransparencyLogCAUnsupported)
	require.EqualError(t, err,
		"transparency log: failed to attach the CA log: "+ErrTransparencyLogCAUnsupported.Error())
}

// TestServiceTransparencyLog_AppendWithoutServiceContext proves an append
// whose call cannot carry the node's service principal is refused and leaves
// the log unchanged, so the CA's issuance or revocation fails closed.
func TestServiceTransparencyLog_AppendWithoutServiceContext(t *testing.T) {
	s := newTLogCAServer(t, true)
	opts, err := s.transparencyLogNodeOptions()
	require.NoError(t, err)
	startTLogNode(t, s, opts)
	require.NoError(t, s.initializeCA())

	ctx, err := s.qrdbNode.ServiceContext(context.Background())
	require.NoError(t, err)
	opened, err := tlog.OpenOrCreate(ctx, s.qrdbNode.Client().Vlog(),
		tlog.Config{Name: caTransparencyLogName, Origin: s.transparencyLogOrigin()}, s.tlogSigners)
	require.NoError(t, err)
	before := tlogtest.Size(ctx, t, opened)

	withoutPrincipal := newTLogNode(t, nil)
	l := &serviceTransparencyLog{log: opened, callContext: withoutPrincipal.ServiceContext}

	_, err = l.AppendCertIssued(context.Background(), tlog.CertIssued{Serial: big.NewInt(7)})
	require.ErrorIs(t, err, qrdbnode.ErrNoServicePrincipal)
	_, err = l.AppendRevoked(context.Background(), tlog.Revoked{Serial: big.NewInt(7), Reason: 1})
	require.ErrorIs(t, err, qrdbnode.ErrNoServicePrincipal)
	require.Equal(t, before, tlogtest.Size(ctx, t, opened), "a refused append records nothing")
}

// TestWireTransparencyLog_ServesReadsAsServicePrincipal proves the XKMSService
// the server composes serves the CA log it opened: a certificate the CA
// issues is the entry at the head, its inclusion proof verifies against the
// head, and the head before it is consistent with the head after. Every read
// runs on a bare context, which the node refuses: the reads succeed only
// because the log carries the node's service principal.
func TestWireTransparencyLog_ServesReadsAsServicePrincipal(t *testing.T) {
	s := newTLogCAServer(t, true)
	opts, err := s.transparencyLogNodeOptions()
	require.NoError(t, err)
	startTLogNode(t, s, opts)
	require.NoError(t, s.initializeCA())
	svc := &xkms.XKMSService{}
	s.wireTransparencyLog(svc)
	ctx := context.Background()

	_, err = s.ca.IssueCertificate(ctx, &ca.CertificateRequest{Subject: ca.Subject{CommonName: "tlog-before"}, Valid: 30, TenantID: "tenant-a"})
	require.NoError(t, err)
	before, err := svc.GetTransparencyLogHead(ctx, &transport.GetTransparencyLogHeadRequest{})
	require.NoError(t, err)
	require.Equal(t, s.transparencyLogOrigin(), before.Origin)

	issued, err := s.ca.IssueCertificate(ctx, &ca.CertificateRequest{Subject: ca.Subject{CommonName: "tlog-served"}, Valid: 30, TenantID: "tenant-a"})
	require.NoError(t, err)
	head, err := svc.GetTransparencyLogHead(ctx, &transport.GetTransparencyLogHeadRequest{})
	require.NoError(t, err)
	require.Equal(t, before.Size+1, head.Size)

	index := head.Size - 1
	entry, err := svc.GetTransparencyLogEntry(ctx, &transport.GetTransparencyLogEntryRequest{Index: index})
	require.NoError(t, err)
	got, body, err := s.tlogService.Entry(ctx, index)
	require.NoError(t, err)
	require.Equal(t, body, entry.Entry)
	logged, ok := got.(tlog.CertIssued)
	require.True(t, ok, "got %T", got)
	require.Equal(t, sha256.Sum256(issued.Certificate.Raw), logged.CertSHA256)

	inclusion, err := svc.GetTransparencyLogInclusionProof(ctx, &transport.GetTransparencyLogInclusionProofRequest{Index: index, TreeSize: head.Size})
	require.NoError(t, err)
	leaf := rfc6962.DefaultHasher.HashLeaf(entry.Entry)
	require.NoError(t, proof.VerifyInclusion(rfc6962.DefaultHasher, index, head.Size, leaf, inclusion.Hashes, head.RootHash))

	consistency, err := svc.GetTransparencyLogConsistencyProof(ctx, &transport.GetTransparencyLogConsistencyProofRequest{FirstSize: before.Size, SecondSize: head.Size})
	require.NoError(t, err)
	require.NoError(t, proof.VerifyConsistency(rfc6962.DefaultHasher, before.Size, head.Size, consistency.Hashes, before.RootHash, head.RootHash))
}

// TestServiceTransparencyLog_ReadWithoutServiceContext proves a read whose
// call cannot carry the node's service principal is refused.
func TestServiceTransparencyLog_ReadWithoutServiceContext(t *testing.T) {
	s := newTLogCAServer(t, true)
	opts, err := s.transparencyLogNodeOptions()
	require.NoError(t, err)
	startTLogNode(t, s, opts)
	require.NoError(t, s.initializeCA())
	l := &serviceTransparencyLog{log: s.tlogService.log, callContext: newTLogNode(t, nil).ServiceContext}
	ctx := context.Background()

	_, err = l.SignedTreeHead(ctx)
	require.ErrorIs(t, err, qrdbnode.ErrNoServicePrincipal)
	_, _, err = l.Entry(ctx, 0)
	require.ErrorIs(t, err, qrdbnode.ErrNoServicePrincipal)
	_, err = l.InclusionProof(ctx, 0, 1)
	require.ErrorIs(t, err, qrdbnode.ErrNoServicePrincipal)
	_, err = l.ConsistencyProof(ctx, 1, 1)
	require.ErrorIs(t, err, qrdbnode.ErrNoServicePrincipal)
}

// The log's default follows the build: this file builds with qrdb_vlog, so
// an unset switch is on.
func TestTransparencyLogEnabled_DefaultOnWithVlog(t *testing.T) {
	require.True(t, (&config.Config{}).TransparencyLogEnabled())
}

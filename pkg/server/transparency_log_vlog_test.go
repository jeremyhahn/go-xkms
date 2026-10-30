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
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tlogtest"
)

// startTLogNode gives s a real in-memory embedded node with xkms's service
// principal and the given node options, as initEmbeddedQRDBNode builds it.
func startTLogNode(t *testing.T, s *Server, opts []qrdbnode.NodeOption) {
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
	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil,
		append([]qrdbnode.NodeOption{serviceprincipal.Option()}, opts...)...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	s.qrdbNode = node
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

// The log's default follows the build: this file builds with qrdb_vlog, so
// an unset switch is on.
func TestTransparencyLogEnabled_DefaultOnWithVlog(t *testing.T) {
	require.True(t, (&config.Config{}).TransparencyLogEnabled())
}

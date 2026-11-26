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

// Package tlogtest runs the CA's transparency log (pkg/ca/tlog) on a real
// in-memory go-qrdb node for the tests of the packages that append to it.
// go-qrdb serves verifiable logs only when built with its qrdb_vlog tag, so
// every test that uses this package carries that tag.
package tlogtest

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
)

// Origin is the fixture log's checkpoint origin.
const Origin = "ca.test/tlog"

// Fixture is a created log and a log that was never created, both on one
// node and signed under one CA key.
type Fixture struct {
	// Log is the created log.
	Log *tlog.Log

	// Missing names a log that does not exist: every append to it fails.
	Missing *tlog.Log

	// Ctx carries the node's service principal, which holds the vlog
	// actions the log needs.
	Ctx context.Context
}

// New starts an in-memory node whose heads caKey signs as the CA certified
// by caCert, and creates the log "certs" on it.
func New(t *testing.T, caKey crypto.Signer, caCert *x509.Certificate) *Fixture {
	t.Helper()
	keys, err := qrdbsdk.NewCAKeyStaticProvider(caKey, caCert)
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
	l, err := tlog.Create(ctx, client, tlog.Config{Name: "certs", Origin: Origin}, signers)
	require.NoError(t, err)
	verifier, err := signers.Verifier(ctx)
	require.NoError(t, err)
	missing, err := tlog.Open(client, tlog.Config{Name: "missing", Origin: Origin}, verifier)
	require.NoError(t, err)
	return &Fixture{Log: l, Missing: missing, Ctx: ctx}
}

// Size returns the log's current tree size.
func (f *Fixture) Size(t *testing.T) uint64 {
	t.Helper()
	return Size(f.Ctx, t, f.Log)
}

// RequireOneEntry checks the log grew by exactly one entry since before,
// that the entry is want, and that its inclusion proof verifies against the
// signed tree head.
func (f *Fixture) RequireOneEntry(t *testing.T, before uint64, want tlog.Entry) {
	t.Helper()
	RequireOneEntry(f.Ctx, t, f.Log, before, want)
}

// Size returns l's current tree size.
func Size(ctx context.Context, t *testing.T, l *tlog.Log) uint64 {
	t.Helper()
	head, err := l.SignedTreeHead(ctx)
	require.NoError(t, err)
	return head.Checkpoint.Size
}

// RequireOneEntry checks l grew by exactly one entry since before, that the
// entry is want, and that its inclusion proof verifies against l's signed
// tree head.
func RequireOneEntry(ctx context.Context, t *testing.T, l *tlog.Log, before uint64, want tlog.Entry) {
	t.Helper()
	head, err := l.SignedTreeHead(ctx)
	require.NoError(t, err)
	require.Equal(t, before+1, head.Checkpoint.Size, "exactly one entry appended")

	got, body, err := l.Entry(ctx, before)
	require.NoError(t, err)
	require.Equal(t, want, got)

	hashes, err := l.InclusionProof(ctx, before, head.Checkpoint.Size)
	require.NoError(t, err)
	leaf := rfc6962.DefaultHasher.HashLeaf(body)
	require.NoError(t, proof.VerifyInclusion(rfc6962.DefaultHasher, before, head.Checkpoint.Size, leaf, hashes, head.Checkpoint.Hash))
}

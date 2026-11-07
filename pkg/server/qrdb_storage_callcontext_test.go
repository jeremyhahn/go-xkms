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

package server

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// TestStorageCallContext_EmbeddedNodeRunsAsPrincipal proves the server's
// storage over an embedded node runs as the node's service principal, and
// that the principal is the reason it is allowed: the same client without
// the binding is refused.
func TestStorageCallContext_EmbeddedNodeRunsAsPrincipal(t *testing.T) {
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false
	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil, serviceprincipal.Option())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	s := &Server{qrdbNode: node}

	bound := qrdbstorage.NewBackend(node.Client().KV(), s.storageCallContext()...)
	require.NoError(t, bound.Put(context.Background(), "xkms/test/k", []byte("v")))
	got, err := bound.Get(context.Background(), "xkms/test/k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)

	unbound := qrdbstorage.NewBackend(node.Client().KV())
	_, err = unbound.Get(context.Background(), "xkms/test/k")
	assert.ErrorIs(t, err, qrdbsdk.ErrUnauthenticated)
}

// newPrincipalTestNode starts an in-memory standalone node that registers
// the xkms service principal.
func newPrincipalTestNode(t *testing.T) *qrdbnode.Node {
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
	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil, serviceprincipal.Option())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	return node
}

// TestPublicCallContext_KeepsCallerIdentity pins the security scope of the
// main run 74687 fix: a request that carries an identity keeps it, and
// never gains the service principal's authority.
func TestPublicCallContext_KeepsCallerIdentity(t *testing.T) {
	node := newPrincipalTestNode(t)
	bind := (&Server{qrdbNode: node}).publicCallContext()
	require.NotNil(t, bind)

	caller := &auth.Identity{Subject: "alice"}
	ctx := auth.WithIdentity(context.Background(), caller)
	got, err := bind(ctx)
	require.NoError(t, err)
	assert.Same(t, caller, auth.GetIdentity(got), "the caller's identity rides through unchanged")
	assert.Equal(t, ctx, got, "a request with an identity is never rebound")

	_, err = node.Client().Users().CreateUser(got, &qrdbtransport.CreateUserRequest{
		Username: "intruder",
		Email:    "intruder@example.com",
	})
	assert.Error(t, err, "the caller's call must not run with the service principal's users grant")
}

// TestPublicCallContext_NoIdentityRunsAsPrincipal is the counterpart: a
// public request with no identity runs as the service principal, whose
// grant covers the WebAuthn ceremonies' user records.
func TestPublicCallContext_NoIdentityRunsAsPrincipal(t *testing.T) {
	node := newPrincipalTestNode(t)
	bind := (&Server{qrdbNode: node}).publicCallContext()
	require.NotNil(t, bind)

	_, err := node.Client().Users().GetUserByEmail(context.Background(), "system", "new@example.com")
	require.ErrorIs(t, err, qrdbsdk.ErrUnauthenticated)

	got, err := bind(context.Background())
	require.NoError(t, err)
	created, err := node.Client().Users().CreateUser(got, &qrdbtransport.CreateUserRequest{
		Username: "new",
		Email:    "new@example.com",
	})
	require.NoError(t, err)
	_, err = node.Client().Users().GetUser(got, created.ID)
	require.NoError(t, err)
}

// TestPublicCallContext_NoEmbeddedNode checks a server without an embedded
// node binds nothing, so remote-client calls keep their own credentials.
func TestPublicCallContext_NoEmbeddedNode(t *testing.T) {
	assert.Nil(t, (&Server{}).publicCallContext())
}

// TestStorageCallContext_NoEmbeddedNode proves a server without an embedded
// node -- a remote datastore, whose client carries xkms's own mTLS identity
// -- binds nothing.
func TestStorageCallContext_NoEmbeddedNode(t *testing.T) {
	s := &Server{}
	assert.Empty(t, s.storageCallContext())
}

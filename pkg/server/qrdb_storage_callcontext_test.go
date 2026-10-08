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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// TestStorageCallContext_NoEmbeddedNode proves a server without an embedded
// node -- a remote datastore, whose client carries xkms's own mTLS identity
// -- binds nothing.
func TestStorageCallContext_NoEmbeddedNode(t *testing.T) {
	s := &Server{}
	assert.Empty(t, s.storageCallContext())
}

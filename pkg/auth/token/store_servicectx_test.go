package token_test

import (
	"context"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
)

// newAuthenticatingNode starts an embedded go-qrdb node that enforces
// authentication and carries xkms's service principal, as xkmsd runs one.
func newAuthenticatingNode(t *testing.T) *qrdbnode.Node {
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

// TestQRDBRefreshStore_NoServiceContext_Unauthenticated pins the node's
// side of the contract: without the binder an anonymous context is refused.
func TestQRDBRefreshStore_NoServiceContext_Unauthenticated(t *testing.T) {
	node := newAuthenticatingNode(t)
	store, err := token.NewQRDBRefreshStore(node.Client().KV())
	require.NoError(t, err)

	err = store.Save(context.Background(), &token.Record{
		JTI: "j1", Family: "f1", Subject: "alice", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	require.ErrorIs(t, err, qrdbsdk.ErrUnauthenticated)
}

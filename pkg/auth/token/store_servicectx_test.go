package token_test

import (
	"context"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/assert"
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

// TestQRDBRefreshStore_ServiceContext_AnonymousCaller is go-xkms#2287: the
// login routes are public, so the context reaching the refresh store carries
// no identity. With the service-context binder the store's own bookkeeping
// runs as the node's service principal and every operation succeeds.
func TestQRDBRefreshStore_ServiceContext_AnonymousCaller(t *testing.T) {
	node := newAuthenticatingNode(t)
	store, err := token.NewQRDBRefreshStore(node.Client().KV(), token.WithCallContext(node.ServiceContext))
	require.NoError(t, err)

	ctx := context.Background() // no identity, as on a public login route
	exp := time.Now().Add(time.Hour).Unix()
	rec := &token.Record{JTI: "j1", Family: "f1", Subject: "alice", ExpiresAt: exp}
	require.NoError(t, store.Save(ctx, rec))

	got, err := store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "alice", got.Subject)

	require.NoError(t, store.MarkRotated(ctx, "f1", "j1"))
	got, err = store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Rotated)

	require.NoError(t, store.RevokeFamily(ctx, "f1"))
	got, err = store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	assert.Nil(t, got, "a revoked family's records are gone")

	require.NoError(t, store.Save(ctx, &token.Record{JTI: "j2", Family: "f2", Subject: "bob", ExpiresAt: exp}))
	require.NoError(t, store.RevokeBySubject(ctx, "bob"))
	got, err = store.Get(ctx, "f2", "j2")
	require.NoError(t, err)
	assert.Nil(t, got, "revoke by subject removes the subject's families")
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

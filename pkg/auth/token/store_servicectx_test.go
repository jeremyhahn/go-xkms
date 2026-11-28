package token_test

import (
	"context"
	"encoding/json"
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

// TestQRDBRefreshStore_NoServiceContext_Unauthenticated pins the node's
// side of the contract: without the binder an anonymous context is refused.
func TestQRDBRefreshStore_NoServiceContext_Unauthenticated(t *testing.T) {
	node := newAuthenticatingNode(t)
	store, err := token.NewQRDBRefreshStore(node.Client().KV())
	require.NoError(t, err)

	err = store.Save(context.Background(), &token.Record{
		JTI: "j1", Family: "f1", Tenant: "t1", Subject: "alice", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	require.ErrorIs(t, err, qrdbsdk.ErrUnauthenticated)
}

// TestQRDBRefreshStore_ServiceContext_AnonymousCaller is go-xkms#2287:
// login routes are public, so the store is called with a context that
// carries no identity. With the node's ServiceContext as binder the
// store's own bookkeeping runs as the service principal.
func TestQRDBRefreshStore_ServiceContext_AnonymousCaller(t *testing.T) {
	node := newAuthenticatingNode(t)
	store, err := token.NewQRDBRefreshStore(node.Client().KV(), token.WithCallContext(node.ServiceContext))
	require.NoError(t, err)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour).Unix()

	require.NoError(t, store.Save(ctx, &token.Record{JTI: "j1", Family: "f1", Tenant: "t1", Subject: "alice", ExpiresAt: exp}))
	rec, err := store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, "alice", rec.Subject)

	require.NoError(t, store.MarkRotated(ctx, "f1", "j1"))
	rec, err = store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.True(t, rec.Rotated)

	require.NoError(t, store.RevokeFamily(ctx, "f1"))
	rec, err = store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	assert.Nil(t, rec)

	require.NoError(t, store.Save(ctx, &token.Record{JTI: "j2", Family: "f2", Tenant: "t1", Subject: "bob", ExpiresAt: exp}))
	require.NoError(t, store.RevokeBySubject(ctx, "t1", "bob"))
	rec, err = store.Get(ctx, "f2", "j2")
	require.NoError(t, err)
	assert.Nil(t, rec)
}

// A module request from a non-system tenant reaches the store with that
// tenant bound to its context. The bookkeeping must still run in the store's
// system-tenant scope, or the self-scoped KV permissions of the service
// principal reject the mismatch (go-xkms#2287, Tenant Agent ruling 971).
func TestQRDBRefreshStore_ServiceContext_NonSystemTenantCaller(t *testing.T) {
	node := newAuthenticatingNode(t)
	store, err := token.NewQRDBRefreshStore(node.Client().KV(), token.WithCallContext(node.ServiceContext))
	require.NoError(t, err)
	exp := time.Now().Add(time.Hour).Unix()
	anon := context.Background()
	tenantCtx := qrdbsdk.ContextWithTenant(context.Background(), "t1")

	require.NoError(t, store.Save(anon, &token.Record{JTI: "j1", Family: "f1", Tenant: "t1", Subject: "alice", ExpiresAt: exp}))
	rec, err := store.Get(tenantCtx, "f1", "j1")
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.NoError(t, store.MarkRotated(tenantCtx, "f1", "j1"))
	require.NoError(t, store.RevokeFamily(tenantCtx, "f1"))
	rec, err = store.Get(anon, "f1", "j1")
	require.NoError(t, err)
	assert.Nil(t, rec)

	require.NoError(t, store.Save(anon, &token.Record{JTI: "j2", Family: "f2", Tenant: "t1", Subject: "bob", ExpiresAt: exp}))
	require.NoError(t, store.RevokeBySubject(tenantCtx, "t1", "bob"))
	rec, err = store.Get(anon, "f2", "j2")
	require.NoError(t, err)
	assert.Nil(t, rec)
}

// The bound call keeps the caller's cancellation: a cancelled request
// context cancels the bookkeeping call instead of running it detached.
func TestQRDBRefreshStore_ServiceContext_CancelledCaller(t *testing.T) {
	node := newAuthenticatingNode(t)
	store, err := token.NewQRDBRefreshStore(node.Client().KV(), token.WithCallContext(node.ServiceContext))
	require.NoError(t, err)
	exp := time.Now().Add(time.Hour).Unix()
	require.NoError(t, store.Save(context.Background(), &token.Record{JTI: "j1", Family: "f1", Tenant: "t1", Subject: "alice", ExpiresAt: exp}))

	ctx, cancel := context.WithCancel(qrdbsdk.ContextWithTenant(context.Background(), "t1"))
	cancel()
	err = store.RevokeFamily(ctx, "f1")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	rec, err := store.Get(context.Background(), "f1", "j1")
	require.NoError(t, err)
	assert.NotNil(t, rec, "a cancelled revoke must not run")
}

// TestQRDBRefreshStore_RevokeBySubject_TenantScoped revokes "alice" in one
// tenant on the embedded node and checks the other tenant's "alice" keeps
// her refresh family (Tenant Agent ruling 962).
func TestQRDBRefreshStore_RevokeBySubject_TenantScoped(t *testing.T) {
	node := newAuthenticatingNode(t)
	store, err := token.NewQRDBRefreshStore(node.Client().KV(), token.WithCallContext(node.ServiceContext))
	require.NoError(t, err)
	token.AssertTenantScopedRevoke(t, context.Background(), store)
}

// TestQRDBRefreshStore_RecordWithoutTenant_FailsClosed writes a record that
// carries no tenant straight into QRDB: no tenant-scoped revoke matches it,
// and the store refuses it on read and rotate and deletes it.
func TestQRDBRefreshStore_RecordWithoutTenant_FailsClosed(t *testing.T) {
	node := newAuthenticatingNode(t)
	store, err := token.NewQRDBRefreshStore(node.Client().KV(), token.WithCallContext(node.ServiceContext))
	require.NoError(t, err)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour).Unix()

	require.Error(t, store.Save(ctx, &token.Record{JTI: "j0", Family: "f0", Subject: "alice", ExpiresAt: exp}))

	sctx, err := node.ServiceContext(ctx)
	require.NoError(t, err)
	raw, err := json.Marshal(map[string]any{"jti": "j0", "family": "f0", "subject": "alice", "expires_at": exp})
	require.NoError(t, err)
	key := token.RefreshKeyForTest("f0", "j0")
	require.NoError(t, node.Client().KV().Put(sctx, key, raw))

	require.NoError(t, store.RevokeBySubject(ctx, "t1", "alice"))
	require.NoError(t, store.RevokeBySubject(ctx, "t2", "alice"))
	require.Error(t, store.RevokeBySubject(ctx, "", "alice"))
	require.Error(t, store.RevokeBySubject(ctx, "t1", ""))

	rec, err := store.Get(ctx, "f0", "j0")
	require.NoError(t, err)
	assert.Nil(t, rec, "a record without a tenant is refused")
	require.Error(t, store.MarkRotated(ctx, "f0", "j0"), "a record without a tenant never rotates")

	_, err = node.Client().KV().Get(sctx, key)
	require.Error(t, err, "a record without a tenant is not kept")
}

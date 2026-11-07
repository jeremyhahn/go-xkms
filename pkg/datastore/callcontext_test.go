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

package datastore

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
)

// tagged is an entity with an indexed field: its DAO registers an index,
// and a Where on the field queries it.
type tagged struct {
	ID  uint64 `json:"id"`
	Tag string `json:"tag" index:"true"`
}

func (e *tagged) EntityID() uint64      { return e.ID }
func (e *tagged) SetEntityID(id uint64) { e.ID = id }

func newTagged() *tagged { return &tagged{} }

// newPrincipalNode boots a real in-memory standalone qrdb node that
// enforces authentication and carries xkms's service principal, as xkmsd's
// embedded node does.
func newPrincipalNode(t *testing.T) *qrdbnode.Node {
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

// TestWithCallContext_FeatureDatabaseRunsAsServicePrincipal proves a
// datastore bound to the node's ServiceContext does a feature's whole DAO
// round trip inside the service principal's grant: it ensures the named
// database, builds an indexed DAO there, saves, and looks up through the
// index.
func TestWithCallContext_FeatureDatabaseRunsAsServicePrincipal(t *testing.T) {
	ctx := t.Context()
	node := newPrincipalNode(t)
	ds, err := New(node.Client(), config.DatastoreConfig{Engine: "memory"}, WithCallContext(node.ServiceContext))
	require.NoError(t, err)

	_, err = ds.DatabaseKVStore(ctx, "feature")
	require.NoError(t, err)
	tags, err := dao.New(ds.DAOFactory(), "feature", "tagged", newTagged)
	require.NoError(t, err)
	require.NoError(t, tags.Save(ctx, &tagged{Tag: "a"}))
	require.NoError(t, tags.Save(ctx, &tagged{Tag: "b"}))

	found, err := tags.Find(ctx).Where("Tag = ?", "a").Execute()
	require.NoError(t, err)
	require.Len(t, found, 1)
	assert.Equal(t, "a", found[0].Tag)
}

// TestWithCallContext_UnboundIsUnauthenticated proves the binding is what
// authorizes the datastore: without it the same node refuses the database
// ensure as unauthenticated.
func TestWithCallContext_UnboundIsUnauthenticated(t *testing.T) {
	node := newPrincipalNode(t)
	ds, err := New(node.Client(), config.DatastoreConfig{Engine: "memory"})
	require.NoError(t, err)

	_, err = ds.DatabaseKVStore(t.Context(), "feature")
	require.ErrorIs(t, err, qrdbsdk.ErrUnauthenticated)
}

// TestWithCallContext_BindErrorFailsTheCall proves a bind failure fails the
// database ensure and a DAO's store call with ErrCallContext before either
// reaches go-qrdb.
func TestWithCallContext_BindErrorFailsTheCall(t *testing.T) {
	ctx := t.Context()
	cause := errors.New("no service principal")
	node := newPrincipalNode(t)
	ds, err := New(node.Client(), config.DatastoreConfig{Engine: "memory"},
		WithCallContext(func(context.Context) (context.Context, error) { return nil, cause }))
	require.NoError(t, err)

	_, err = ds.DatabaseKVStore(ctx, "feature")
	var bindErr *ErrCallContext
	require.ErrorAs(t, err, &bindErr)
	assert.ErrorIs(t, err, cause)

	notes, err := dao.New(ds.DAOFactory(), "", "notes", newNote)
	require.NoError(t, err)
	err = notes.Save(ctx, &note{Text: "x"})
	require.ErrorAs(t, err, &bindErr)
	assert.ErrorIs(t, err, cause)
}

// TestBindKV_RunsAsServicePrincipal pins the token issuer's refresh store
// seam (main run 74687): an unbound call on the node's KV client is
// unauthenticated, and BindKV runs it as the service principal, keeping
// the guarded verbs the refresh store needs.
func TestBindKV_RunsAsServicePrincipal(t *testing.T) {
	ctx := t.Context()
	node := newPrincipalNode(t)

	require.ErrorIs(t, node.Client().KV().Put(ctx, "xkms/test/a", []byte("v")), qrdbsdk.ErrUnauthenticated)

	kv := BindKV(node.Client().KV(), node.ServiceContext)
	require.NoError(t, kv.Put(ctx, "xkms/test/a", []byte("v")))
	got, err := kv.Get(ctx, "xkms/test/a")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)

	guarded, ok := kv.(transport.GuardedKVClient)
	require.True(t, ok, "the bound client keeps the guarded verbs")
	swapped, err := guarded.CompareAndSwap(ctx, "xkms/test/a", []byte("v"), []byte("w"))
	require.NoError(t, err)
	assert.True(t, swapped)
}

// TestBindKV_NilBindAndBindError checks a nil binder returns the client
// unchanged and a failing binder stops the call with ErrCallContext.
func TestBindKV_NilBindAndBindError(t *testing.T) {
	node := newPrincipalNode(t)
	inner := node.Client().KV()
	assert.Same(t, inner, BindKV(inner, nil))

	cause := errors.New("no service principal")
	kv := BindKV(inner, func(context.Context) (context.Context, error) { return nil, cause })
	_, err := kv.Get(t.Context(), "xkms/test/a")
	var bindErr *ErrCallContext
	require.ErrorAs(t, err, &bindErr)
	assert.ErrorIs(t, err, cause)
}

// TestBoundKV_RefusesVerbsTheInnerClientLacks proves the bound client
// refuses the guarded and transaction verbs as the SDK's adapter does when
// the client it wraps does not carry them, rather than claiming them.
func TestBoundKV_RefusesVerbsTheInnerClientLacks(t *testing.T) {
	ctx := t.Context()
	plain := &boundKV{
		kv:   struct{ transport.KVClient }{},
		bind: func(ctx context.Context) (context.Context, error) { return ctx, nil },
	}

	calls := map[string]func() error{
		"put if absent":      func() error { _, err := plain.PutIfAbsent(ctx, "k", nil); return err },
		"compare and delete": func() error { _, err := plain.CompareAndDelete(ctx, "k", nil); return err },
		"compare and swap":   func() error { _, err := plain.CompareAndSwap(ctx, "k", nil, nil); return err },
		"transaction": func() error {
			_, err := plain.ExecuteTransaction(ctx, &transport.TransactionRequest{})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), qrdbsdk.ErrKVAtomicWriteUnsupported)
		})
	}
}

// featureClients returns the KV and index planes of an existing feature
// database on node, each wrapped to bind its calls with bind.
func featureClients(t *testing.T, node *qrdbnode.Node, bind func(context.Context) (context.Context, error)) (*boundKV, *boundIndex) {
	t.Helper()
	ds, err := New(node.Client(), config.DatastoreConfig{Engine: "memory"}, WithCallContext(node.ServiceContext))
	require.NoError(t, err)
	_, err = ds.DatabaseKVStore(t.Context(), "feature")
	require.NoError(t, err)

	scoped, err := node.Client().DatabaseScoped("feature")
	require.NoError(t, err)
	return &boundKV{kv: scoped.KV(), bind: bind}, &boundIndex{index: scoped.Index(), bind: bind}
}

// boundVerbs exercises every verb of the bound KV and index planes once.
var boundVerbs = map[string]func(context.Context, *boundKV, *boundIndex) error{
	"put":    func(ctx context.Context, kv *boundKV, _ *boundIndex) error { return kv.Put(ctx, "k", []byte("v")) },
	"get":    func(ctx context.Context, kv *boundKV, _ *boundIndex) error { _, err := kv.Get(ctx, "k"); return err },
	"delete": func(ctx context.Context, kv *boundKV, _ *boundIndex) error { return kv.Delete(ctx, "k") },
	"list":   func(ctx context.Context, kv *boundKV, _ *boundIndex) error { _, err := kv.List(ctx, ""); return err },
	"scan":   func(ctx context.Context, kv *boundKV, _ *boundIndex) error { _, err := kv.Scan(ctx, ""); return err },
	"exists": func(ctx context.Context, kv *boundKV, _ *boundIndex) error { _, err := kv.Exists(ctx, "k"); return err },
	"put if absent": func(ctx context.Context, kv *boundKV, _ *boundIndex) error {
		_, err := kv.PutIfAbsent(ctx, "k", []byte("v"))
		return err
	},
	"compare and delete": func(ctx context.Context, kv *boundKV, _ *boundIndex) error {
		_, err := kv.CompareAndDelete(ctx, "k", []byte("v"))
		return err
	},
	"compare and swap": func(ctx context.Context, kv *boundKV, _ *boundIndex) error {
		_, err := kv.CompareAndSwap(ctx, "k", []byte("v"), []byte("w"))
		return err
	},
	"transaction": func(ctx context.Context, kv *boundKV, _ *boundIndex) error {
		_, err := kv.ExecuteTransaction(ctx, &transport.TransactionRequest{})
		return err
	},
	"index create": func(ctx context.Context, _ *boundKV, ix *boundIndex) error {
		return ix.IndexCreate(ctx, "by_tag", "tag", transport.IndexConfig{})
	},
	"index drop": func(ctx context.Context, _ *boundKV, ix *boundIndex) error { return ix.IndexDrop(ctx, "by_tag") },
	"index query": func(ctx context.Context, _ *boundKV, ix *boundIndex) error {
		_, err := ix.IndexQuery(ctx, "by_tag", "a")
		return err
	},
	"index scan": func(ctx context.Context, _ *boundKV, ix *boundIndex) error {
		_, err := ix.IndexScan(ctx, "by_tag", nil, nil)
		return err
	},
	"index list": func(ctx context.Context, _ *boundKV, ix *boundIndex) error { _, err := ix.IndexList(ctx); return err },
}

// TestBoundKV_EveryVerbRunsUnderTheBoundContext pins that each KV and index
// verb reaches the node under the service principal the bind supplies: the
// same verbs a caller issues with no bind are refused as unauthenticated.
func TestBoundKV_EveryVerbRunsUnderTheBoundContext(t *testing.T) {
	ctx := t.Context()
	node := newPrincipalNode(t)
	kv, ix := featureClients(t, node, node.ServiceContext)

	require.NoError(t, kv.Put(ctx, "tags/1", []byte(`{"id":1,"tag":"a"}`)))
	got, err := kv.Get(ctx, "tags/1")
	require.NoError(t, err)
	assert.JSONEq(t, `{"id":1,"tag":"a"}`, string(got))
	found, err := kv.Exists(ctx, "tags/1")
	require.NoError(t, err)
	assert.True(t, found)
	keys, err := kv.List(ctx, "tags/")
	require.NoError(t, err)
	assert.Equal(t, []string{"tags/1"}, keys)
	pairs, err := kv.Scan(ctx, "tags/")
	require.NoError(t, err)
	assert.Len(t, pairs, 1)

	stored, err := kv.PutIfAbsent(ctx, "claim", []byte("one"))
	require.NoError(t, err)
	assert.True(t, stored)
	swapped, err := kv.CompareAndSwap(ctx, "claim", []byte("one"), []byte("two"))
	require.NoError(t, err)
	assert.True(t, swapped)
	tx, err := kv.ExecuteTransaction(ctx, &transport.TransactionRequest{
		Compares:   []transport.Compare{{Key: []byte("claim"), Target: transport.CompareValue, Result: transport.CompareEqual, Value: []byte("two")}},
		SuccessOps: []transport.Op{{Type: transport.OpPut, Key: []byte("claim"), Value: []byte("three")}},
	})
	require.NoError(t, err)
	assert.True(t, tx.Succeeded)
	deleted, err := kv.CompareAndDelete(ctx, "claim", []byte("three"))
	require.NoError(t, err)
	assert.True(t, deleted)
	require.NoError(t, kv.Delete(ctx, "tags/1"))
	found, err = kv.Exists(ctx, "tags/1")
	require.NoError(t, err)
	assert.False(t, found)

	require.NoError(t, ix.IndexCreate(ctx, "by_tag", "tag", transport.IndexConfig{}))
	_, err = ix.IndexQuery(ctx, "by_tag", "a")
	require.NoError(t, err)

	// The service principal's grant stops at create and query, so scanning,
	// listing and dropping reach the node authenticated and are refused by its RBAC.
	var denied *qrdbsdk.PermissionDeniedError
	_, err = ix.IndexScan(ctx, "by_tag", nil, nil)
	require.ErrorAs(t, err, &denied)
	_, err = ix.IndexList(ctx)
	require.ErrorAs(t, err, &denied)
	require.ErrorAs(t, ix.IndexDrop(ctx, "by_tag"), &denied)
}

// TestBoundKV_EveryVerbNeedsTheBind pins the failure side of the same verbs:
// without a bind the node refuses each one, and a bind that fails stops each
// one before it reaches the node.
func TestBoundKV_EveryVerbNeedsTheBind(t *testing.T) {
	cause := errors.New("no service principal")
	node := newPrincipalNode(t)
	unbound, unboundIx := featureClients(t, node, (&Datastore{}).callContext)
	failing := (&Datastore{bind: func(context.Context) (context.Context, error) { return nil, cause }}).callContext
	failed, failedIx := featureClients(t, node, failing)

	for name, verb := range boundVerbs {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, verb(t.Context(), unbound, unboundIx), qrdbsdk.ErrUnauthenticated)

			err := verb(t.Context(), failed, failedIx)
			var bindErr *ErrCallContext
			require.ErrorAs(t, err, &bindErr)
			assert.ErrorIs(t, err, cause)
		})
	}
}

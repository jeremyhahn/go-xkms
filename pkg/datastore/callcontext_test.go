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

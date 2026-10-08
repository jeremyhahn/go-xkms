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

package serviceprincipal

import (
	"context"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newNode boots a real in-memory standalone qrdb node with no network
// protocols, configured with opts.
func newNode(t *testing.T, opts ...qrdbnode.NodeOption) *qrdbnode.Node {
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

// TestOption_InternalCallsSucceed proves every call xkms makes on its own
// behalf is inside the grant: the storage backend's KV verbs and the OIDC
// credential service's lease acquire, renew and release.
func TestOption_InternalCallsSucceed(t *testing.T) {
	node := newNode(t, Option())
	ctx, err := node.ServiceContext(context.Background())
	require.NoError(t, err)

	kv := node.Client().KV()
	require.NoError(t, kv.Put(ctx, "xkms/test/a", []byte("v")))
	got, err := kv.Get(ctx, "xkms/test/a")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)
	exists, err := kv.Exists(ctx, "xkms/test/a")
	require.NoError(t, err)
	assert.True(t, exists)
	keys, err := kv.List(ctx, "xkms/test/")
	require.NoError(t, err)
	assert.Equal(t, []string{"xkms/test/a"}, keys)
	pairs, err := kv.Scan(ctx, "xkms/test/")
	require.NoError(t, err)
	assert.Equal(t, map[string][]byte{"xkms/test/a": []byte("v")}, pairs)
	require.NoError(t, kv.Delete(ctx, "xkms/test/a"))

	coord, err := node.Client().Coordination()
	require.NoError(t, err)
	lease, err := coord.AcquireLease(ctx, "xkms/test/lease", time.Minute)
	require.NoError(t, err)
	require.NoError(t, lease.Renew(ctx))
	require.NoError(t, lease.Release(ctx))
}

// TestOption_EnsuresAFeatureDatabase proves the principal can do what the
// datastore does to open a feature's go-qrdb database for its DAOs
// (pkg/datastore DatabaseKVStore): look it up, create it when absent, and
// read and write through the database-scoped store.
func TestOption_EnsuresAFeatureDatabase(t *testing.T) {
	node := newNode(t, Option())
	ctx, err := node.ServiceContext(context.Background())
	require.NoError(t, err)

	// The datastore's ensure needs only databases:create: a refused lookup
	// falls through to the create, and creating a database that exists
	// answers DBAlreadyExistsError, which the ensure reads as success.
	db := node.Client().Database()
	_, err = db.GetDatabase(ctx, "feature")
	var denied *qrdbsdk.PermissionDeniedError
	require.ErrorAs(t, err, &denied, "the grant carries no databases:read")
	req := qrdbtransport.CreateDatabaseRequest{Name: "feature", Backend: "memory"}
	_, err = db.CreateDatabase(ctx, req)
	require.NoError(t, err)
	_, err = db.CreateDatabase(ctx, req)
	var exists *qrdbsdk.DBAlreadyExistsError
	require.ErrorAs(t, err, &exists)

	scoped, err := node.Client().DatabaseScoped("feature")
	require.NoError(t, err)
	kv := scoped.KVStore()
	require.NoError(t, kv.Put(ctx, "k", []byte("v")))
	got, err := kv.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)
}

// TestOption_CallOutsideGrantIsRefused proves the grant is least privilege:
// the principal cannot do what xkms never does on its own behalf.
func TestOption_CallOutsideGrantIsRefused(t *testing.T) {
	node := newNode(t, Option())
	ctx, err := node.ServiceContext(context.Background())
	require.NoError(t, err)

	_, err = node.Client().Database().ListDatabases(ctx)
	var denied *qrdbsdk.PermissionDeniedError
	require.ErrorAs(t, err, &denied)
}

// TestOption_UnboundCallIsNotThePrincipal proves the principal is not
// ambient: a call on a context ServiceContext did not derive -- a request's
// context -- keeps that context's identity, here none, and is refused.
func TestOption_UnboundCallIsNotThePrincipal(t *testing.T) {
	node := newNode(t, Option())

	_, err := node.Client().KV().Get(context.Background(), "xkms/test/a")
	require.ErrorIs(t, err, qrdbsdk.ErrUnauthenticated)
}

// TestServiceContext_NoPrincipal proves a node built without Option has no
// principal to run as.
func TestServiceContext_NoPrincipal(t *testing.T) {
	node := newNode(t)

	_, err := node.ServiceContext(context.Background())
	require.ErrorIs(t, err, qrdbnode.ErrNoServicePrincipal)
}

func TestGrant_IsLeastPrivilegeCopy(t *testing.T) {
	got := Grant()
	assert.Equal(t, grant, got)
	for _, p := range got {
		assert.NotContains(t, string(p), "*", "the grant never holds a wildcard")
	}

	got[0] = "admin:*"
	assert.NotEqual(t, got[0], Grant()[0], "Grant returns a copy")
}

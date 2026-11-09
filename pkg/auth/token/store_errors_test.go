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

package token

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stringNotFoundError mimics a transport whose missing-key error carries no
// NotFound() method — only the "not found" substring isNotFound falls back
// to matching.
type stringNotFoundError struct{}

func (stringNotFoundError) Error() string { return "rpc error: key not found: no such entry" }

// errKVOutage is the sentinel injected-failure error every errorKV method
// below returns, distinguishing "the transport is down" from "the key is
// absent" in test assertions.
var errKVOutage = errors.New("kv transport outage")

// errorKV wraps a guardedMemoryKV and fails exactly the named operation,
// delegating every other call to the wrapped store. This is the seam
// store.go's QRDBRefreshStore already exercises through the
// qrdbtransport.GuardedKVClient interface — no new production code is
// needed to inject the failure.
type errorKV struct {
	*guardedMemoryKV
	failOp string
}

func newErrorKV(failOp string) *errorKV {
	return &errorKV{guardedMemoryKV: newGuardedMemoryKV(), failOp: failOp}
}

var _ qrdbtransport.GuardedKVClient = (*errorKV)(nil)

func (k *errorKV) Put(ctx context.Context, key string, value []byte, opts ...qrdbtransport.WriteOption) error {
	if k.failOp == "put" {
		return errKVOutage
	}
	return k.guardedMemoryKV.Put(ctx, key, value, opts...)
}

func (k *errorKV) Get(ctx context.Context, key string, opts ...qrdbtransport.ReadOption) ([]byte, error) {
	if k.failOp == "get" {
		return nil, errKVOutage
	}
	return k.guardedMemoryKV.Get(ctx, key, opts...)
}

func (k *errorKV) Delete(ctx context.Context, key string, opts ...qrdbtransport.WriteOption) error {
	if k.failOp == "delete" {
		return errKVOutage
	}
	return k.guardedMemoryKV.Delete(ctx, key, opts...)
}

func (k *errorKV) List(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) ([]string, error) {
	if k.failOp == "list" {
		return nil, errKVOutage
	}
	return k.guardedMemoryKV.List(ctx, prefix, opts...)
}

func (k *errorKV) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if k.failOp == "putifabsent" {
		return false, errKVOutage
	}
	return k.guardedMemoryKV.PutIfAbsent(ctx, key, value)
}

func (k *errorKV) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if k.failOp == "comparedelete" {
		return false, errKVOutage
	}
	return k.guardedMemoryKV.CompareAndDelete(ctx, key, expected)
}

func (k *errorKV) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	if k.failOp == "compareswap" {
		return false, errKVOutage
	}
	return k.guardedMemoryKV.CompareAndSwap(ctx, key, expected, next)
}

func (k *errorKV) Scan(ctx context.Context, prefix string, opts ...qrdbtransport.ReadOption) (map[string][]byte, error) {
	if k.failOp == "scan" {
		return nil, errKVOutage
	}
	return k.guardedMemoryKV.Scan(ctx, prefix, opts...)
}

func newQRDBStore(t *testing.T, kv qrdbtransport.KVClient) *QRDBRefreshStore {
	t.Helper()
	store, err := NewQRDBRefreshStore(kv)
	require.NoError(t, err)
	return store
}

func TestQRDBRefreshStore_Save_PutError(t *testing.T) {
	store := newQRDBStore(t, newErrorKV("put"))
	rec := &Record{JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix()}

	err := store.Save(context.Background(), rec)
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "put", se.Op)
	assert.ErrorIs(t, se, errKVOutage)
}

func TestQRDBRefreshStore_Save_FamilyRevokedCheckError(t *testing.T) {
	store := newQRDBStore(t, newErrorKV("get"))
	rec := &Record{JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix()}

	err := store.Save(context.Background(), rec)
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "get revocation", se.Op)
}

func TestQRDBRefreshStore_Save_WithdrawOnRevokedFamilyFails(t *testing.T) {
	kv := newErrorKV("comparedelete")
	store := newQRDBStore(t, kv)
	ctx := context.Background()

	require.NoError(t, store.RevokeFamily(ctx, "f1"))
	kv.failOp = "comparedelete"

	rec := &Record{JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	err := store.Save(ctx, rec)
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "compare-and-delete", se.Op)
}

func TestQRDBRefreshStore_Save_RevokedFamilyIsWithdrawn(t *testing.T) {
	kv := newErrorKV("")
	store := newQRDBStore(t, kv)
	ctx := context.Background()

	require.NoError(t, store.RevokeFamily(ctx, "f1"))

	rec := &Record{JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	err := store.Save(ctx, rec)
	var fre *FamilyRevokedError
	require.ErrorAs(t, err, &fre)
	assert.Equal(t, "f1", fre.Family)

	// The record must have been withdrawn, not left behind.
	got, err := store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestQRDBRefreshStore_Load_GetErrorPropagates(t *testing.T) {
	store := newQRDBStore(t, newErrorKV("get"))
	_, err := store.Get(context.Background(), "f1", "j1")
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "get", se.Op)
}

func TestQRDBRefreshStore_Load_DecodeErrorSurfaces(t *testing.T) {
	kv := newGuardedMemoryKV()
	store := newQRDBStore(t, kv)
	require.NoError(t, kv.Put(context.Background(), refreshKey("f1", "j1"), []byte("{not valid json")))

	_, err := store.Get(context.Background(), "f1", "j1")
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "decode", se.Op)
}

func TestQRDBRefreshStore_Load_ExpiredRecordIsCleanedUp(t *testing.T) {
	kv := newGuardedMemoryKV()
	store := newQRDBStore(t, kv)
	ctx := context.Background()
	require.NoError(t, store.Save(ctx, &Record{
		JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	}))

	got, err := store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	assert.Nil(t, got, "an expired record must read back as absent")

	// The lazy cleanup must actually have deleted the key.
	exists, err := kv.Exists(ctx, refreshKey("f1", "j1"))
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestQRDBRefreshStore_RevokeFamily_PutIfAbsentError(t *testing.T) {
	store := newQRDBStore(t, newErrorKV("putifabsent"))
	err := store.RevokeFamily(context.Background(), "f1")
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "put-if-absent", se.Op)
}

func TestQRDBRefreshStore_RevokeFamily_ListError(t *testing.T) {
	store := newQRDBStore(t, newErrorKV("list"))
	err := store.RevokeFamily(context.Background(), "f1")
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "list", se.Op)
}

func TestQRDBRefreshStore_RevokeFamily_DeleteError(t *testing.T) {
	kv := newErrorKV("")
	store := newQRDBStore(t, kv)
	ctx := context.Background()
	require.NoError(t, store.Save(ctx, &Record{
		JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))
	kv.failOp = "delete"

	err := store.RevokeFamily(ctx, "f1")
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "delete", se.Op)
}

func TestQRDBRefreshStore_RevokeBySubject_ScanError(t *testing.T) {
	store := newQRDBStore(t, newErrorKV("scan"))
	err := store.RevokeBySubject(context.Background(), "acme", "alice")
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "scan", se.Op)
}

func TestQRDBRefreshStore_RevokeBySubject_DecodeErrorSurfaces(t *testing.T) {
	kv := newGuardedMemoryKV()
	// A malformed value under the refresh prefix must surface as a typed
	// decode failure, not be silently skipped -- an undecodable record could
	// be exactly the family a lifecycle change was trying to revoke.
	require.NoError(t, kv.Put(context.Background(), refreshKey("f1", "j1"), []byte("not json")))
	store := newQRDBStore(t, kv)

	err := store.RevokeBySubject(context.Background(), "acme", "alice")
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "decode", se.Op)
}

func TestQRDBRefreshStore_RevokeBySubject_RevokeFamilyErrorPropagates(t *testing.T) {
	kv := newErrorKV("")
	store := newQRDBStore(t, kv)
	ctx := context.Background()
	require.NoError(t, store.Save(ctx, &Record{
		JTI: "j1", Family: "f1", Subject: "alice", Tenant: "acme", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))
	kv.failOp = "putifabsent"

	err := store.RevokeBySubject(ctx, "acme", "alice")
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "put-if-absent", se.Op)
}

func TestQRDBRefreshStore_FamilyRevoked_GetErrorPropagates(t *testing.T) {
	store := newQRDBStore(t, newErrorKV("get"))
	rec := &Record{JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	// Save reaches familyRevoked internally after a successful Put, so drive
	// the get-error branch through Save rather than duplicating the call.
	err := store.Save(context.Background(), rec)
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "get revocation", se.Op)
}

func TestQRDBRefreshStore_FamilyRevoked_DecodeErrorSurfaces(t *testing.T) {
	kv := newGuardedMemoryKV()
	store := newQRDBStore(t, kv)
	require.NoError(t, kv.Put(context.Background(), revokedKey("f1"), []byte("{not valid json")))

	rec := &Record{JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	err := store.Save(context.Background(), rec)
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "decode revocation", se.Op)
}

func TestQRDBRefreshStore_FamilyRevoked_ExpiredTombstoneIsCleanedUp(t *testing.T) {
	kv := newGuardedMemoryKV()
	store := newQRDBStore(t, kv)
	ctx := context.Background()
	require.NoError(t, kv.Put(ctx, revokedKey("f1"), mustJSON(t, &revocation{
		Family: "f1", ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	})))

	// An expired tombstone no longer guards the family: Save must succeed.
	rec := &Record{JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, store.Save(ctx, rec))

	exists, err := kv.Exists(ctx, revokedKey("f1"))
	require.NoError(t, err)
	assert.False(t, exists, "the expired tombstone must have been cleaned up")
}

func TestQRDBRefreshStore_MarkRotated_LoadErrorPropagates(t *testing.T) {
	store := newQRDBStore(t, newErrorKV("get"))
	err := store.MarkRotated(context.Background(), "f1", "j1")
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "get", se.Op)
}

func TestQRDBRefreshStore_MarkRotated_CompareAndSwapError(t *testing.T) {
	kv := newErrorKV("")
	store := newQRDBStore(t, kv)
	ctx := context.Background()
	require.NoError(t, store.Save(ctx, &Record{
		JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))
	kv.failOp = "compareswap"

	err := store.MarkRotated(ctx, "f1", "j1")
	var se *StoreError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, "compare-and-swap", se.Op)
}

// TestIsNotFound_StringFallback pins the fallback branch: a transport error
// with no NotFound() method still reads as "not found" by substring match.
func TestIsNotFound_StringFallback(t *testing.T) {
	assert.True(t, isNotFound(stringNotFoundError{}))
	assert.False(t, isNotFound(errors.New("connection reset by peer")))
}

// newServiceNode boots a real in-memory standalone qrdb node configured with
// xkms's service principal, as embeddednode.NewNode configures production's.
func newServiceNode(t *testing.T) *qrdbnode.Node {
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

// TestQRDBRefreshStore_EmbeddedNode_BareContextIsRefused shows why the store
// needs a call context: a WebAuthn registration finish mints its first token
// pair on the anonymous request's context, and the embedded node refuses that
// context's KV write as unauthenticated.
func TestQRDBRefreshStore_EmbeddedNode_BareContextIsRefused(t *testing.T) {
	node := newServiceNode(t)
	store, err := NewQRDBRefreshStore(node.Client().KV())
	require.NoError(t, err)

	rec := &Record{JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.ErrorIs(t, store.Save(context.Background(), rec), qrdbsdk.ErrUnauthenticated)
}

// TestQRDBRefreshStore_CallContext_RunsAsServicePrincipal proves every qrdb
// call the store makes runs on the bound call context: on the anonymous
// request's context, a token pair is saved, read, rotated and revoked as the
// node's service principal.
func TestQRDBRefreshStore_CallContext_RunsAsServicePrincipal(t *testing.T) {
	node := newServiceNode(t)
	store, err := NewQRDBRefreshStore(node.Client().KV(), WithCallContext(node.ServiceContext))
	require.NoError(t, err)

	ctx := context.Background()
	exp := time.Now().Add(time.Hour).Unix()
	require.NoError(t, store.Save(ctx, &Record{JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: exp}))
	got, err := store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	assert.Equal(t, "s1", got.Subject)
	require.NoError(t, store.MarkRotated(ctx, "f1", "j1"))
	require.NoError(t, store.RevokeFamily(ctx, "f1"))

	require.NoError(t, store.Save(ctx, &Record{JTI: "j2", Family: "f2", Subject: "s2", Tenant: "acme", ExpiresAt: exp}))
	require.NoError(t, store.RevokeBySubject(ctx, "acme", "s2"))
}

// TestQRDBRefreshStore_CallContext_BindError proves a call context that
// cannot bind fails the call instead of falling back to the caller's context.
func TestQRDBRefreshStore_CallContext_BindError(t *testing.T) {
	bindErr := errors.New("bind failed")
	store, err := NewQRDBRefreshStore(newGuardedMemoryKV(), WithCallContext(func(context.Context) (context.Context, error) {
		return nil, bindErr
	}))
	require.NoError(t, err)

	rec := &Record{JTI: "j1", Family: "f1", Subject: "s1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.ErrorIs(t, store.Save(context.Background(), rec), bindErr)
	_, err = store.Get(context.Background(), "f1", "j1")
	require.ErrorIs(t, err, bindErr)
	require.ErrorIs(t, store.MarkRotated(context.Background(), "f1", "j1"), bindErr)
	require.ErrorIs(t, store.RevokeFamily(context.Background(), "f1"), bindErr)
	require.ErrorIs(t, store.RevokeBySubject(context.Background(), "acme", "s1"), bindErr)
}

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return data
}

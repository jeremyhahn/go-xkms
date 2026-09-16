//go:build codec_json

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

package objstore

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// plainKVStore is a KVStore with no guarded operations. It is the fixture for
// the honesty half of this change: a tenant wrapper over a store that cannot
// perform guarded writes must not look as though it can.
type plainKVStore struct {
	qrdbsdk.KVStore
}

// scopedAtomic returns the tenant-scoped store as the interface go-qrdb's DAO
// layer asserts, failing the test if the assertion does not hold.
func scopedAtomic(t *testing.T, inner qrdbsdk.KVStore, prefix string) qrdbsdk.AtomicKVStore {
	t.Helper()
	atomic, ok := newPrefixedKVStore(inner, prefix).(qrdbsdk.AtomicKVStore)
	require.True(t, ok, "an atomic inner store must produce an atomic tenant-scoped store")
	return atomic
}

func TestPrefixedKVStore_AtomicInnerStoreKeepsTheCapability(t *testing.T) {
	_, ok := newPrefixedKVStore(newSharedKV(t), "acme/tenants/alpha").(qrdbsdk.AtomicKVStore)

	assert.True(t, ok,
		"dropping the guarded operations makes every tenant-scoped DAO fail closed at run time")
}

func TestPrefixedKVStore_NonAtomicInnerStoreIsNotClaimedAtomic(t *testing.T) {
	_, ok := newPrefixedKVStore(&plainKVStore{KVStore: newSharedKV(t)}, "acme/tenants/alpha").(qrdbsdk.AtomicKVStore)

	assert.False(t, ok,
		"the wrapper namespaces keys; it cannot add an atomicity guarantee the inner store lacks")
}

func TestPrefixedKVStore_PutIfAbsentWritesUnderTheTenantPrefix(t *testing.T) {
	ctx := context.Background()
	inner := newSharedKV(t)
	scoped := scopedAtomic(t, inner, "acme/tenants/alpha")

	stored, err := scoped.PutIfAbsent(ctx, "nonces/n1", []byte("alpha-nonce"))
	require.NoError(t, err)
	require.True(t, stored)

	// The inner store must hold the fully-qualified key: a wrapper that
	// forwarded the guarded write WITHOUT the prefix would round-trip through
	// its own Get and still collide across tenants.
	value, err := inner.Get(ctx, "acme/tenants/alpha/nonces/n1")
	require.NoError(t, err)
	assert.Equal(t, []byte("alpha-nonce"), value)

	// Absence is checked with Exists, not Get: this inner store is a
	// kvadapter, which reports a missing key as a QRDBError NotFound rather
	// than as (nil, nil) so the DAO layer can recognise it.
	unprefixed, err := inner.Exists(ctx, "nonces/n1")
	require.NoError(t, err)
	assert.False(t, unprefixed, "nothing may be written at the unprefixed key")
}

// TestPrefixedKVStore_PutIfAbsentIsolatesTenants is the property the prefix
// exists for, asserted on the guarded path: one tenant taking a key must not
// stop another tenant taking the same relative key.
func TestPrefixedKVStore_PutIfAbsentIsolatesTenants(t *testing.T) {
	ctx := context.Background()
	inner := newSharedKV(t)
	alpha := scopedAtomic(t, inner, "acme/tenants/alpha")
	beta := scopedAtomic(t, inner, "acme/tenants/beta")

	stored, err := alpha.PutIfAbsent(ctx, "orders/1", []byte("alpha-order"))
	require.NoError(t, err)
	require.True(t, stored)

	stored, err = beta.PutIfAbsent(ctx, "orders/1", []byte("beta-order"))
	require.NoError(t, err)
	assert.True(t, stored, "beta's namespace is its own; alpha's key must not block it")

	betaValue, err := beta.Get(ctx, "orders/1")
	require.NoError(t, err)
	assert.Equal(t, []byte("beta-order"), betaValue)

	alphaValue, err := alpha.Get(ctx, "orders/1")
	require.NoError(t, err)
	assert.Equal(t, []byte("alpha-order"), alphaValue, "beta's write must not have landed on alpha's key")
}

func TestPrefixedKVStore_CompareAndDeleteReleasesTheTenantsOwnKey(t *testing.T) {
	ctx := context.Background()
	inner := newSharedKV(t)
	alpha := scopedAtomic(t, inner, "acme/tenants/alpha")
	beta := scopedAtomic(t, inner, "acme/tenants/beta")

	require.NoError(t, alpha.Put(ctx, "certificates/c1", []byte("alpha-cert")))
	require.NoError(t, beta.Put(ctx, "certificates/c1", []byte("beta-cert")))

	deleted, err := alpha.CompareAndDelete(ctx, "certificates/c1", []byte("alpha-cert"))
	require.NoError(t, err)
	assert.True(t, deleted)

	// Alpha's release must leave beta's identically-named key untouched.
	betaValue, err := beta.Get(ctx, "certificates/c1")
	require.NoError(t, err)
	assert.Equal(t, []byte("beta-cert"), betaValue)

	stillThere, err := inner.Exists(ctx, "acme/tenants/alpha/certificates/c1")
	require.NoError(t, err)
	assert.False(t, stillThere, "alpha's own key is the one that was released")
}

func TestPrefixedKVStore_CompareAndDeleteRefusesAnUnexpectedValue(t *testing.T) {
	ctx := context.Background()
	inner := newSharedKV(t)
	scoped := scopedAtomic(t, inner, "acme/tenants/alpha")
	require.NoError(t, scoped.Put(ctx, "eab/k1", []byte("current")))

	deleted, err := scoped.CompareAndDelete(ctx, "eab/k1", []byte("stale"))
	require.NoError(t, err)
	assert.False(t, deleted)

	value, err := scoped.Get(ctx, "eab/k1")
	require.NoError(t, err)
	assert.Equal(t, []byte("current"), value)
}

func TestPrefixedKVStore_CompareAndSwapSwapsTheTenantsOwnKey(t *testing.T) {
	ctx := context.Background()
	inner := newSharedKV(t)
	alpha := scopedAtomic(t, inner, "acme/tenants/alpha")
	beta := scopedAtomic(t, inner, "acme/tenants/beta")

	require.NoError(t, alpha.Put(ctx, "accounts/1", []byte("alpha-v1")))
	require.NoError(t, beta.Put(ctx, "accounts/1", []byte("beta-v1")))

	swapped, err := alpha.CompareAndSwap(ctx, "accounts/1", []byte("alpha-v1"), []byte("alpha-v2"))
	require.NoError(t, err)
	assert.True(t, swapped)

	alphaValue, err := inner.Get(ctx, "acme/tenants/alpha/accounts/1")
	require.NoError(t, err)
	assert.Equal(t, []byte("alpha-v2"), alphaValue)

	betaValue, err := inner.Get(ctx, "acme/tenants/beta/accounts/1")
	require.NoError(t, err)
	assert.Equal(t, []byte("beta-v1"), betaValue)
}

func TestPrefixedKVStore_CompareAndSwapRefusesAnUnexpectedValue(t *testing.T) {
	ctx := context.Background()
	scoped := scopedAtomic(t, newSharedKV(t), "acme/tenants/alpha")
	ctxKey := "authorizations/1"
	require.NoError(t, scoped.Put(context.Background(), ctxKey, []byte("v1")))

	swapped, err := scoped.CompareAndSwap(ctx, ctxKey, []byte("v9"), []byte("v2"))
	require.NoError(t, err)
	assert.False(t, swapped)

	value, err := scoped.Get(ctx, ctxKey)
	require.NoError(t, err)
	assert.Equal(t, []byte("v1"), value)
}

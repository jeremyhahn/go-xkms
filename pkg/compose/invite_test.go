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

package compose

import (
	"context"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// newTestInviteStore builds the invite store BuildInviteStore returns over
// an in-memory Backend — the same construction path production uses over
// whichever storage.backend is configured (memory/file/pebble/qrdb all
// support the guarded writes this store needs; see invite.go's doc
// comment) — and asserts it down to the concrete type the caching test
// needs.
func newTestInviteStore(t *testing.T) *tenantPrefixedInviteStore {
	t.Helper()
	open := func(name string) (storage.Backend, error) {
		return storage.NewMemoryBackend()
	}
	store, err := BuildInviteStore(open)
	require.NoError(t, err)
	concrete, ok := store.(*tenantPrefixedInviteStore)
	require.True(t, ok, "BuildInviteStore must return *tenantPrefixedInviteStore")
	return concrete
}

func TestBuildInviteStore_NilStorageFactory(t *testing.T) {
	_, err := BuildInviteStore(nil)
	var nilDep *NilDependencyError
	require.ErrorAs(t, err, &nilDep)
	assert.Equal(t, FeatureInvite, nilDep.Feature)
}

func TestBuildInviteStore_OpenFailure(t *testing.T) {
	open := func(name string) (storage.Backend, error) {
		return nil, assert.AnError
	}
	_, err := BuildInviteStore(open)
	require.Error(t, err)
	var buildErr *FeatureBuildError
	require.ErrorAs(t, err, &buildErr)
	assert.Equal(t, FeatureInvite, buildErr.Feature)
}

func TestTenantPrefixedInviteStore_CreateLookupRedeem(t *testing.T) {
	s := newTestInviteStore(t)
	ctx := context.Background()

	token, entity, err := s.Create(ctx, "42", "acme", time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, "42", entity.UserID)
	assert.Equal(t, "acme", entity.TenantID)

	looked, err := s.Lookup(ctx, "acme", token)
	require.NoError(t, err)
	assert.Equal(t, entity.UserID, looked.UserID)
	assert.False(t, looked.Redeemed())

	redeemed, err := s.Redeem(ctx, "acme", token)
	require.NoError(t, err)
	assert.True(t, redeemed.Redeemed())
}

// TestTenantPrefixedInviteStore_SingleUse proves the guarded write this
// store needs (storage.Backend.PutIfAbsent) is genuinely atomic over the
// default in-memory/pebble/file backends: a token redeemed once cannot be
// redeemed again.
func TestTenantPrefixedInviteStore_SingleUse(t *testing.T) {
	s := newTestInviteStore(t)
	ctx := context.Background()

	token, _, err := s.Create(ctx, "1", "acme", time.Hour)
	require.NoError(t, err)

	_, err = s.Redeem(ctx, "acme", token)
	require.NoError(t, err)

	_, err = s.Redeem(ctx, "acme", token)
	require.ErrorIs(t, err, qrdbsdk.ErrInviteAlreadyRedeemed)
}

// TestTenantPrefixedInviteStore_UnknownTokenIsNotFound proves a fabricated
// token is refused the same way a genuinely absent one is.
func TestTenantPrefixedInviteStore_UnknownTokenIsNotFound(t *testing.T) {
	s := newTestInviteStore(t)
	ctx := context.Background()

	_, err := s.Lookup(ctx, "acme", "never-issued")
	require.ErrorIs(t, err, qrdbsdk.ErrInviteNotFound)
}

// TestTenantPrefixedInviteStore_TenantIsolation is the property the
// key-prefix separation exists to provide: a token minted for one tenant
// does not resolve, and cannot be redeemed, under another tenant's name —
// the same answer a fabricated token gets, so cross-tenant probing learns
// nothing.
func TestTenantPrefixedInviteStore_TenantIsolation(t *testing.T) {
	s := newTestInviteStore(t)
	ctx := context.Background()

	token, _, err := s.Create(ctx, "7", "tenant-a", time.Hour)
	require.NoError(t, err)

	_, err = s.Lookup(ctx, "tenant-b", token)
	require.ErrorIs(t, err, qrdbsdk.ErrInviteNotFound)

	_, err = s.Redeem(ctx, "tenant-b", token)
	require.ErrorIs(t, err, qrdbsdk.ErrInviteNotFound)

	// The token is untouched by the cross-tenant attempt and still redeems
	// correctly under its own tenant.
	redeemed, err := s.Redeem(ctx, "tenant-a", token)
	require.NoError(t, err)
	assert.True(t, redeemed.Redeemed())
}

// TestTenantPrefixedInviteStore_EmptyTenantIsolatedFromLookalikeTenantName
// proves the empty-tenant sentinel segment cannot be reached by a valid
// tenant ID that merely resembles it: an operator running a tenant
// literally named "empty-tenant" does not collide with the empty-tenant
// keyspace, because the sentinel (defaultInviteStoreTenant) contains a
// colon and storage.ValidateTenantID refuses any tenant ID that does — no
// valid tenant name can ever equal it.
func TestTenantPrefixedInviteStore_EmptyTenantIsolatedFromLookalikeTenantName(t *testing.T) {
	s := newTestInviteStore(t)
	ctx := context.Background()

	require.NoError(t, storage.ValidateTenantID("empty-tenant"))
	require.Error(t, storage.ValidateTenantID(defaultInviteStoreTenant),
		"the sentinel segment must not itself be a valid tenant ID, or a real tenant could collide with it")

	token, _, err := s.Create(ctx, "9", "", time.Hour)
	require.NoError(t, err)

	_, err = s.Lookup(ctx, "empty-tenant", token)
	require.ErrorIs(t, err, qrdbsdk.ErrInviteNotFound)

	looked, err := s.Lookup(ctx, "", token)
	require.NoError(t, err)
	assert.Equal(t, "9", looked.UserID)
}

func TestTenantPrefixedInviteStore_StoreForIsCachedPerTenant(t *testing.T) {
	s := newTestInviteStore(t)

	first, err := s.storeFor("acme")
	require.NoError(t, err)
	second, err := s.storeFor("acme")
	require.NoError(t, err)
	assert.Same(t, first, second, "the per-tenant DAO store must be cached, not rebuilt per call")

	other, err := s.storeFor("other")
	require.NoError(t, err)
	assert.NotSame(t, first, other)
}

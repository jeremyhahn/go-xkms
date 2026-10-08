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

package invitetest

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errUnknownTenant = errors.New("unknown tenant")

// mapResolver routes each known tenant to its own in-memory store and refuses
// any other tenant.
type mapResolver map[string]qrdbsdk.KVStore

func (r mapResolver) Resolve(_ context.Context, tenantID string) (qrdbsdk.KVStore, error) {
	store, ok := r[tenantID]
	if !ok {
		return nil, errUnknownTenant
	}
	return store, nil
}

func newStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(mapResolver{
		"acme":   qrdbsdk.NewMemoryKVStore(),
		"globex": qrdbsdk.NewMemoryKVStore(),
	})
	require.NoError(t, err)
	return store
}

func TestStore_CreateLookupRedeem(t *testing.T) {
	ctx := t.Context()
	store := newStore(t)

	token, created, err := store.Create(ctx, "alice", "acme", time.Hour)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.Equal(t, "alice", created.UserID)

	found, err := store.Lookup(ctx, "acme", token)
	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)

	redeemed, err := store.Redeem(ctx, "acme", token)
	require.NoError(t, err)
	assert.Equal(t, created.ID, redeemed.ID)

	_, err = store.Redeem(ctx, "acme", token)
	assert.Error(t, err, "an invitation redeems exactly once")
}

func TestStore_TokenIsConfinedToItsTenant(t *testing.T) {
	ctx := t.Context()
	store := newStore(t)

	token, _, err := store.Create(ctx, "alice", "acme", time.Hour)
	require.NoError(t, err)

	_, err = store.Lookup(ctx, "globex", token)
	assert.ErrorIs(t, err, qrdbsdk.ErrInviteNotFound)
}

func TestStore_CreateSurfacesResolverError(t *testing.T) {
	store := newStore(t)

	_, _, err := store.Create(t.Context(), "alice", "initech", time.Hour)
	assert.ErrorIs(t, err, errUnknownTenant)
}

func TestNew_NilResolver(t *testing.T) {
	store, err := New(nil)
	assert.Error(t, err)
	assert.Nil(t, store)
}

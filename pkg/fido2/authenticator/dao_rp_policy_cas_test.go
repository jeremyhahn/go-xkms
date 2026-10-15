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

package authenticator

import (
	"context"
	"fmt"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDAORPPolicyStoreShared creates a DAORPPolicyStore and returns the
// KVStore backing it so tests can build a second, independent store instance
// over the same records — the two-writer topology of issue #326.
func newTestDAORPPolicyStoreShared(t *testing.T) (*DAORPPolicyStore, qrdbsdk.KVStore) {
	t.Helper()
	backend := xkms.NewStorageMemory()
	t.Cleanup(func() { backend.Close() })

	kvStore, err := xkms.NewKVStoreAdapter(backend)
	require.NoError(t, err)

	store, err := NewDAORPPolicyStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	return store, kvStore
}

// hookedRPPolicyDAO wraps the real GenericDAO and runs afterGet between the
// store's version-observing read and its conditional save, so tests can land
// a concurrent write deterministically inside the CAS window.
type hookedRPPolicyDAO struct {
	qrdbsdk.GenericDAO[*RPPolicyEntity]
	mu       sync.Mutex
	getCount int
	afterGet func(getCount int)
}

func (h *hookedRPPolicyDAO) Get(ctx context.Context, id uint64) (*RPPolicyEntity, error) {
	entity, err := h.GenericDAO.Get(ctx, id)
	h.mu.Lock()
	h.getCount++
	count := h.getCount
	hook := h.afterGet
	h.mu.Unlock()
	if hook != nil {
		hook(count)
	}
	return entity, err
}

func (h *hookedRPPolicyDAO) gets() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.getCount
}

func fullTestRPPolicy(rpID string) *RPPolicy {
	up := true
	return &RPPolicy{
		RPID:                rpID,
		UVOverride:          "required",
		UPOverride:          &up,
		AttestationOverride: "direct",
		Enterprise:          true,
		Blocked:             false,
	}
}

// TestDAORPPolicyStore_UpdatePolicy_PartialPreservesStoredFields is the #321
// regression probe: a full policy followed by an update carrying only Blocked
// must leave the SO's UV, UP and attestation overrides and the Enterprise
// flag intact while changing Blocked.
func TestDAORPPolicyStore_UpdatePolicy_PartialPreservesStoredFields(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	require.NoError(t, store.SetPolicy(fullTestRPPolicy("rp.example")))

	blocked := true
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{
		RPID:    "rp.example",
		Blocked: &blocked,
	}))

	loaded, err := store.GetPolicy("rp.example")
	require.NoError(t, err)
	assert.Equal(t, "required", loaded.UVOverride, "UVOverride must survive a partial update")
	require.NotNil(t, loaded.UPOverride, "UPOverride must survive a partial update")
	assert.True(t, *loaded.UPOverride)
	assert.Equal(t, "direct", loaded.AttestationOverride, "AttestationOverride must survive a partial update")
	assert.True(t, loaded.Enterprise, "Enterprise must survive a partial update")
	assert.True(t, loaded.Blocked, "Blocked was carried by the update and must change")
}

// TestDAORPPolicyStore_UpdatePolicy_BlockSurvivesUnrelatedUpdate asserts the
// sharpest #321 consequence: blocking an RP and then changing an unrelated
// field must not lift the block.
func TestDAORPPolicyStore_UpdatePolicy_BlockSurvivesUnrelatedUpdate(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	blocked := true
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "blocked.example", Blocked: &blocked}))

	uv := "required"
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "blocked.example", UVOverride: &uv}))

	loaded, err := store.GetPolicy("blocked.example")
	require.NoError(t, err)
	assert.True(t, loaded.Blocked, "an update that omits Blocked must not lift an RP block")
	assert.Equal(t, "required", loaded.UVOverride)
}

// TestDAORPPolicyStore_UpdatePolicy_ExplicitZeroTakesEffect asserts the
// distinction merge semantics must preserve: a field the caller explicitly
// sets to its zero value does take effect.
func TestDAORPPolicyStore_UpdatePolicy_ExplicitZeroTakesEffect(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	policy := fullTestRPPolicy("zero.example")
	policy.Blocked = true
	require.NoError(t, store.SetPolicy(policy))

	unblocked := false
	clearUV := ""
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{
		RPID:       "zero.example",
		Blocked:    &unblocked,
		UVOverride: &clearUV,
	}))

	loaded, err := store.GetPolicy("zero.example")
	require.NoError(t, err)
	assert.False(t, loaded.Blocked, "an explicit false must lift the block")
	assert.Equal(t, "", loaded.UVOverride, "an explicit empty string must clear the override")
	assert.Equal(t, "direct", loaded.AttestationOverride, "fields not carried must survive")
	assert.True(t, loaded.Enterprise)
}

// TestDAORPPolicyStore_UpdatePolicy_CreatesWhenAbsent verifies upsert
// behavior: updating an RPID with no stored policy creates one carrying
// exactly the supplied fields.
func TestDAORPPolicyStore_UpdatePolicy_CreatesWhenAbsent(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	blocked := true
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "new.example", Blocked: &blocked}))

	loaded, err := store.GetPolicy("new.example")
	require.NoError(t, err)
	assert.True(t, loaded.Blocked)
	assert.Equal(t, "", loaded.UVOverride)
	assert.Nil(t, loaded.UPOverride)
	assert.False(t, loaded.Enterprise)
}

func TestDAORPPolicyStore_UpdatePolicy_InvalidInputs(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	require.ErrorIs(t, store.UpdatePolicy(nil), ErrRPPolicyUpdateNil)
	require.ErrorIs(t, store.UpdatePolicy(&RPPolicyUpdate{}), ErrRPPolicyInvalidRPID)

	badUV := "sometimes"
	require.ErrorIs(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "rp.example", UVOverride: &badUV}), ErrInvalidParameter)

	badAtt := "maybe"
	require.ErrorIs(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "rp.example", AttestationOverride: &badAtt}), ErrInvalidParameter)
}

func TestDAORPPolicyStore_UpdatePolicy_Closed(t *testing.T) {
	store := newTestDAORPPolicyStore(t)
	require.NoError(t, store.Close())

	blocked := true
	require.ErrorIs(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "rp.example", Blocked: &blocked}), ErrRPPolicyStoreClosed)
}

// TestDAORPPolicyStore_UpdatePolicy_InterleavedWriterRetries lands a full
// concurrent write deterministically between UpdatePolicy's version-observing
// read and its conditional save. The CAS condition must fail, the update must
// retry against the fresh record, and BOTH writers' fields must land (#326).
func TestDAORPPolicyStore_UpdatePolicy_InterleavedWriterRetries(t *testing.T) {
	store, kvStore := newTestDAORPPolicyStoreShared(t)

	require.NoError(t, store.SetPolicy(fullTestRPPolicy("race.example")))

	// A second, independent writer over the same records.
	otherWriter, err := NewDAORPPolicyStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { otherWriter.Close() })

	hooked := &hookedRPPolicyDAO{GenericDAO: store.dao}
	store.dao = hooked

	// On the first observed read only, the other writer changes UVOverride —
	// bumping the stored version after this store observed it.
	hooked.afterGet = func(getCount int) {
		if getCount != 1 {
			return
		}
		uv := "discouraged"
		require.NoError(t, otherWriter.UpdatePolicy(&RPPolicyUpdate{RPID: "race.example", UVOverride: &uv}))
	}

	blocked := true
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "race.example", Blocked: &blocked}))
	assert.Equal(t, 2, hooked.gets(), "the failed CAS must trigger exactly one retry read")

	loaded, err := store.GetPolicy("race.example")
	require.NoError(t, err)
	assert.True(t, loaded.Blocked, "this writer's field must land")
	assert.Equal(t, "discouraged", loaded.UVOverride, "the interleaved writer's field must land too")
	assert.Equal(t, "direct", loaded.AttestationOverride)
	assert.True(t, loaded.Enterprise)
}

// TestDAORPPolicyStore_UpdatePolicy_ConflictExhausted forces the CAS
// condition to fail on every bounded attempt and asserts the typed conflict
// error — never a silent success over a lost update (#326).
func TestDAORPPolicyStore_UpdatePolicy_ConflictExhausted(t *testing.T) {
	store, kvStore := newTestDAORPPolicyStoreShared(t)

	require.NoError(t, store.SetPolicy(fullTestRPPolicy("conflict.example")))

	otherWriter, err := NewDAORPPolicyStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { otherWriter.Close() })

	hooked := &hookedRPPolicyDAO{GenericDAO: store.dao}
	store.dao = hooked

	// After EVERY read this store performs, the other writer lands another
	// update, so the observed version is always stale by save time.
	uvValues := []string{"discouraged", "preferred", "required", "", "preferred"}
	hooked.afterGet = func(getCount int) {
		uv := uvValues[(getCount-1)%len(uvValues)]
		require.NoError(t, otherWriter.UpdatePolicy(&RPPolicyUpdate{RPID: "conflict.example", UVOverride: &uv}))
	}

	blocked := true
	err = store.UpdatePolicy(&RPPolicyUpdate{RPID: "conflict.example", Blocked: &blocked})
	require.ErrorIs(t, err, ErrRPPolicyConflict)
	assert.Equal(t, rpPolicyCASMaxAttempts, hooked.gets(), "every bounded attempt must re-read before giving up")
}

// TestDAORPPolicyStore_SetPolicy_ConflictExhausted asserts the full-replace
// path reports the same typed conflict instead of silently overwriting a
// record whose version moved on every attempt (#326).
func TestDAORPPolicyStore_SetPolicy_ConflictExhausted(t *testing.T) {
	store, kvStore := newTestDAORPPolicyStoreShared(t)

	require.NoError(t, store.SetPolicy(fullTestRPPolicy("setconflict.example")))

	otherWriter, err := NewDAORPPolicyStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { otherWriter.Close() })

	hooked := &hookedRPPolicyDAO{GenericDAO: store.dao}
	store.dao = hooked
	hooked.afterGet = func(int) {
		enterprise := true
		require.NoError(t, otherWriter.UpdatePolicy(&RPPolicyUpdate{RPID: "setconflict.example", Enterprise: &enterprise}))
	}

	err = store.SetPolicy(fullTestRPPolicy("setconflict.example"))
	require.ErrorIs(t, err, ErrRPPolicyConflict)
}

// TestDAORPPolicyStore_ConcurrentUpdaters_BothFieldsLand runs two genuinely
// concurrent updaters per iteration under the race detector — the two
// concurrent writers of issue #326, sharing one store instance the way the
// authenticator's callers do — each carrying a different field, and asserts
// both fields land. On unmodified main the lost update manifests as one of
// them missing.
func TestDAORPPolicyStore_ConcurrentUpdaters_BothFieldsLand(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	const iterations = 100
	for i := 0; i < iterations; i++ {
		rpID := fmt.Sprintf("concurrent-%d.example", i)
		require.NoError(t, store.SetPolicy(&RPPolicy{RPID: rpID}))

		var wg sync.WaitGroup
		var errBlocked, errUV error
		wg.Add(2)
		go func() {
			defer wg.Done()
			blocked := true
			errBlocked = store.UpdatePolicy(&RPPolicyUpdate{RPID: rpID, Blocked: &blocked})
		}()
		go func() {
			defer wg.Done()
			uv := "required"
			errUV = store.UpdatePolicy(&RPPolicyUpdate{RPID: rpID, UVOverride: &uv})
		}()
		wg.Wait()

		require.NoError(t, errBlocked)
		require.NoError(t, errUV)

		loaded, err := store.GetPolicy(rpID)
		require.NoError(t, err)
		require.True(t, loaded.Blocked, "iteration %d: Blocked lost to a concurrent writer", i)
		require.Equal(t, "required", loaded.UVOverride, "iteration %d: UVOverride lost to a concurrent writer", i)
	}
}

// TestDAORPPolicyStore_SetPolicy_VersionIncrements verifies every save bumps
// the stored optimistic-concurrency version, which is what makes the CAS
// condition able to detect a concurrent writer at all.
func TestDAORPPolicyStore_SetPolicy_VersionIncrements(t *testing.T) {
	store := newTestDAORPPolicyStore(t)

	require.NoError(t, store.SetPolicy(&RPPolicy{RPID: "versioned.example"}))

	entity, err := store.dao.Get(context.Background(), store.computeID("versioned.example"))
	require.NoError(t, err)
	assert.Equal(t, int64(1), entity.GetVersion())

	blocked := true
	require.NoError(t, store.UpdatePolicy(&RPPolicyUpdate{RPID: "versioned.example", Blocked: &blocked}))

	entity, err = store.dao.Get(context.Background(), store.computeID("versioned.example"))
	require.NoError(t, err)
	assert.Equal(t, int64(2), entity.GetVersion())
}

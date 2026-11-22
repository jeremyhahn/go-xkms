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

package xkms

// Tests for Codex findings 2 and 3 on row #2218: a rotation whose claim was
// taken over never deletes the new holder's key, and a cancelled request
// context still releases the claim.

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/claimclock"
	"github.com/jeremyhahn/go-xkms/pkg/keyversion"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestRotateKey_ExpiredClaimHolderNeverDeletesTheNewHoldersKey is Codex
// finding 2: rotator A claims the record, finds an interrupted rotation's
// key under the next version's name and stalls before removing it; its claim
// expires, rotator B in another process takes the claim over and records the
// next version; A then resumes. A must fail with a version conflict and
// leave B's recorded key in place, so what B's key signs still verifies.
func TestRotateKey_ExpiredClaimHolderNeverDeletesTheNewHoldersKey(t *testing.T) {
	ctx := context.Background()
	here, elsewhere, shared := twoProcesses(t)
	genKey(t, here, "", "k", "ed25519", 0)
	// An interrupted rotation left version 2's backend key unrecorded.
	_, err := shared.GenerateEd25519(ctx, &types.KeyAttributes{CN: "k--v2", KeyType: types.KeyTypeSigning, StoreType: types.StoreSoftware})
	require.NoError(t, err)

	var other *rotation
	var otherErr error
	b := &deleteHookBackend{Backend: shared, beforeDelete: func(ctx context.Context) {
		// A stalls here for longer than ClaimTTL: B runs past A's claim
		// expiry.
		claimclock.Now = func() time.Time { return time.Now().Add(keyversion.ClaimTTL + time.Minute) }
		defer func() { claimclock.Now = time.Now }()
		other, otherErr = elsewhere.rotateKey(ctx, shared, "software", "k")
	}}
	t.Cleanup(func() { claimclock.Now = time.Now })
	_, mineErr := here.rotateKey(ctx, b, "software", "k")
	require.NoError(t, otherErr, "B takes the expired claim over and records its version")
	require.ErrorIs(t, mineErr, keyversion.ErrVersionConflict, "A lost its claim")

	store, err := here.requireVersionStore()
	require.NoError(t, err)
	stored, found, err := store.Load(ctx, "", "software", "k")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, other.version, stored.Current, "the recorded version is B's")
	got, err := here.GetKey(ctx, "software", "k")
	require.NoError(t, err, "B's recorded backend key still exists")
	want, err := pubKeyPEM(other.key)
	require.NoError(t, err)
	assert.Equal(t, want, got.PublicKeyPEM, "the current key material is B's")

	data := []byte("signed under B's version")
	sig := sign(t, here, "k", data)
	assert.Equal(t, other.version, sig.KeyVersion)
	resp, err := verify(here, "k", data, sig.Signature, other.version)
	require.NoError(t, err)
	assert.True(t, resp.Valid, "B's version signs and verifies")
}

// cancelFailGenerateBackend cancels the rotation's request context and fails
// the key generation, modelling a request that times out mid-rotation after
// its claim was taken.
type cancelFailGenerateBackend struct {
	Backend
	cancel context.CancelFunc
}

func (b *cancelFailGenerateBackend) GenerateEd25519(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.cancel()
	return nil, errors.New("injected generate failure")
}

// TestRotateKey_CancelledRequestReleasesItsClaim is Codex finding 3: a
// rotation whose request context is cancelled after it took the claim, and
// whose backend then fails, must still release the claim, so the next
// rotation is not refused with a version conflict until ClaimTTL.
func TestRotateKey_CancelledRequestReleasesItsClaim(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "k", "ed25519", 0)
	shared, err := svc.LookupBackend("software")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = svc.rotateKey(ctx, &cancelFailGenerateBackend{Backend: shared, cancel: cancel}, "software", "k")
	require.Error(t, err)

	next, err := svc.rotateKey(context.Background(), shared, "software", "k")
	require.NoError(t, err, "the cancelled rotation released its claim")
	assert.NotZero(t, next.version)
}

// TestRotateKey_TakeoverReclaimsTheCrashedRotatorsVersion: a rotator
// reserves version 2, creates K--v2 and crashes before recording it. Once
// its claim expires, the next rotation reserves version 3 and removes K--v2,
// which no record holds and RetireKeyVersion could never reach.
func TestRotateKey_TakeoverReclaimsTheCrashedRotatorsVersion(t *testing.T) {
	svc := setupDeriveService(t)
	ctx := context.Background()
	genKey(t, svc, "", "k", "ed25519", 0)
	b, err := svc.LookupBackend("software")
	require.NoError(t, err)
	store, err := svc.requireVersionStore()
	require.NoError(t, err)

	// The crashed rotator: claim, generate, never record or release.
	_, reserved, err := store.Claim(ctx, "", "software", "k", nil)
	require.NoError(t, err)
	require.Equal(t, uint32(2), reserved)
	_, err = b.GenerateEd25519(ctx, &types.KeyAttributes{CN: "k--v2", KeyType: types.KeyTypeSigning, StoreType: types.StoreSoftware})
	require.NoError(t, err)

	claimclock.Now = func() time.Time { return time.Now().Add(keyversion.ClaimTTL + time.Minute) }
	t.Cleanup(func() { claimclock.Now = time.Now })
	assert.Equal(t, uint32(3), rotate(t, svc, "", "k"), "the takeover keeps distinct reservations")

	keys, err := b.ListKeys(ctx)
	require.NoError(t, err)
	var names []string
	for _, attrs := range keys {
		names = append(names, attrs.CN)
	}
	assert.NotContains(t, names, "k--v2", "the abandoned version is reclaimed")
	assert.Contains(t, names, "k", "the recorded version 1 is never deleted")
	assert.Contains(t, names, "k--v3")

	stored, found, err := store.Load(ctx, "", "software", "k")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, uint32(3), stored.Current)
	_, err = stored.Version(2)
	assert.Error(t, err, "the record lists no version 2")
	_, err = stored.Version(1)
	assert.NoError(t, err)
}

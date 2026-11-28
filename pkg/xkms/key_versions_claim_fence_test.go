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
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/internal/claimclock"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
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

// A version-state write in another process lands while a rotation holds
// its claim, between the rotation's orphan check and its removal of the
// orphan (Codex round 4, #2225). Recording the orphan's version as current
// must fail, or the orphan's key material must survive the rotation.
func TestRotateKey_PutDuringClaimNeverLosesRecordedMaterial(t *testing.T) {
	ctx := context.Background()
	here, elsewhere, shared := twoProcesses(t)
	genKey(t, here, "", "k", "ed25519", 0)
	orphan, err := shared.GenerateEd25519(ctx, &types.KeyAttributes{CN: "k--v2", KeyType: types.KeyTypeSigning, StoreType: types.StoreSoftware})
	require.NoError(t, err)
	orphanPEM, err := pubKeyPEM(orphan)
	require.NoError(t, err)

	var writeErr error
	b := &deleteHookBackend{Backend: shared, beforeDelete: func(ctx context.Context) {
		_, writeErr = elsewhere.updateVersions(ctx, "software", "", "k", func(k *versionedKey) (bool, error) {
			k.record.AddCurrent(2, time.Now().UTC(), "state-writer")
			return true, nil
		})
	}}
	_, _ = here.rotateKey(ctx, b, "software", "k")

	if writeErr != nil {
		require.ErrorIs(t, writeErr, keyversion.ErrVersionConflict)
		return
	}
	store, err := here.requireVersionStore()
	require.NoError(t, err)
	stored, found, err := store.Load(ctx, "", "software", "k")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint32(2), stored.Current, "the state writer recorded version 2")
	got, err := here.GetKey(ctx, "software", "k")
	require.NoError(t, err, "the recorded version's backend key exists")
	assert.Equal(t, orphanPEM, got.PublicKeyPEM, "version 2's recorded key material survives the rotation")
}

// A version-state change that read the record before another process
// rotated the key must not write the stale record back over the newer
// version (Codex round 4, #2225).
func TestUpdateVersions_StaleReadDoesNotDropANewerVersion(t *testing.T) {
	ctx := context.Background()
	kv := &writeAfterReadKV{AtomicKVStore: qrdbsdk.NewMemoryKVStore()}
	inner, err := setupDeriveService(t).LookupBackend("software")
	require.NoError(t, err)
	armAt := 0
	lb := &listHookBackend{Backend: inner, onList: func(n int) {
		if n == armAt { // the listing under the key's lock, just before the read
			kv.arm()
		}
	}}
	svc, err := NewService(&ServiceConfig{
		Backends:       map[string]Backend{"software": lb},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	store, err := keyversion.NewStore(dao.NewStoreFactory(kv))
	require.NoError(t, err)
	svc.SetKeyVersionStore(store)
	other, err := keyversion.NewStore(dao.NewStoreFactory(kv))
	require.NoError(t, err)

	genKey(t, svc, "", "k", "ed25519", 0)
	require.Equal(t, uint32(2), rotate(t, svc, "", "k"))

	// Another process rotates the key to version 3 right after the state
	// change reads the record under its lock.
	kv.afterRead = func() {
		rec, found, err := other.Load(ctx, "", "software", "k")
		require.NoError(t, err)
		require.True(t, found)
		read := *rec
		read.Versions = slices.Clone(rec.Versions)
		rec.AddCurrent(3, time.Now().UTC(), "other-rotator")
		require.NoError(t, other.CompareAndPut(ctx, "", "", &read, rec))
	}
	armAt = lb.n + 2

	_, err = svc.DisableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
	require.ErrorIs(t, err, keyversion.ErrVersionConflict)

	stored, found, err := store.Load(ctx, "", "software", "k")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, uint32(3), stored.Current, "the newer version stays current")
	_, err = stored.Version(3)
	assert.NoError(t, err, "the newer version stays recorded")
}

// Retirement reads the record (versions 1 and 2, current 3), then another
// process changes it, by disabling version 2 or by taking a rotation claim,
// before the retirement is stored (Codex round 5, #2225). The stored record
// must never advertise a version whose key material is gone, and an
// unversioned Verify must still succeed.
func TestRetireKeyVersion_ConcurrentChangeNeverStrandsAnAdvertisedVersion(t *testing.T) {
	for name, interleave := range map[string]func(ctx context.Context, t *testing.T, elsewhere *XKMSService){
		"disable version 2": func(ctx context.Context, t *testing.T, elsewhere *XKMSService) {
			_, err := elsewhere.DisableKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 2})
			require.NoError(t, err)
		},
		"live rotation claim": func(ctx context.Context, t *testing.T, elsewhere *XKMSService) {
			store, err := elsewhere.requireVersionStore()
			require.NoError(t, err)
			rec, found, err := store.Load(ctx, "", "software", "k")
			require.NoError(t, err)
			require.True(t, found)
			_, _, err = store.Claim(ctx, "", "software", "k", rec)
			require.NoError(t, err)
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			kv := qrdbsdk.NewMemoryKVStore()
			base := setupDeriveService(t)
			shared, err := base.LookupBackend("software")
			require.NoError(t, err)
			hook := &deleteHookBackend{Backend: shared}
			newProcess := func(b Backend) *XKMSService {
				svc, err := NewService(&ServiceConfig{Backends: map[string]Backend{"software": b}, DefaultBackend: "software"})
				require.NoError(t, err)
				store, err := keyversion.NewStore(dao.NewStoreFactory(kv))
				require.NoError(t, err)
				svc.SetKeyVersionStore(store)
				return svc
			}
			retirer, elsewhere := newProcess(hook), newProcess(shared)

			genKey(t, elsewhere, "", "k", "ed25519", 0)
			rotate(t, elsewhere, "", "k")
			require.Equal(t, uint32(3), rotate(t, elsewhere, "", "k"))
			data := []byte("signed under version 3")
			sig := sign(t, elsewhere, "k", data)

			hook.beforeDelete = func(ctx context.Context) { interleave(ctx, t, elsewhere) }
			_, retireErr := retirer.RetireKeyVersion(ctx, &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1})
			if retireErr != nil {
				require.ErrorIs(t, retireErr, keyversion.ErrVersionConflict)
			}

			store, err := elsewhere.requireVersionStore()
			require.NoError(t, err)
			stored, found, err := store.Load(ctx, "", "software", "k")
			require.NoError(t, err)
			require.True(t, found)
			for _, v := range stored.Versions {
				if v.State == keyversion.StateRetired {
					continue
				}
				_, err := findKeyAttrs(ctx, shared, keyversion.Name("k", v.Number))
				assert.NoError(t, err, "advertised version %d keeps its key material", v.Number)
			}
			resp, err := verify(elsewhere, "k", data, sig.Signature, 0)
			require.NoError(t, err, "unversioned Verify still builds its trial versions")
			assert.True(t, resp.Valid)
		})
	}
}

// failDeleteBackend fails its next DeleteKey, modelling a crash between
// storing a retirement and deleting the version's key material.
type failDeleteBackend struct {
	Backend
	fail bool
}

func (b *failDeleteBackend) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	if b.fail {
		b.fail = false
		return errors.New("injected delete failure")
	}
	return b.Backend.DeleteKey(ctx, attrs)
}

// A retirement whose key delete fails after the record said retired leaves
// a record no signer or verifier uses; retrying the retirement finishes the
// delete.
func TestRetireKeyVersion_RetryFinishesAnInterruptedDelete(t *testing.T) {
	ctx := context.Background()
	inner, err := setupDeriveService(t).LookupBackend("software")
	require.NoError(t, err)
	fb := &failDeleteBackend{Backend: inner}
	svc, err := NewService(&ServiceConfig{Backends: map[string]Backend{"software": fb}, DefaultBackend: "software"})
	require.NoError(t, err)
	store, err := keyversion.NewStore(dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore()))
	require.NoError(t, err)
	svc.SetKeyVersionStore(store)
	genKey(t, svc, "", "k", "ed25519", 0)
	rotate(t, svc, "", "k")
	data := []byte("signed under version 2")
	sig := sign(t, svc, "k", data)

	fb.fail = true
	req := &transport.KeyVersionRequest{Backend: "software", KeyID: "k", Version: 1}
	_, err = svc.RetireKeyVersion(ctx, req)
	require.Error(t, err)
	stored, found, err := store.Load(ctx, "", "software", "k")
	require.NoError(t, err)
	require.True(t, found)
	v1, err := stored.Version(1)
	require.NoError(t, err)
	assert.Equal(t, keyversion.StateRetired, v1.State, "the retirement is stored before the delete")
	resp, err := verify(svc, "k", data, sig.Signature, 0)
	require.NoError(t, err)
	assert.True(t, resp.Valid)

	_, err = svc.RetireKeyVersion(ctx, req)
	require.NoError(t, err, "the retry finishes the delete")
	_, err = findKeyAttrs(ctx, inner, "k")
	assert.ErrorIs(t, err, ErrKeyNotFound, "version 1's key material is gone")
	_, err = svc.RetireKeyVersion(ctx, req)
	assert.ErrorAs(t, err, new(*keyversion.RetiredVersionError), "a finished retirement is retired")
}

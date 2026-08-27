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

package sealed

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EVERY FAILURE ON THIS PATH MUST BE AN ERROR, NEVER A REFUSAL.
//
// deleted=false with a nil error says the guard was evaluated and lost, and a
// caller acts on it by giving up its claim. Each fault below is a case where
// the guard was NOT evaluated, so collapsing it into a refusal would make a
// caller abandon a claim it still holds — the stale-releaser defect this verb
// exists to close, reached by a different route.
//
// Only injected faults separate the two: the contract tests never fail a read,
// so a regression that turned any of these into (false, nil) would ship green.

// faultyInner is a real memory backend with individually failable operations,
// so each test exercises the genuine code path up to the injected fault.
type faultyInner struct {
	storage.Backend

	getErr error
	cadErr error
}

func newFaultyInner(t *testing.T) *faultyInner {
	t.Helper()
	inner := storage.NewMemory()
	t.Cleanup(func() { _ = inner.Close() })
	return &faultyInner{Backend: inner}
}

func (f *faultyInner) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.Backend.Get(ctx, key)
}

func (f *faultyInner) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if f.cadErr != nil {
		return false, f.cadErr
	}
	return f.Backend.(storage.CompareAndDeleter).CompareAndDelete(ctx, key, expected)
}

// noCADBackend hides the inner backend's guarded-delete capability, standing in
// for a backend that legitimately has none (the hardware adapter, the remote
// PKCS#11 state store).
type noCADBackend struct{ storage.Backend }

func newSealedOver(t *testing.T, inner storage.Backend) *Backend {
	t.Helper()
	b, err := New(inner, randomizingSealer{}, nil)
	require.NoError(t, err)
	return b
}

// A read failure that is NOT "absent" leaves the outcome unknown. Only
// storage.ErrNotFound may become a refusal; everything else must error.
func TestCompareAndDelete_NonAbsentReadFailureIsAnError(t *testing.T) {
	ctx := context.Background()
	inner := newFaultyInner(t)
	b := newSealedOver(t, inner)

	const key = "keys/fault-subject"
	require.NoError(t, b.Put(ctx, key, []byte("value-A")))

	injected := errors.New("injected read fault")
	inner.getErr = injected

	deleted, err := b.CompareAndDelete(ctx, key, []byte("value-A"))

	require.Error(t, err, "a read fault is not a refusal")
	assert.False(t, deleted)
	assert.ErrorIs(t, err, injected)
	assert.NotErrorIs(t, err, storage.ErrNotFound,
		"and it must not be mistaken for the absent case, which IS a refusal")

	// Nothing removed under the fault.
	inner.getErr = nil
	ok, err := b.Exists(ctx, key)
	require.NoError(t, err)
	assert.True(t, ok, "a failed guard must leave the value in place")
}

// A malformed envelope means the stored bytes cannot be interpreted at all. It
// is damage, not a mismatch, so it must not be reported as "the value differed".
func TestCompareAndDelete_MalformedEnvelopeIsAnError(t *testing.T) {
	ctx := context.Background()
	inner := newFaultyInner(t)
	b := newSealedOver(t, inner)

	const key = "keys/fault-subject"
	// Write raw non-JSON straight past the sealing layer.
	require.NoError(t, inner.Put(ctx, key, []byte("this is not a sealed envelope")))

	deleted, err := b.CompareAndDelete(ctx, key, []byte("value-A"))

	require.Error(t, err)
	assert.False(t, deleted)
	assert.ErrorIs(t, err, ErrUnmarshalFailed)

	ok, existsErr := b.Exists(ctx, key)
	require.NoError(t, existsErr)
	assert.True(t, ok, "damaged data must not be deleted by a guard that could not read it")
}

// An inner backend without the capability cannot perform the guarded delete at
// all. Refusing with deleted=false would send a caller into a retry loop that
// can never succeed.
func TestCompareAndDelete_InnerWithoutCapabilityIsAnError(t *testing.T) {
	ctx := context.Background()
	inner := storage.NewMemory()
	t.Cleanup(func() { _ = inner.Close() })
	b := newSealedOver(t, noCADBackend{inner})

	const key = "keys/fault-subject"
	require.NoError(t, b.Put(ctx, key, []byte("value-A")))

	// The guard MATCHES, so only the missing capability can stop it — the
	// refusal cannot be mistaken for a lost comparison.
	deleted, err := b.CompareAndDelete(ctx, key, []byte("value-A"))

	require.Error(t, err)
	assert.False(t, deleted)
	assert.ErrorIs(t, err, storage.ErrCompareAndDeleteUnsupported)

	ok, existsErr := b.Exists(ctx, key)
	require.NoError(t, existsErr)
	assert.True(t, ok)
}

// The inner guarded delete failing is the last step, AFTER the guard matched.
// Its failure is an unknown outcome — the delete may or may not have applied —
// so it must never be flattened into a refusal.
func TestCompareAndDelete_InnerGuardedDeleteFailureIsAnError(t *testing.T) {
	ctx := context.Background()
	inner := newFaultyInner(t)
	b := newSealedOver(t, inner)

	const key = "keys/fault-subject"
	require.NoError(t, b.Put(ctx, key, []byte("value-A")))

	injected := errors.New("injected guarded-delete fault")
	inner.cadErr = injected

	deleted, err := b.CompareAndDelete(ctx, key, []byte("value-A"))

	require.Error(t, err, "the delete may or may not have applied; that is not a refusal")
	assert.False(t, deleted)
	assert.ErrorIs(t, err, injected)
}

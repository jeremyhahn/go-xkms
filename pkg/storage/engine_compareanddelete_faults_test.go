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

package storage

import (
	"context"
	"errors"
	"testing"

	qrdbstorage "github.com/jeremyhahn/go-qrdb/sdk/go/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// THE BOUNDARY THIS FILE EXISTS TO DEFEND. deleted=false with a nil error is a
// LOAD-BEARING CLAIM: the guard was evaluated and it lost. A caller acts on it
// by giving up its claim. An I/O failure means the opposite — the guard was
// never evaluated and the outcome is unknown — so it must be an error.
//
// The two are one `return` apart in every implementation, and a regression that
// collapsed a failure into a refusal would be invisible: the happy-path and
// contract tests all still pass, because they never fail a read. Only injected
// faults distinguish them.

// faultyStorage is a real memory engine with individually failable operations.
// Embedding rather than reimplementing keeps every other method honest, so a
// test exercises the real code path right up to the injected fault.
type faultyStorage struct {
	qrdbstorage.Storage

	existsErr error
	getErr    error
	deleteErr error
}

func newFaultyStorage() *faultyStorage {
	return &faultyStorage{Storage: qrdbstorage.NewMemoryStorage()}
}

func (f *faultyStorage) Exists(key []byte) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	return f.Storage.Exists(key)
}

func (f *faultyStorage) Get(key []byte) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.Storage.Get(key)
}

func (f *faultyStorage) Delete(key []byte) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.Storage.Delete(key)
}

// Each of the three operations CompareAndDelete performs must surface its
// failure as an error rather than as a refusal, and must carry the operation
// and key so an operator can place it.
func TestEngineBackend_CompareAndDeleteSurfacesFaultsAsErrors(t *testing.T) {
	ctx := context.Background()
	const key = "keys/fault-subject"
	value := []byte("value-A")

	for _, tc := range []struct {
		name   string
		inject func(*faultyStorage, error)
	}{
		{"Exists fails", func(f *faultyStorage, e error) { f.existsErr = e }},
		{"Get fails", func(f *faultyStorage, e error) { f.getErr = e }},
		{"Delete fails", func(f *faultyStorage, e error) { f.deleteErr = e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			injected := errors.New("injected engine fault")
			eng := newFaultyStorage()
			b := NewEngineBackend(eng)

			// Seed BEFORE arming the fault, so the value is genuinely present
			// and a matching guard would otherwise have deleted it.
			require.NoError(t, b.Put(ctx, key, value))
			tc.inject(eng, injected)

			cad, ok := b.(CompareAndDeleter)
			require.True(t, ok)

			deleted, err := cad.CompareAndDelete(ctx, key, value)

			require.Error(t, err, "an I/O fault must not be reported as a refusal")
			assert.False(t, deleted)
			assert.ErrorIs(t, err, injected, "the underlying cause must stay reachable")

			var engErr *EngineError
			require.True(t, errors.As(err, &engErr), "want *EngineError, got %T", err)
			assert.Equal(t, "compare-and-delete", engErr.Op,
				"the operation must be named, not inherited from a neighbouring verb")
			assert.Equal(t, key, engErr.Key)
		})
	}
}

// A fault must leave the store alone. This is the half a caller cannot see from
// the return value: if the delete had already landed when the failure was
// reported, a retry would act on a key that is gone.
func TestEngineBackend_CompareAndDeleteFaultLeavesTheValueInPlace(t *testing.T) {
	ctx := context.Background()
	const key = "keys/fault-subject"
	value := []byte("value-A")

	eng := newFaultyStorage()
	b := NewEngineBackend(eng)
	require.NoError(t, b.Put(ctx, key, value))

	eng.getErr = errors.New("injected read fault")
	cad := b.(CompareAndDeleter)
	_, err := cad.CompareAndDelete(ctx, key, value)
	require.Error(t, err)

	// Clear the fault and confirm nothing was removed under it.
	eng.getErr = nil
	got, err := b.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, value, got, "a failed guard must not have deleted anything")
}

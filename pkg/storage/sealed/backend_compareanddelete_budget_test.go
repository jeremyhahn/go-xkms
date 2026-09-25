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
	"os"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testing/enclavetest"
)

// The guard's locked region is admitted through the process allocator. When
// that budget is spent the guarded delete must fail with a typed enclave
// error and leave the value in place -- it must neither compare on the heap
// nor report deleted=false as though the guard had been evaluated and lost.
func TestCompareAndDelete_RefusedByProcessBudget(t *testing.T) {
	if !enclavetest.RunWithBudget(t, int64(os.Getpagesize())) {
		return
	}
	ctx := context.Background()

	inner := storage.NewMemory()
	t.Cleanup(func() { _ = inner.Close() })
	b, err := New(inner, randomizingSealer{}, nil)
	require.NoError(t, err)

	const key = "keys/budgeted"
	value := []byte("value-A")
	require.NoError(t, b.Put(ctx, key, value))

	// Hold the only page, so the guard cannot be admitted.
	alloc, err := enclave.ProcessAllocator()
	require.NoError(t, err)
	held, err := alloc.NewSized(1)
	require.NoError(t, err)

	deleted, err := b.CompareAndDelete(ctx, key, value)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrGuardEnclaveFailed)
	assert.ErrorIs(t, err, enclave.ErrBudgetExhausted, "the budget refusal stays reachable")
	assert.False(t, deleted)

	ok, err := b.Exists(ctx, key)
	require.NoError(t, err)
	assert.True(t, ok, "a refused guard must leave the value in place")

	// Releasing the page makes the same delete succeed, so the refusal above
	// was the budget and not something else about the call.
	held.Destroy()
	deleted, err = b.CompareAndDelete(ctx, key, value)
	require.NoError(t, err)
	assert.True(t, deleted)
}

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

package ratelimits

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLimit(t *testing.T) *Limit {
	t.Helper()
	limit, err := NewLimit(NewOrdersPerAccount, 10, 100, time.Hour)
	require.NoError(t, err)
	return limit
}

func TestNewTransaction(t *testing.T) {
	t.Run("creates check-and-spend transaction", func(t *testing.T) {
		limit := testLimit(t)

		txn, err := NewTransaction(limit, "user:123", 1)

		require.NoError(t, err)
		assert.Equal(t, "user:123", txn.BucketKey())
		assert.Equal(t, limit, txn.Limit())
		assert.Equal(t, int64(1), txn.Cost())
		assert.True(t, txn.check)
		assert.True(t, txn.spend)
		assert.False(t, txn.reset)
	})

	t.Run("rejects nil limit", func(t *testing.T) {
		_, err := NewTransaction(nil, "key", 1)
		assert.ErrorIs(t, err, errors.ErrNilLimit)
	})

	t.Run("rejects negative cost", func(t *testing.T) {
		limit := testLimit(t)
		_, err := NewTransaction(limit, "key", -1)
		assert.ErrorIs(t, err, errors.ErrInvalidCost)
	})

	t.Run("rejects cost exceeding burst", func(t *testing.T) {
		limit := testLimit(t)
		_, err := NewTransaction(limit, "key", limit.Burst+1)
		assert.ErrorIs(t, err, errors.ErrInvalidCostOverLimit)
	})

	t.Run("allows zero cost", func(t *testing.T) {
		limit := testLimit(t)
		txn, err := NewTransaction(limit, "key", 0)
		require.NoError(t, err)
		assert.Equal(t, int64(0), txn.Cost())
	})

	t.Run("allows cost equal to burst", func(t *testing.T) {
		limit := testLimit(t)
		txn, err := NewTransaction(limit, "key", limit.Burst)
		require.NoError(t, err)
		assert.Equal(t, limit.Burst, txn.Cost())
	})
}

func TestNewCheckOnlyTransaction(t *testing.T) {
	t.Run("creates check-only transaction", func(t *testing.T) {
		limit := testLimit(t)

		txn, err := NewCheckOnlyTransaction(limit, "user:123", 1)

		require.NoError(t, err)
		assert.True(t, txn.check)
		assert.False(t, txn.spend)
		assert.False(t, txn.reset)
		assert.True(t, txn.checkOnly())
		assert.False(t, txn.spendOnly())
		assert.False(t, txn.allowOnly())
		assert.False(t, txn.resetOnly())
	})

	t.Run("validates like regular transaction", func(t *testing.T) {
		limit := testLimit(t)
		_, err := NewCheckOnlyTransaction(limit, "key", -1)
		assert.ErrorIs(t, err, errors.ErrInvalidCost)
	})
}

func TestNewSpendOnlyTransaction(t *testing.T) {
	t.Run("creates spend-only transaction", func(t *testing.T) {
		limit := testLimit(t)

		txn, err := NewSpendOnlyTransaction(limit, "user:123", 1)

		require.NoError(t, err)
		assert.False(t, txn.check)
		assert.True(t, txn.spend)
		assert.False(t, txn.reset)
		assert.False(t, txn.checkOnly())
		assert.True(t, txn.spendOnly())
		assert.False(t, txn.allowOnly())
		assert.False(t, txn.resetOnly())
	})

	t.Run("validates like regular transaction", func(t *testing.T) {
		_, err := NewSpendOnlyTransaction(nil, "key", 1)
		assert.ErrorIs(t, err, errors.ErrNilLimit)
	})
}

func TestNewResetTransaction(t *testing.T) {
	t.Run("creates reset-only transaction", func(t *testing.T) {
		limit := testLimit(t)

		txn, err := NewResetTransaction(limit, "user:123")

		require.NoError(t, err)
		assert.False(t, txn.check)
		assert.False(t, txn.spend)
		assert.True(t, txn.reset)
		assert.False(t, txn.checkOnly())
		assert.False(t, txn.spendOnly())
		assert.False(t, txn.allowOnly())
		assert.True(t, txn.resetOnly())
	})

	t.Run("rejects nil limit", func(t *testing.T) {
		_, err := NewResetTransaction(nil, "key")
		assert.ErrorIs(t, err, errors.ErrNilLimit)
	})

	t.Run("rejects limit with zero burst", func(t *testing.T) {
		limit := &Limit{Name: NewOrdersPerAccount, Burst: 0, Count: 10, Period: time.Hour}
		_, err := NewResetTransaction(limit, "key")
		assert.ErrorIs(t, err, errors.ErrInvalidBurst)
	})
}

func TestNewAllowOnlyTransaction(t *testing.T) {
	t.Run("creates allow-only transaction", func(t *testing.T) {
		txn := NewAllowOnlyTransaction()

		assert.False(t, txn.check)
		assert.False(t, txn.spend)
		assert.False(t, txn.reset)
		assert.False(t, txn.checkOnly())
		assert.False(t, txn.spendOnly())
		assert.True(t, txn.allowOnly())
		assert.False(t, txn.resetOnly())
	})
}

func TestTransactionTypes(t *testing.T) {
	limit := testLimit(t)

	tests := []struct {
		name      string
		txn       Transaction
		checkOnly bool
		spendOnly bool
		allowOnly bool
		resetOnly bool
	}{
		{
			name:      "check-and-spend",
			txn:       Transaction{limit: limit, check: true, spend: true},
			checkOnly: false,
			spendOnly: false,
			allowOnly: false,
			resetOnly: false,
		},
		{
			name:      "check-only",
			txn:       Transaction{limit: limit, check: true, spend: false},
			checkOnly: true,
			spendOnly: false,
			allowOnly: false,
			resetOnly: false,
		},
		{
			name:      "spend-only",
			txn:       Transaction{limit: limit, check: false, spend: true},
			checkOnly: false,
			spendOnly: true,
			allowOnly: false,
			resetOnly: false,
		},
		{
			name:      "allow-only",
			txn:       Transaction{limit: limit, check: false, spend: false, reset: false},
			checkOnly: false,
			spendOnly: false,
			allowOnly: true,
			resetOnly: false,
		},
		{
			name:      "reset-only",
			txn:       Transaction{limit: limit, check: false, spend: false, reset: true},
			checkOnly: false,
			spendOnly: false,
			allowOnly: false,
			resetOnly: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.checkOnly, tt.txn.checkOnly())
			assert.Equal(t, tt.spendOnly, tt.txn.spendOnly())
			assert.Equal(t, tt.allowOnly, tt.txn.allowOnly())
			assert.Equal(t, tt.resetOnly, tt.txn.resetOnly())
		})
	}
}

func TestPrepareBatch(t *testing.T) {
	limit := testLimit(t)

	t.Run("filters allow-only transactions", func(t *testing.T) {
		txns := []Transaction{
			{limit: limit, bucketKey: "key1", check: true, spend: true},
			NewAllowOnlyTransaction(),
			{limit: limit, bucketKey: "key2", check: true, spend: true},
		}

		batch, keys, err := PrepareBatch(txns)

		require.NoError(t, err)
		assert.Len(t, batch, 2)
		assert.Len(t, keys, 2)
		assert.Equal(t, []string{"key1", "key2"}, keys)
	})

	t.Run("detects duplicate bucket keys", func(t *testing.T) {
		txns := []Transaction{
			{limit: limit, bucketKey: "key1", check: true, spend: true},
			{limit: limit, bucketKey: "key1", check: true, spend: true},
		}

		_, _, err := PrepareBatch(txns)

		var caErr *errors.TrustedCAError
		require.ErrorAs(t, err, &caErr)
		assert.Equal(t, errors.Malformed, caErr.Type)
	})

	t.Run("returns empty for all allow-only", func(t *testing.T) {
		txns := []Transaction{
			NewAllowOnlyTransaction(),
			NewAllowOnlyTransaction(),
		}

		batch, keys, err := PrepareBatch(txns)

		require.NoError(t, err)
		assert.Empty(t, batch)
		assert.Empty(t, keys)
	})

	t.Run("handles empty input", func(t *testing.T) {
		batch, keys, err := PrepareBatch(nil)

		require.NoError(t, err)
		assert.Empty(t, batch)
		assert.Empty(t, keys)
	})

	t.Run("preserves transaction order", func(t *testing.T) {
		txns := []Transaction{
			{limit: limit, bucketKey: "z", check: true, spend: true},
			{limit: limit, bucketKey: "a", check: true, spend: true},
			{limit: limit, bucketKey: "m", check: true, spend: true},
		}

		batch, keys, err := PrepareBatch(txns)

		require.NoError(t, err)
		assert.Equal(t, []string{"z", "a", "m"}, keys)
		assert.Len(t, batch, 3)
	})
}

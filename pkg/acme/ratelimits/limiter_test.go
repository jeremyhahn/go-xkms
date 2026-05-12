// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ratelimits

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimiterCheck(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := newMockClock(now)

	limit, err := NewLimit(NewOrdersPerAccount, 10, 10, time.Second)
	require.NoError(t, err)

	t.Run("allows check with no prior usage", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		txn, err := NewCheckOnlyTransaction(limit, "user:1", 1)
		require.NoError(t, err)

		d, err := limiter.Check(context.Background(), txn)

		require.NoError(t, err)
		assert.True(t, d.Allowed())
		assert.Equal(t, int64(9), d.Remaining())
	})

	t.Run("check does not modify bucket", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		txn, err := NewCheckOnlyTransaction(limit, "user:1", 1)
		require.NoError(t, err)

		d1, err := limiter.Check(context.Background(), txn)
		require.NoError(t, err)

		d2, err := limiter.Check(context.Background(), txn)
		require.NoError(t, err)

		// Both checks should have same capacity
		assert.Equal(t, d1.Remaining(), d2.Remaining())
	})

	t.Run("returns allowed for allow-only transaction", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		txn := NewAllowOnlyTransaction()

		d, err := limiter.Check(context.Background(), txn)

		require.NoError(t, err)
		assert.True(t, d.Allowed())
	})
}

func TestLimiterSpend(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := newMockClock(now)

	limit, err := NewLimit(NewOrdersPerAccount, 10, 10, time.Second)
	require.NoError(t, err)

	t.Run("allows spend with capacity", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		txn, err := NewTransaction(limit, "user:1", 1)
		require.NoError(t, err)

		d, err := limiter.Spend(context.Background(), txn)

		require.NoError(t, err)
		assert.True(t, d.Allowed())
	})

	t.Run("spend modifies bucket", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		txn, err := NewTransaction(limit, "user:1", 1)
		require.NoError(t, err)

		d1, err := limiter.Spend(context.Background(), txn)
		require.NoError(t, err)

		d2, err := limiter.Spend(context.Background(), txn)
		require.NoError(t, err)

		assert.True(t, d1.Remaining() > d2.Remaining())
	})

	t.Run("denies after burst exhausted", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		// Use all burst capacity
		for i := 0; i < 10; i++ {
			txn, _ := NewTransaction(limit, "user:1", 1)
			d, err := limiter.Spend(context.Background(), txn)
			require.NoError(t, err)
			require.True(t, d.Allowed(), "request %d should be allowed", i)
		}

		// Next request should be denied
		txn, err := NewTransaction(limit, "user:1", 1)
		require.NoError(t, err)

		d, err := limiter.Spend(context.Background(), txn)

		require.NoError(t, err)
		assert.False(t, d.Allowed())
		assert.Greater(t, d.RetryIn(), time.Duration(0))
	})

	t.Run("spend-only always reports allowed", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		// Exhaust capacity
		for i := 0; i < 15; i++ {
			txn, _ := NewSpendOnlyTransaction(limit, "user:1", 1)
			d, err := limiter.Spend(context.Background(), txn)
			require.NoError(t, err)
			assert.True(t, d.Allowed()) // spend-only ignores capacity
		}
	})
}

func TestLimiterBatchSpend(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := newMockClock(now)

	limit, err := NewLimit(NewOrdersPerAccount, 10, 10, time.Second)
	require.NoError(t, err)

	t.Run("processes multiple buckets", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		txn1, _ := NewTransaction(limit, "user:1", 1)
		txn2, _ := NewTransaction(limit, "user:2", 1)

		d, err := limiter.BatchSpend(context.Background(), []Transaction{txn1, txn2})

		require.NoError(t, err)
		assert.True(t, d.Allowed())
	})

	t.Run("returns strictest decision", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		// Exhaust user:1's capacity
		for i := 0; i < 10; i++ {
			txn, _ := NewTransaction(limit, "user:1", 1)
			limiter.Spend(context.Background(), txn)
		}

		// Batch with exhausted and fresh buckets
		txn1, _ := NewTransaction(limit, "user:1", 1) // Will be denied
		txn2, _ := NewTransaction(limit, "user:2", 1) // Would be allowed

		d, err := limiter.BatchSpend(context.Background(), []Transaction{txn1, txn2})

		require.NoError(t, err)
		assert.False(t, d.Allowed()) // Strictest is denied
	})

	t.Run("filters allow-only transactions", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		txn1 := NewAllowOnlyTransaction()
		txn2, _ := NewTransaction(limit, "user:1", 1)

		d, err := limiter.BatchSpend(context.Background(), []Transaction{txn1, txn2})

		require.NoError(t, err)
		assert.True(t, d.Allowed())
	})

	t.Run("returns allowed for all allow-only", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		txns := []Transaction{
			NewAllowOnlyTransaction(),
			NewAllowOnlyTransaction(),
		}

		d, err := limiter.BatchSpend(context.Background(), txns)

		require.NoError(t, err)
		assert.True(t, d.Allowed())
	})
}

func TestLimiterRefund(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := newMockClock(now)

	limit, err := NewLimit(NewOrdersPerAccount, 10, 10, time.Second)
	require.NoError(t, err)

	t.Run("refunds spent capacity", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		// Spend some capacity
		txn, _ := NewTransaction(limit, "user:1", 5)
		d1, err := limiter.Spend(context.Background(), txn)
		require.NoError(t, err)
		require.True(t, d1.Allowed())

		// Refund
		refundTxn, _ := NewSpendOnlyTransaction(limit, "user:1", 3)
		d2, err := limiter.Refund(context.Background(), refundTxn)
		require.NoError(t, err)

		// Check capacity increased using zero-cost check
		checkTxn, _ := NewCheckOnlyTransaction(limit, "user:1", 0)
		d3, _ := limiter.Check(context.Background(), checkTxn)
		assert.Greater(t, d3.Remaining(), d1.Remaining())
		assert.True(t, d2.Allowed())
	})

	t.Run("does not refund check-only transactions", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		// Spend capacity
		txn, _ := NewTransaction(limit, "user:1", 5)
		limiter.Spend(context.Background(), txn)

		// Check capacity before attempted refund (with zero cost to get actual capacity)
		checkBefore, _ := NewCheckOnlyTransaction(limit, "user:1", 0)
		dBefore, _ := limiter.Check(context.Background(), checkBefore)

		// Try to refund check-only
		refundTxn, _ := NewCheckOnlyTransaction(limit, "user:1", 5)
		limiter.Refund(context.Background(), refundTxn)

		// Capacity should be unchanged
		checkAfter, _ := NewCheckOnlyTransaction(limit, "user:1", 0)
		dAfter, _ := limiter.Check(context.Background(), checkAfter)
		assert.Equal(t, dBefore.Remaining(), dAfter.Remaining())
	})

	t.Run("does not refund non-existent bucket", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		txn, _ := NewSpendOnlyTransaction(limit, "nonexistent", 1)
		d, err := limiter.Refund(context.Background(), txn)

		require.NoError(t, err)
		assert.True(t, d.Allowed()) // No bucket = allowed
	})
}

func TestLimiterReset(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := newMockClock(now)

	limit, err := NewLimit(NewOrdersPerAccount, 10, 10, time.Second)
	require.NoError(t, err)

	t.Run("resets exhausted bucket", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		// Exhaust capacity
		for i := 0; i < 10; i++ {
			txn, _ := NewTransaction(limit, "user:1", 1)
			limiter.Spend(context.Background(), txn)
		}

		// Verify exhausted
		checkTxn, _ := NewTransaction(limit, "user:1", 1)
		d1, _ := limiter.Spend(context.Background(), checkTxn)
		assert.False(t, d1.Allowed())

		// Reset
		resetTxn, _ := NewResetTransaction(limit, "user:1")
		err := limiter.Reset(context.Background(), []Transaction{resetTxn})
		require.NoError(t, err)

		// Should now be allowed
		d2, _ := limiter.Spend(context.Background(), checkTxn)
		assert.True(t, d2.Allowed())
	})

	t.Run("ignores allow-only transactions", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		err := limiter.Reset(context.Background(), []Transaction{NewAllowOnlyTransaction()})
		require.NoError(t, err)
	})

	t.Run("rejects non-reset transactions", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, clk)

		txn, _ := NewTransaction(limit, "user:1", 1)
		err := limiter.Reset(context.Background(), []Transaction{txn})

		assert.Error(t, err)
	})
}

func TestLimiterWithNilClock(t *testing.T) {
	t.Run("uses default clock when nil", func(t *testing.T) {
		source := NewInMemorySource()
		limiter := NewLimiter(source, nil) // nil clock

		limit, _ := NewLimit(NewOrdersPerAccount, 10, 10, time.Second)
		txn, _ := NewTransaction(limit, "user:1", 1)

		d, err := limiter.Spend(context.Background(), txn)

		require.NoError(t, err)
		assert.True(t, d.Allowed())
	})
}

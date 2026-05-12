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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockClock implements Clock for testing.
type mockClock struct {
	now time.Time
}

func (m *mockClock) Now() time.Time { return m.now }

func newMockClock(t time.Time) *mockClock {
	return &mockClock{now: t}
}

func TestMaybeSpend(t *testing.T) {
	// Create a limit: 10 burst, 10 requests per second
	limit, err := NewLimit(NewOrdersPerAccount, 10, 10, time.Second)
	require.NoError(t, err)

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := newMockClock(now)

	t.Run("allows first request with full bucket", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			check:     true,
			spend:     true,
		}

		// TAT at now means full bucket
		d := maybeSpend(clk, txn, now)

		assert.True(t, d.Allowed())
		assert.Equal(t, int64(9), d.Remaining()) // 10 - 1 = 9
		assert.Greater(t, d.NewTAT(), now)
	})

	t.Run("allows requests until burst exhausted", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			check:     true,
			spend:     true,
		}

		tat := now
		for i := 0; i < 10; i++ {
			d := maybeSpend(clk, txn, tat)
			assert.True(t, d.Allowed(), "request %d should be allowed", i)
			tat = d.NewTAT()
		}

		// 11th request should be denied
		d := maybeSpend(clk, txn, tat)
		assert.False(t, d.Allowed())
		assert.Greater(t, d.RetryIn(), time.Duration(0))
	})

	t.Run("denies request when bucket empty", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			check:     true,
			spend:     true,
		}

		// Set TAT far in the future (bucket is empty)
		futureTAT := now.Add(time.Second * 2)

		d := maybeSpend(clk, txn, futureTAT)

		assert.False(t, d.Allowed())
		assert.Greater(t, d.RetryIn(), time.Duration(0))
	})

	t.Run("allows zero cost request", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      0,
			check:     true,
			spend:     true,
		}

		d := maybeSpend(clk, txn, now)

		assert.True(t, d.Allowed())
		assert.Equal(t, int64(10), d.Remaining())
	})

	t.Run("handles burst cost", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      10, // Use full burst
			check:     true,
			spend:     true,
		}

		d := maybeSpend(clk, txn, now)

		assert.True(t, d.Allowed())
		assert.Equal(t, int64(0), d.Remaining())
	})

	t.Run("calculates correct retry time", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			check:     true,
			spend:     true,
		}

		// Set TAT to now + burst offset (bucket empty)
		tat := now.Add(time.Duration(limit.burstOffset))

		d := maybeSpend(clk, txn, tat)

		assert.False(t, d.Allowed())
		// Should need to wait for one emission interval
		assert.GreaterOrEqual(t, d.RetryIn(), limit.EmissionInterval())
	})

	t.Run("uses max of now and TAT", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			check:     true,
			spend:     true,
		}

		// TAT in the past should be treated as now
		pastTAT := now.Add(-time.Hour)

		d := maybeSpend(clk, txn, pastTAT)

		assert.True(t, d.Allowed())
		// New TAT should be based on now, not past TAT
		assert.GreaterOrEqual(t, d.NewTAT().UnixNano(), now.UnixNano())
	})
}

func TestMaybeRefund(t *testing.T) {
	limit, err := NewLimit(NewOrdersPerAccount, 10, 10, time.Second)
	require.NoError(t, err)

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := newMockClock(now)

	t.Run("refunds when TAT in future", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			spend:     true,
		}

		// TAT slightly in the future
		futureTAT := now.Add(limit.EmissionInterval() * 2)

		d := maybeRefund(clk, txn, futureTAT)

		assert.True(t, d.Allowed())
		assert.Less(t, d.NewTAT().UnixNano(), futureTAT.UnixNano())
	})

	t.Run("does not refund when TAT in past", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			spend:     true,
		}

		pastTAT := now.Add(-time.Minute)

		d := maybeRefund(clk, txn, pastTAT)

		assert.False(t, d.Allowed())
		assert.Equal(t, limit.Burst, d.Remaining())
	})

	t.Run("refunds zero cost", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      0,
			spend:     true,
		}

		futureTAT := now.Add(limit.EmissionInterval() * 2)

		d := maybeRefund(clk, txn, futureTAT)

		assert.False(t, d.Allowed()) // TAT didn't change
		assert.Equal(t, futureTAT, d.NewTAT())
	})

	t.Run("does not refund past now", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      10, // Large refund
			spend:     true,
		}

		// TAT only slightly in future
		futureTAT := now.Add(limit.EmissionInterval())

		d := maybeRefund(clk, txn, futureTAT)

		// New TAT should be at most now, not before
		assert.GreaterOrEqual(t, d.NewTAT().UnixNano(), now.UnixNano())
	})
}

func TestGCRAIntegration(t *testing.T) {
	// 10 requests per second with burst of 5
	limit, err := NewLimit(NewOrdersPerAccount, 5, 10, time.Second)
	require.NoError(t, err)

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := newMockClock(now)

	t.Run("burst capacity is respected", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			check:     true,
			spend:     true,
		}

		tat := now
		allowed := 0
		for i := 0; i < 10; i++ {
			d := maybeSpend(clk, txn, tat)
			if d.Allowed() {
				allowed++
				tat = d.NewTAT()
			} else {
				break
			}
		}

		assert.Equal(t, 5, allowed) // Only burst capacity
	})

	t.Run("refill allows more requests", func(t *testing.T) {
		txn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			check:     true,
			spend:     true,
		}

		// Exhaust burst
		tat := now
		for i := 0; i < 5; i++ {
			d := maybeSpend(clk, txn, tat)
			require.True(t, d.Allowed())
			tat = d.NewTAT()
		}

		// Wait for one emission interval
		clk.now = now.Add(limit.EmissionInterval())

		// Should now have capacity for one more
		d := maybeSpend(clk, txn, tat)
		assert.True(t, d.Allowed())
	})

	t.Run("spend and refund cycle", func(t *testing.T) {
		spendTxn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			check:     true,
			spend:     true,
		}

		// First spend
		d1 := maybeSpend(clk, spendTxn, now)
		require.True(t, d1.Allowed())

		// Refund
		refundTxn := Transaction{
			limit:     limit,
			bucketKey: "test",
			cost:      1,
			spend:     true,
		}
		d2 := maybeRefund(clk, refundTxn, d1.NewTAT())
		assert.True(t, d2.Allowed())

		// Should be back to original capacity
		assert.GreaterOrEqual(t, d2.Remaining(), d1.Remaining())
	})
}

func TestDefaultClock(t *testing.T) {
	t.Run("returns real time", func(t *testing.T) {
		clk := DefaultClock()
		before := time.Now()
		got := clk.Now()
		after := time.Now()

		assert.True(t, !got.Before(before) && !got.After(after))
	})
}

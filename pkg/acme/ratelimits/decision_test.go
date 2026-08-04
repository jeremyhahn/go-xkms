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

func TestDecisionAccessors(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	limit, _ := NewLimit(NewOrdersPerAccount, 10, 100, time.Hour)
	txn := Transaction{limit: limit, bucketKey: "test", cost: 1}

	d := &Decision{
		allowed:     true,
		remaining:   5,
		retryIn:     time.Minute,
		resetIn:     time.Hour,
		newTAT:      now,
		transaction: txn,
	}

	t.Run("Allowed", func(t *testing.T) {
		assert.True(t, d.Allowed())
	})

	t.Run("Remaining", func(t *testing.T) {
		assert.Equal(t, int64(5), d.Remaining())
	})

	t.Run("RetryIn", func(t *testing.T) {
		assert.Equal(t, time.Minute, d.RetryIn())
	})

	t.Run("ResetIn", func(t *testing.T) {
		assert.Equal(t, time.Hour, d.ResetIn())
	})

	t.Run("NewTAT", func(t *testing.T) {
		assert.Equal(t, now, d.NewTAT())
	})

	t.Run("Transaction", func(t *testing.T) {
		assert.Equal(t, txn, d.Transaction())
	})
}

func TestDecisionResult(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	t.Run("returns nil for allowed decision", func(t *testing.T) {
		d := &Decision{allowed: true}
		assert.Nil(t, d.Result(now))
	})

	t.Run("returns RateLimitError for denied decision", func(t *testing.T) {
		limit, _ := NewLimit(NewOrdersPerAccount, 10, 100, time.Hour)
		d := &Decision{
			allowed: false,
			retryIn: time.Minute,
			transaction: Transaction{
				limit: limit,
			},
		}

		err := d.Result(now)

		require.NotNil(t, err)
		var rle *errors.RateLimitError
		assert.True(t, errors.As(err, &rle))
		assert.Contains(t, rle.Message, "rate limit exceeded")
		assert.Contains(t, rle.Message, "NewOrdersPerAccount")
		assert.GreaterOrEqual(t, rle.RetryAfter, time.Minute)
	})

	t.Run("adds jitter to retry time", func(t *testing.T) {
		limit, _ := NewLimit(NewOrdersPerAccount, 10, 100, time.Hour)
		d := &Decision{
			allowed: false,
			retryIn: time.Minute,
			transaction: Transaction{
				limit: limit,
			},
		}

		// Check that retry time has jitter (up to 3%)
		retryTimes := make([]time.Duration, 10)
		for i := 0; i < 10; i++ {
			err := d.Result(now)
			var rle *errors.RateLimitError
			errors.As(err, &rle)
			retryTimes[i] = rle.RetryAfter
		}

		// At least some variation expected (though not guaranteed due to randomness)
		allSame := true
		for _, rt := range retryTimes {
			if rt != retryTimes[0] {
				allSame = false
				break
			}
		}
		// This test may occasionally fail due to randomness - that's acceptable
		assert.False(t, allSame, "expected some jitter in retry times")
	})

	t.Run("handles nil limit", func(t *testing.T) {
		d := &Decision{
			allowed: false,
			retryIn: time.Minute,
			transaction: Transaction{
				limit: nil,
			},
		}

		err := d.Result(now)

		require.NotNil(t, err)
		var rle *errors.RateLimitError
		assert.True(t, errors.As(err, &rle))
		assert.Contains(t, rle.Message, "rate limit exceeded")
	})

	t.Run("error message includes retry time", func(t *testing.T) {
		limit, _ := NewLimit(NewOrdersPerAccount, 10, 100, time.Hour)
		d := &Decision{
			allowed: false,
			retryIn: 30 * time.Second,
			transaction: Transaction{
				limit: limit,
			},
		}

		err := d.Result(now)

		var rle *errors.RateLimitError
		errors.As(err, &rle)
		// Message should include retry timestamp
		assert.Contains(t, rle.Message, "2025-01-01")
	})
}

func TestStricter(t *testing.T) {
	t.Run("returns decision with longer retry", func(t *testing.T) {
		d1 := &Decision{retryIn: time.Minute, remaining: 5}
		d2 := &Decision{retryIn: time.Hour, remaining: 5}

		result := stricter(d1, d2)

		assert.Equal(t, d2, result)
	})

	t.Run("returns decision with fewer remaining when retry equal", func(t *testing.T) {
		d1 := &Decision{retryIn: time.Minute, remaining: 2}
		d2 := &Decision{retryIn: time.Minute, remaining: 5}

		result := stricter(d1, d2)

		assert.Equal(t, d1, result)
	})

	t.Run("returns incoming when retry equal and remaining equal", func(t *testing.T) {
		d1 := &Decision{retryIn: time.Minute, remaining: 5}
		d2 := &Decision{retryIn: time.Minute, remaining: 5}

		result := stricter(d1, d2)

		assert.Equal(t, d2, result)
	})

	t.Run("prefers denied over allowed", func(t *testing.T) {
		allowed := &Decision{allowed: true, retryIn: 0, remaining: 10}
		denied := &Decision{allowed: false, retryIn: time.Minute, remaining: 0}

		result := stricter(allowed, denied)

		assert.Equal(t, denied, result)
	})
}

func TestAllowedDecision(t *testing.T) {
	t.Run("is allowed", func(t *testing.T) {
		assert.True(t, allowedDecision.Allowed())
	})

	t.Run("has max remaining", func(t *testing.T) {
		assert.Greater(t, allowedDecision.Remaining(), int64(0))
	})
}

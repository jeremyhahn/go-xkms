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

package errors

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSentinelErrors(t *testing.T) {
	t.Run("rate limit errors are distinct", func(t *testing.T) {
		errs := []error{
			ErrBucketNotFound,
			ErrInvalidCost,
			ErrInvalidCostOverLimit,
			ErrNilLimit,
			ErrInvalidBurst,
			ErrInvalidCount,
			ErrInvalidPeriod,
			ErrDuplicateBucket,
			ErrInvalidResetTransaction,
			ErrLimitDisabled,
		}

		for i, e1 := range errs {
			for j, e2 := range errs {
				if i != j {
					assert.False(t, errors.Is(e1, e2), "expected %v != %v", e1, e2)
				}
			}
		}
	})

	t.Run("nonce errors are distinct", func(t *testing.T) {
		errs := []error{
			ErrInvalidNonceLength,
			ErrInvalidNoncePrefix,
			ErrNonceDecryptFailed,
			ErrNonceTooHigh,
			ErrNonceTooLow,
			ErrNonceAlreadyUsed,
			ErrNoncePrefixMismatch,
		}

		for i, e1 := range errs {
			for j, e2 := range errs {
				if i != j {
					assert.False(t, errors.Is(e1, e2), "expected %v != %v", e1, e2)
				}
			}
		}
	})
}

func TestRateLimitError(t *testing.T) {
	t.Run("creates error with all fields", func(t *testing.T) {
		err := NewRateLimitError(
			"too many requests",
			time.Minute,
			"TestLimit",
			10,
			time.Hour,
		)

		require.NotNil(t, err)
		assert.Equal(t, "too many requests", err.Message)
		assert.Equal(t, time.Minute, err.RetryAfter)
		assert.Equal(t, "TestLimit", err.LimitName)
		assert.Equal(t, int64(10), err.Burst)
		assert.Equal(t, time.Hour, err.Period)
	})

	t.Run("implements error interface", func(t *testing.T) {
		err := NewRateLimitError("test message", time.Second, "test", 1, time.Second)
		var e error = err
		assert.Equal(t, "test message", e.Error())
	})

	t.Run("unwrap returns nil", func(t *testing.T) {
		err := NewRateLimitError("test", time.Second, "test", 1, time.Second)
		assert.Nil(t, err.Unwrap())
	})
}

func TestNonceError(t *testing.T) {
	t.Run("creates error with message only", func(t *testing.T) {
		err := NewNonceError("invalid nonce", nil)

		require.NotNil(t, err)
		assert.Equal(t, "invalid nonce", err.Message)
		assert.Nil(t, err.Cause)
	})

	t.Run("creates error with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := NewNonceError("invalid nonce", cause)

		require.NotNil(t, err)
		assert.Equal(t, "invalid nonce", err.Message)
		assert.Equal(t, cause, err.Cause)
	})

	t.Run("implements error interface", func(t *testing.T) {
		err := NewNonceError("test message", nil)
		var e error = err
		assert.Equal(t, "test message", e.Error())
	})

	t.Run("unwrap returns cause", func(t *testing.T) {
		cause := errors.New("cause")
		err := NewNonceError("test", cause)
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("errors.Is works with cause", func(t *testing.T) {
		err := NewNonceError("test", ErrNonceTooHigh)
		assert.True(t, errors.Is(err, ErrNonceTooHigh))
	})
}

func TestValidationError(t *testing.T) {
	t.Run("creates error with value", func(t *testing.T) {
		err := NewValidationError("field", "must be positive", -5)

		require.NotNil(t, err)
		assert.Equal(t, "field", err.Field)
		assert.Equal(t, "must be positive", err.Message)
		assert.Equal(t, -5, err.Value)
	})

	t.Run("creates error without value", func(t *testing.T) {
		err := NewValidationError("field", "is required", nil)

		require.NotNil(t, err)
		assert.Equal(t, "field", err.Field)
		assert.Equal(t, "is required", err.Message)
		assert.Nil(t, err.Value)
	})

	t.Run("error message includes value", func(t *testing.T) {
		err := NewValidationError("count", "must be positive", -5)
		msg := err.Error()
		assert.Contains(t, msg, "count")
		assert.Contains(t, msg, "must be positive")
		assert.Contains(t, msg, "-5")
	})

	t.Run("error message without value", func(t *testing.T) {
		err := NewValidationError("name", "is required", nil)
		msg := err.Error()
		assert.Contains(t, msg, "name")
		assert.Contains(t, msg, "is required")
		assert.NotContains(t, msg, "value:")
	})
}

func TestTransactionError(t *testing.T) {
	t.Run("creates error with all fields", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := NewTransactionError("bucket:123", "get", cause)

		require.NotNil(t, err)
		assert.Equal(t, "bucket:123", err.BucketKey)
		assert.Equal(t, "get", err.Operation)
		assert.Equal(t, cause, err.Cause)
	})

	t.Run("error message includes context", func(t *testing.T) {
		err := NewTransactionError("user:42", "set", errors.New("timeout"))
		msg := err.Error()
		assert.Contains(t, msg, "user:42")
		assert.Contains(t, msg, "set")
		assert.Contains(t, msg, "timeout")
	})

	t.Run("unwrap returns cause", func(t *testing.T) {
		cause := errors.New("cause")
		err := NewTransactionError("key", "op", cause)
		assert.Equal(t, cause, err.Unwrap())
	})
}

func TestIs(t *testing.T) {
	t.Run("matches sentinel errors", func(t *testing.T) {
		assert.True(t, Is(ErrBucketNotFound, ErrBucketNotFound))
		assert.False(t, Is(ErrBucketNotFound, ErrInvalidCost))
	})

	t.Run("works with wrapped errors", func(t *testing.T) {
		wrapped := Wrap(NotFound, ErrBucketNotFound, "context")
		assert.True(t, Is(wrapped, ErrBucketNotFound))
	})
}

func TestAs(t *testing.T) {
	t.Run("extracts typed error from wrap", func(t *testing.T) {
		cause := NewRateLimitError("test", time.Second, "limit", 5, time.Minute)
		wrapped := Wrap(InternalServer, cause, "context")

		// errors.As should find TrustedCAError (the wrapping type)
		var tce *TrustedCAError
		assert.True(t, As(wrapped, &tce))
		assert.Equal(t, InternalServer, tce.Type)

		// errors.As should also find the RateLimitError cause
		var rle *RateLimitError
		assert.True(t, As(wrapped, &rle))
		assert.Equal(t, "test", rle.Message)
	})

	t.Run("returns false for non-matching type", func(t *testing.T) {
		err := NewNonceError("test", nil)

		var rle *RateLimitError
		assert.False(t, As(err, &rle))
	})
}

func TestWrapFromErrors(t *testing.T) {
	t.Run("wraps error with type and cause", func(t *testing.T) {
		err := Wrap(NotFound, ErrBucketNotFound, "failed to get bucket")
		assert.Contains(t, err.Error(), "failed to get bucket")
		assert.True(t, errors.Is(err, NotFound))
		assert.True(t, errors.Is(err, ErrBucketNotFound))
	})

	t.Run("maintains error chain through cause", func(t *testing.T) {
		wrapped := Wrap(StorageFailure, ErrBucketNotFound, "context: %v", ErrBucketNotFound)
		assert.True(t, errors.Is(wrapped, ErrBucketNotFound))
		assert.True(t, errors.Is(wrapped, StorageFailure))
	})
}

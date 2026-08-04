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
	"fmt"
	"math"
	"math/rand/v2"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// Decision represents the result of a rate limit check or spend operation.
type Decision struct {
	// allowed is true if the request was allowed.
	allowed bool

	// remaining is the number of requests remaining before rate limiting.
	remaining int64

	// retryIn is the duration to wait before retrying a denied request.
	retryIn time.Duration

	// resetIn is the duration until the bucket is fully replenished.
	resetIn time.Duration

	// newTAT is the new theoretical arrival time for the bucket.
	newTAT time.Time

	// transaction is the transaction that produced this decision.
	transaction Transaction
}

// allowedDecision is returned when a limit is disabled.
var allowedDecision = &Decision{allowed: true, remaining: math.MaxInt64}

// Allowed returns true if the request was allowed.
func (d *Decision) Allowed() bool {
	return d.allowed
}

// Remaining returns the number of requests remaining.
func (d *Decision) Remaining() int64 {
	return d.remaining
}

// RetryIn returns the duration to wait before retrying.
func (d *Decision) RetryIn() time.Duration {
	return d.retryIn
}

// ResetIn returns the duration until the bucket is reset.
func (d *Decision) ResetIn() time.Duration {
	return d.resetIn
}

// NewTAT returns the new theoretical arrival time.
func (d *Decision) NewTAT() time.Time {
	return d.newTAT
}

// Transaction returns the transaction that produced this decision.
func (d *Decision) Transaction() Transaction {
	return d.transaction
}

// Result converts a denied Decision into a RateLimitError.
// Returns nil if the decision allows the request.
func (d *Decision) Result(now time.Time) error {
	if d.allowed {
		return nil
	}

	// Add 0-3% jitter to prevent thundering herd.
	// Using math/rand is appropriate here - jitter doesn't require cryptographic randomness
	jitter := time.Duration(float64(d.retryIn) * 0.03 * rand.Float64()) // #nosec G404 - jitter doesn't need crypto-strength randomness
	retryAfter := d.retryIn + jitter
	retryAfterTs := now.UTC().Add(retryAfter).Format("2006-01-02 15:04:05 MST")

	var message string
	if d.transaction.limit != nil {
		message = fmt.Sprintf(
			"rate limit exceeded for %s: too many requests (%d) in the last %s, retry after %s",
			d.transaction.limit.Name.String(),
			d.transaction.limit.Burst,
			d.transaction.limit.Period,
			retryAfterTs,
		)
	} else {
		message = fmt.Sprintf("rate limit exceeded, retry after %s", retryAfterTs)
	}

	var limitName string
	var burst int64
	var period time.Duration
	if d.transaction.limit != nil {
		limitName = d.transaction.limit.Name.String()
		burst = d.transaction.limit.Burst
		period = d.transaction.limit.Period
	}

	return errors.NewRateLimitError(message, retryAfter, limitName, burst, period)
}

// stricter returns the stricter of two decisions.
// A decision is stricter if it has a longer retryIn or fewer remaining requests.
func stricter(existing, incoming *Decision) *Decision {
	if existing.retryIn == incoming.retryIn {
		if existing.remaining < incoming.remaining {
			return existing
		}
		return incoming
	}
	if existing.retryIn > incoming.retryIn {
		return existing
	}
	return incoming
}

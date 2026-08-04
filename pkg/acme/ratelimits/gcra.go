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

// Package ratelimits implements the Generic Cell Rate Algorithm (GCRA) for
// rate limiting ACME requests. GCRA is a token bucket variant that provides
// smooth rate limiting with burst capacity.
//
// The algorithm tracks a Theoretical Arrival Time (TAT) for each bucket,
// which represents when the bucket will be completely full. By comparing
// the current time against the TAT, we can determine if a request should
// be allowed and calculate remaining capacity.
//
// Key concepts:
//   - TAT (Theoretical Arrival Time): When the bucket will be full
//   - Emission Interval: Time between token additions (period / count)
//   - Burst Offset: Maximum TAT distance from now (burst * emission_interval)
package ratelimits

import (
	"time"
)

// Clock interface for time operations, allowing for testing.
type Clock interface {
	Now() time.Time
}

// realClock implements Clock using the standard library.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// DefaultClock returns a Clock that uses real time.
func DefaultClock() Clock {
	return realClock{}
}

// maybeSpend uses GCRA to decide whether to allow a request.
// It returns a Decision with the result and updated TAT.
//
// The algorithm works by:
// 1. Taking the max of current time and existing TAT
// 2. Adding the cost increment to find the new TAT
// 3. Checking if the new TAT exceeds the burst capacity
//
// If the TAT would exceed now + burstOffset, the request is denied.
func maybeSpend(clk Clock, txn Transaction, tat time.Time) *Decision {
	// Safety check - should never happen if callers validate properly.
	if txn.cost < 0 || txn.cost > txn.limit.Burst {
		panic("invalid cost for maybeSpend")
	}

	nowUnix := clk.Now().UnixNano()

	// Use the max of now and TAT to prevent accumulating credits from the past.
	tatUnix := max(nowUnix, tat.UnixNano())

	// Calculate the cost in time units.
	costIncrement := txn.limit.emissionInterval * txn.cost

	// Calculate the new TAT after spending.
	newTAT := tatUnix + costIncrement

	// Calculate the difference from the burst limit.
	// difference = now - (newTAT - burstOffset)
	// If difference < 0, we've exceeded the burst capacity.
	difference := nowUnix - (newTAT - txn.limit.burstOffset)

	if difference < 0 {
		// Request denied - insufficient capacity.
		residual := (nowUnix - (tatUnix - txn.limit.burstOffset)) / txn.limit.emissionInterval
		return &Decision{
			allowed:     false,
			remaining:   residual,
			retryIn:     -time.Duration(difference),
			resetIn:     time.Duration(tatUnix - nowUnix),
			newTAT:      time.Unix(0, tatUnix).UTC(),
			transaction: txn,
		}
	}

	// Request allowed.
	var retryIn time.Duration
	residual := difference / txn.limit.emissionInterval
	if difference < costIncrement {
		retryIn = time.Duration(costIncrement - difference)
	}

	return &Decision{
		allowed:     true,
		remaining:   residual,
		retryIn:     retryIn,
		resetIn:     time.Duration(newTAT - nowUnix),
		newTAT:      time.Unix(0, newTAT).UTC(),
		transaction: txn,
	}
}

// maybeRefund attempts to refund a previously spent cost.
// Refunds restore capacity to the bucket up to its maximum.
//
// The algorithm works by:
// 1. Checking if the TAT is in the future (bucket not yet full)
// 2. Subtracting the refund increment from the TAT
// 3. Ensuring the new TAT is not earlier than now
func maybeRefund(clk Clock, txn Transaction, tat time.Time) *Decision {
	// Safety check - should never happen if callers validate properly.
	if txn.cost < 0 || txn.cost > txn.limit.Burst {
		panic("invalid cost for maybeRefund")
	}

	nowUnix := clk.Now().UnixNano()
	tatUnix := tat.UnixNano()

	// If TAT is in the past, the bucket is already full.
	if nowUnix > tatUnix {
		return &Decision{
			allowed:     false,
			remaining:   txn.limit.Burst,
			retryIn:     0,
			resetIn:     0,
			newTAT:      tat,
			transaction: txn,
		}
	}

	// Calculate the refund increment.
	refundIncrement := txn.limit.emissionInterval * txn.cost

	// Subtract from TAT, but don't go earlier than now.
	newTATUnix := max(tatUnix-refundIncrement, nowUnix)

	// Calculate remaining capacity.
	difference := nowUnix - (newTATUnix - txn.limit.burstOffset)
	residual := difference / txn.limit.emissionInterval

	return &Decision{
		allowed:     newTATUnix != tatUnix, // allowed if TAT changed
		remaining:   residual,
		retryIn:     0,
		resetIn:     time.Duration(newTATUnix - nowUnix),
		newTAT:      time.Unix(0, newTATUnix).UTC(),
		transaction: txn,
	}
}

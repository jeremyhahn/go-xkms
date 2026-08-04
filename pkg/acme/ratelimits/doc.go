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

// Package ratelimits implements GCRA (Generic Cell Rate Algorithm) based rate
// limiting for ACME protocol operations.
//
// GCRA is a token bucket variant that tracks a Theoretical Arrival Time (TAT)
// for each rate limit bucket. It provides smooth rate limiting with configurable
// burst capacity while avoiding the thundering herd problem.
//
// # Key Concepts
//
//   - Limit: Defines the rate limit parameters (burst capacity, count, period)
//   - Transaction: Represents a single rate limit operation (check, spend, reset)
//   - Decision: The result of a rate limit check with retry information
//   - Source: Storage backend for TAT values (in-memory or external)
//   - Limiter: Coordinates transactions against the source using GCRA
//
// # Algorithm Overview
//
// GCRA works by tracking when each bucket will be "full" (the TAT). When a
// request arrives:
//
//  1. Compare current time with the TAT
//  2. If TAT is in the past, the bucket is full (reset TAT to now)
//  3. Add the cost to the TAT
//  4. If new TAT exceeds now + burstOffset, deny the request
//  5. Otherwise, allow the request and update the TAT
//
// # Transaction Types
//
//   - check-and-spend: Check capacity and consume if allowed
//   - check-only: Check capacity without consuming (pre-flight check)
//   - spend-only: Consume capacity without checking (best-effort spend)
//   - reset: Restore bucket to full capacity
//   - allow-only: Always allowed (for disabled limits)
//
// # Example Usage
//
//	// Create a rate limiter
//	source := ratelimits.NewInMemorySource()
//	limiter := ratelimits.NewLimiter(source, nil)
//
//	// Define a limit: 10 requests per second with burst of 20
//	limit, _ := ratelimits.NewLimit(
//	    ratelimits.NewOrdersPerAccount,
//	    20,           // burst
//	    10,           // count
//	    time.Second,  // period
//	)
//
//	// Create a transaction
//	txn, _ := ratelimits.NewTransaction(limit, "user:123", 1)
//
//	// Check and spend
//	decision, err := limiter.Spend(ctx, txn)
//	if err != nil {
//	    // Handle error
//	}
//	if !decision.Allowed() {
//	    // Request denied, use decision.RetryIn() for Retry-After header
//	}
package ratelimits

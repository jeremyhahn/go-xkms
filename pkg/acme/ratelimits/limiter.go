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
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// Limiter provides rate limiting using the GCRA algorithm.
// It is safe for concurrent use.
type Limiter struct {
	source Source
	clk    Clock
}

// NewLimiter creates a new Limiter with the given source and clock.
func NewLimiter(source Source, clk Clock) *Limiter {
	if clk == nil {
		clk = DefaultClock()
	}
	return &Limiter{
		source: source,
		clk:    clk,
	}
}

// Check tests if a request would be allowed without consuming capacity.
// This is useful for pre-flight checks.
func (l *Limiter) Check(ctx context.Context, txn Transaction) (*Decision, error) {
	if txn.allowOnly() {
		return allowedDecision, nil
	}

	// Remove cancellation so we complete even if client disconnects.
	ctx = context.WithoutCancel(ctx)

	tat, err := l.source.Get(ctx, txn.bucketKey)
	if err != nil {
		if !errors.Is(err, errors.ErrBucketNotFound) {
			return nil, err
		}
		// No bucket yet - treat as full capacity.
		tat = l.clk.Now()
	}

	return maybeSpend(l.clk, txn, tat), nil
}

// Spend attempts to consume capacity from a bucket.
// If allowed, the bucket state is updated.
func (l *Limiter) Spend(ctx context.Context, txn Transaction) (*Decision, error) {
	return l.BatchSpend(ctx, []Transaction{txn})
}

// BatchSpend processes multiple transactions atomically.
// Returns the strictest decision from the batch.
func (l *Limiter) BatchSpend(ctx context.Context, txns []Transaction) (*Decision, error) {
	batch, bucketKeys, err := PrepareBatch(txns)
	if err != nil {
		return nil, err
	}
	if len(batch) == 0 {
		return allowedDecision, nil
	}

	// Remove cancellation so we complete even if client disconnects.
	ctx = context.WithoutCancel(ctx)

	// Fetch current bucket states.
	tats, err := l.source.BatchGet(ctx, bucketKeys)
	if err != nil {
		return nil, errors.StorageFailureError("batch get for %d keys: %v", len(bucketKeys), err)
	}

	batchDecision := allowedDecision
	newBuckets := make(map[string]time.Time)
	incrBuckets := make(map[string]increment)
	staleBuckets := make(map[string]time.Time)

	now := l.clk.Now()

	for _, txn := range batch {
		storedTAT, bucketExists := tats[txn.bucketKey]
		if !bucketExists {
			storedTAT = now
		}

		d := maybeSpend(l.clk, txn, storedTAT)

		if d.allowed && storedTAT != d.newTAT && txn.spend {
			if !bucketExists {
				newBuckets[txn.bucketKey] = d.newTAT
			} else if storedTAT.After(now) {
				// Bucket is in use, increment.
				incrBuckets[txn.bucketKey] = increment{
					cost: time.Duration(txn.cost * txn.limit.emissionInterval),
					ttl:  time.Duration(txn.limit.burstOffset),
				}
			} else {
				// Bucket is stale, overwrite.
				staleBuckets[txn.bucketKey] = d.newTAT
			}
		}

		if !txn.spendOnly() {
			batchDecision = stricter(batchDecision, d)
		}
	}

	if batchDecision.allowed {
		// Process new buckets.
		if len(newBuckets) > 0 {
			alreadyExists, err := l.source.BatchSetNotExisting(ctx, newBuckets)
			if err != nil {
				return nil, errors.StorageFailureError("batch set for %d keys: %v", len(newBuckets), err)
			}
			// Handle race condition: if bucket was created concurrently, increment instead.
			for _, txn := range batch {
				if alreadyExists[txn.bucketKey] {
					incrBuckets[txn.bucketKey] = increment{
						cost: time.Duration(txn.cost * txn.limit.emissionInterval),
						ttl:  time.Duration(txn.limit.burstOffset),
					}
				}
			}
		}

		// Process increments.
		if len(incrBuckets) > 0 {
			if err := l.source.BatchIncrement(ctx, incrBuckets); err != nil {
				return nil, errors.StorageFailureError("batch increment for %d keys: %v", len(incrBuckets), err)
			}
		}

		// Process stale bucket overwrites.
		if len(staleBuckets) > 0 {
			if err := l.source.BatchSet(ctx, staleBuckets); err != nil {
				return nil, errors.StorageFailureError("batch set for %d keys: %v", len(staleBuckets), err)
			}
		}
	}

	return batchDecision, nil
}

// Refund attempts to restore capacity to a bucket.
func (l *Limiter) Refund(ctx context.Context, txn Transaction) (*Decision, error) {
	return l.BatchRefund(ctx, []Transaction{txn})
}

// BatchRefund processes multiple refund transactions.
func (l *Limiter) BatchRefund(ctx context.Context, txns []Transaction) (*Decision, error) {
	batch, bucketKeys, err := PrepareBatch(txns)
	if err != nil {
		return nil, err
	}
	if len(batch) == 0 {
		return allowedDecision, nil
	}

	// Remove cancellation so we complete even if client disconnects.
	ctx = context.WithoutCancel(ctx)

	tats, err := l.source.BatchGet(ctx, bucketKeys)
	if err != nil {
		return nil, errors.StorageFailureError("batch get for %d keys: %v", len(bucketKeys), err)
	}

	batchDecision := allowedDecision
	incrBuckets := make(map[string]increment)

	for _, txn := range batch {
		tat, bucketExists := tats[txn.bucketKey]
		if !bucketExists {
			continue
		}

		// For check-only transactions, don't refund.
		cost := txn.cost
		if txn.checkOnly() {
			cost = 0
		}

		refundTxn := Transaction{
			bucketKey: txn.bucketKey,
			limit:     txn.limit,
			cost:      cost,
			spend:     true,
		}

		d := maybeRefund(l.clk, refundTxn, tat)
		batchDecision = stricter(batchDecision, d)

		if d.allowed && tat != d.newTAT {
			// Negative increment = refund.
			incrBuckets[txn.bucketKey] = increment{
				cost: -time.Duration(cost * txn.limit.emissionInterval),
				ttl:  time.Duration(txn.limit.burstOffset),
			}
		}
	}

	if len(incrBuckets) > 0 {
		if err := l.source.BatchIncrement(ctx, incrBuckets); err != nil {
			return nil, errors.StorageFailureError("batch increment for %d keys: %v", len(incrBuckets), err)
		}
	}

	return batchDecision, nil
}

// Reset restores buckets to full capacity.
func (l *Limiter) Reset(ctx context.Context, txns []Transaction) error {
	var bucketKeys []string
	for _, txn := range txns {
		if txn.allowOnly() {
			continue
		}
		if !txn.resetOnly() {
			return errors.MalformedError("expected reset-only transaction, got check=%t spend=%t reset=%t",
				txn.check, txn.spend, txn.reset)
		}
		bucketKeys = append(bucketKeys, txn.bucketKey)
	}

	if len(bucketKeys) == 0 {
		return nil
	}

	// Remove cancellation so we complete even if client disconnects.
	ctx = context.WithoutCancel(ctx)

	return l.source.BatchDelete(ctx, bucketKeys)
}

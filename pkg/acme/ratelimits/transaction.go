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
	"slices"

	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// Transaction represents a single rate limit operation.
//
// Transaction types:
//   - check-and-spend: check=true, spend=true - checks capacity and spends if allowed
//   - check-only: check=true, spend=false - checks capacity without spending
//   - spend-only: check=false, spend=true - best-effort spend, always "allowed"
//   - reset-only: reset=true - resets the bucket to full capacity
//   - allow-only: check=false, spend=false, reset=false - always allowed (disabled limit)
type Transaction struct {
	// bucketKey uniquely identifies the bucket for this transaction.
	bucketKey string

	// limit defines the rate limit parameters.
	limit *Limit

	// cost is the number of tokens to spend.
	cost int64

	// check indicates whether to check capacity before spending.
	check bool

	// spend indicates whether to deduct cost from the bucket.
	spend bool

	// reset indicates whether to reset the bucket to full capacity.
	reset bool
}

// BucketKey returns the bucket key for this transaction.
func (t Transaction) BucketKey() string {
	return t.bucketKey
}

// Limit returns the limit for this transaction.
func (t Transaction) Limit() *Limit {
	return t.limit
}

// Cost returns the cost for this transaction.
func (t Transaction) Cost() int64 {
	return t.cost
}

// checkOnly returns true if this is a check-only transaction.
func (t Transaction) checkOnly() bool {
	return t.check && !t.spend && !t.reset
}

// spendOnly returns true if this is a spend-only transaction.
func (t Transaction) spendOnly() bool {
	return t.spend && !t.check && !t.reset
}

// allowOnly returns true if this is an allow-only transaction (disabled limit).
func (t Transaction) allowOnly() bool {
	return !t.check && !t.spend && !t.reset
}

// resetOnly returns true if this is a reset-only transaction.
func (t Transaction) resetOnly() bool {
	return t.reset && !t.check && !t.spend
}

// validate ensures the transaction configuration is valid.
func (t Transaction) validate() error {
	if t.limit == nil {
		return errors.ErrNilLimit
	}
	if t.reset {
		if t.check || t.spend {
			return errors.ErrInvalidResetTransaction
		}
		if t.limit.Burst == 0 {
			return errors.ErrInvalidBurst
		}
		return nil
	}
	if t.cost < 0 {
		return errors.ErrInvalidCost
	}
	if t.limit.Burst == 0 {
		return errors.ErrInvalidBurst
	}
	if t.cost > t.limit.Burst {
		return errors.ErrInvalidCostOverLimit
	}
	return nil
}

// NewTransaction creates a new check-and-spend transaction.
func NewTransaction(limit *Limit, bucketKey string, cost int64) (Transaction, error) {
	t := Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		check:     true,
		spend:     true,
	}
	if err := t.validate(); err != nil {
		return Transaction{}, err
	}
	return t, nil
}

// NewCheckOnlyTransaction creates a check-only transaction.
func NewCheckOnlyTransaction(limit *Limit, bucketKey string, cost int64) (Transaction, error) {
	t := Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		check:     true,
		spend:     false,
	}
	if err := t.validate(); err != nil {
		return Transaction{}, err
	}
	return t, nil
}

// NewSpendOnlyTransaction creates a spend-only transaction.
func NewSpendOnlyTransaction(limit *Limit, bucketKey string, cost int64) (Transaction, error) {
	t := Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		cost:      cost,
		check:     false,
		spend:     true,
	}
	if err := t.validate(); err != nil {
		return Transaction{}, err
	}
	return t, nil
}

// NewResetTransaction creates a reset-only transaction.
func NewResetTransaction(limit *Limit, bucketKey string) (Transaction, error) {
	t := Transaction{
		bucketKey: bucketKey,
		limit:     limit,
		reset:     true,
	}
	if err := t.validate(); err != nil {
		return Transaction{}, err
	}
	return t, nil
}

// NewAllowOnlyTransaction creates an allow-only transaction (disabled limit).
func NewAllowOnlyTransaction() Transaction {
	return Transaction{}
}

// PrepareBatch validates and prepares a batch of transactions.
// It filters out allow-only transactions and checks for duplicate bucket keys.
func PrepareBatch(txns []Transaction) ([]Transaction, []string, error) {
	var bucketKeys []string
	var transactions []Transaction

	for _, txn := range txns {
		if txn.allowOnly() {
			// Ignore allow-only transactions.
			continue
		}
		if slices.Contains(bucketKeys, txn.bucketKey) {
			return nil, nil, errors.MalformedError("duplicate bucket key in batch: %s", txn.bucketKey)
		}
		bucketKeys = append(bucketKeys, txn.bucketKey)
		transactions = append(transactions, txn)
	}
	return transactions, bucketKeys, nil
}

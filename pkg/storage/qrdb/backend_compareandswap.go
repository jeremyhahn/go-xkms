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

package qrdb

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// NOT SUPPORTED BY EVERY BACKEND -- same two refusal layers as PutIfAbsent;
// see the note there and the constructor doc in factory.go.
//
// CompareAndSwap atomically stores new at key only if the current value equals
// expected (or, when expected is nil, only if the key is absent), using a QRDB
// compare-and-swap transaction applied through Raft consensus. This is the same
// linearizable transaction primitive PutIfAbsent uses — here with a value
// compare rather than a version==0 compare — so the guarantee holds across every
// node: at most one of N concurrent CompareAndSwap calls against the same
// current value succeeds.
//
// The transaction carries NO failure branch. A transaction's success/failure
// branches are executed atomically as a single Raft write with no per-op
// read-result channel, so branch operations are write-only by design; go-qrdb's
// service layer rejects a Get in either branch with "transaction branches
// support only Put and Delete" (#125 — this package's compare-and-delete and
// put-if-absent transactions never had a read branch; this one, uniquely,
// used to). So on a failed swap, current is fetched with a follow-up Get
// instead of inside the transaction — current is advisory for a retry, and any
// value can change between the attempt and the retry regardless of how it was
// read.
func (b *Backend) CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	txClient, ok := b.client.(transport.TransactionClient)
	if !ok {
		return false, nil, &BackendError{Op: "compare-and-swap", Key: key, Err: ErrTransactionsUnsupported}
	}

	var compare transport.Compare
	if expected == nil {
		// version 0 ⇒ the key has never been written (absent).
		compare = transport.Compare{
			Key:     []byte(key),
			Target:  transport.CompareVersion,
			Result:  transport.CompareEqual,
			Version: 0,
		}
	} else {
		compare = transport.Compare{
			Key:    []byte(key),
			Target: transport.CompareValue,
			Result: transport.CompareEqual,
			Value:  expected,
		}
	}

	req := &transport.TransactionRequest{
		Compares:   []transport.Compare{compare},
		SuccessOps: []transport.Op{{Type: transport.OpPut, Key: []byte(key), Value: newValue}},
	}

	resp, err := txClient.ExecuteTransaction(ctx, req)
	if err != nil {
		return false, nil, &BackendError{Op: "compare-and-swap", Key: key, Err: err}
	}
	if resp.Succeeded {
		return true, nil, nil
	}

	// The swap did not happen; fetch the value actually present so a
	// read-modify-write caller can recompute and retry. A key that is still
	// absent is not an error here — it is the current value, nil.
	current, err := b.client.Get(ctx, key, followerRead)
	if err != nil {
		var knf *transport.KeyNotFoundError
		if errors.As(err, &knf) {
			return false, nil, nil
		}
		return false, nil, &BackendError{Op: "compare-and-swap", Key: key, Err: err}
	}
	return false, current, nil
}

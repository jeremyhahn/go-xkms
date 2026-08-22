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
// On a failed swap the transaction's failure branch reads the key, so current
// carries the value actually present (nil when the key is absent), letting a
// read-modify-write caller recompute and retry.
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
		// On failure, read the key back so the caller learns the current value
		// it must recompute against.
		FailureOps: []transport.Op{{Type: transport.OpGet, Key: []byte(key)}},
	}

	resp, err := txClient.ExecuteTransaction(ctx, req)
	if err != nil {
		return false, nil, &BackendError{Op: "compare-and-swap", Key: key, Err: err}
	}
	if resp.Succeeded {
		return true, nil, nil
	}

	var current []byte
	if len(resp.Responses) > 0 && len(resp.Responses[0].Kvs) > 0 {
		current = resp.Responses[0].Kvs[0].Value
	}
	return false, current, nil
}

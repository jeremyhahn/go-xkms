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

// AVAILABLE FROM EVERY EMBEDDED CONSTRUCTOR in factory.go, on the guarded
// path, since go-qrdb's transport.GuardedKVClient carried CompareAndSwap
// (#121, go-qrdb v0.12.0-alpha). This package simply never dispatched to it:
// CompareAndSwap went straight to transport.TransactionClient, and
// newEmbedded's embedded.New(kvSvc, adminSvc) wires no transaction service, so
// every embedded constructor failed with "embedded: TransactionServicer must
// not be nil" despite the client sitting right there implementing the
// capability that would have served the call directly (#125). Fixed by
// preferring GuardedKVClient here, the same dispatch order CompareAndDelete
// and PutIfAbsent already use.
//
// It prefers transport.GuardedKVClient — the SDK's native guarded-write
// capability — over a compare-and-swap TRANSACTION for the same reason
// CompareAndDelete does: the embedded transport wires no transaction service
// but does implement the guarded capability, delegating straight to the KV
// service. The transaction fallback covers a remote transport whose protocol
// carries transactions but not yet the guarded verbs.
//
// transport.GuardedKVClient.CompareAndSwap reports only swapped/err, with no
// current value on a refusal, so a refusal on either path is followed by the
// same currentAfterRefusedSwap Get -- current is advisory for a retry in both
// cases, and any value can change between the attempt and the retry regardless
// of how it was read.
//
// CompareAndSwap atomically stores new at key only if the current value equals
// expected (or, when expected is nil, only if the key is absent). On the
// guarded path this is the KV service's native CompareAndSwap opcode; on the
// transaction fallback it is the same linearizable QRDB transaction primitive
// PutIfAbsent uses, with a value compare rather than a version==0 compare. So
// the guarantee holds across every node either way: at most one of N
// concurrent CompareAndSwap calls against the same current value succeeds.
//
// The transaction carries NO failure branch. A transaction's success/failure
// branches are executed atomically as a single Raft write with no per-op
// read-result channel, so branch operations are write-only by design; go-qrdb's
// service layer rejects a Get in either branch with "transaction branches
// support only Put and Delete" (#125 — this package's compare-and-delete and
// put-if-absent transactions never had a read branch; this one, uniquely,
// used to).
func (b *Backend) CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	// Same capability-refusal-falls-through rule as PutIfAbsent and
	// CompareAndDelete: ONLY a capability refusal from the guarded path falls
	// through to the transaction, because it is the one error that means the
	// operation was not performed.
	var guardedErr error
	if guarded, ok := b.client.(transport.GuardedKVClient); ok {
		swapped, err := guarded.CompareAndSwap(ctx, key, expected, newValue)
		if err == nil {
			if swapped {
				return true, nil, nil
			}
			return b.currentAfterRefusedSwap(ctx, key)
		}
		var unsupported *transport.CapabilityUnsupportedError
		if !errors.As(err, &unsupported) {
			return false, nil, &BackendError{Op: "compare-and-swap", Key: key, Err: err}
		}
		guardedErr = err
	}

	txClient, ok := b.client.(transport.TransactionClient)
	if !ok {
		cause := error(ErrTransactionsUnsupported)
		if guardedErr != nil {
			cause = guardedErr
		}
		return false, nil, &BackendError{Op: "compare-and-swap", Key: key, Err: cause}
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
	return b.currentAfterRefusedSwap(ctx, key)
}

// currentAfterRefusedSwap fetches the value actually present after a refused
// CompareAndSwap, on either dispatch path: neither transport.GuardedKVClient's
// CompareAndSwap nor the transaction branch above reports the current value on
// refusal, so both need this same follow-up read. A key that is still absent
// is not an error here — it is the current value, nil, matching what an
// absent key means for a read-modify-write retry.
func (b *Backend) currentAfterRefusedSwap(ctx context.Context, key string) (bool, []byte, error) {
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

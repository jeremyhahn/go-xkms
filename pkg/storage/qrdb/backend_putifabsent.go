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

// ErrTransactionsUnsupported is returned by PutIfAbsent when the underlying
// QRDB client does not implement transport.TransactionClient and therefore
// cannot provide a linearizable compare-and-swap. Every concrete QRDB
// transport implements transaction execution; this error only surfaces if a
// caller injects a hand-rolled KVClient lacking that capability.
var ErrTransactionsUnsupported = errors.New("qrdb: client does not support compare-and-swap transactions")

// AVAILABLE FROM EVERY EMBEDDED CONSTRUCTOR in factory.go, on the guarded
// path, since go-qrdb's transport.GuardedKVClient carried PutIfAbsent (#119,
// well before the transaction fallback below was ever reachable through
// newEmbedded). This package simply never dispatched to it: PutIfAbsent went
// straight to transport.TransactionClient, and newEmbedded's
// embedded.New(kvSvc, adminSvc) wires no transaction service, so every
// embedded constructor failed with "embedded: TransactionServicer must not be
// nil" despite the client sitting right there implementing the capability
// that would have served the call directly (#125). Fixed by preferring
// GuardedKVClient here, the same dispatch order CompareAndDelete already
// used. See factory_cas_characterization_test.go.
//
// It prefers transport.GuardedKVClient — the SDK's native guarded-write
// capability — over a compare-and-swap TRANSACTION for the same reason
// CompareAndDelete does: the embedded transport wires no transaction service
// but does implement the guarded capability, delegating straight to the KV
// service. The transaction fallback covers a remote transport whose protocol
// carries transactions but not yet the guarded verbs.
//
// A caller cannot ask a Backend whether the operation is available; that needs
// a capability on the interface and is an owner decision (#29). Until then the
// constructor doc in factory.go is the reference.
//
// PutIfAbsent atomically stores value at key only if key is absent. On the
// guarded path this is the KV service's native PutIfAbsent opcode; on the
// transaction fallback it is a QRDB compare-and-swap transaction applied
// through Raft consensus, whose precondition "key version == 0" holds exactly
// when the key has never been written, so the success op (Put) executes only
// on the first writer. Either way every concurrent writer on any node observes
// stored=false. This gives linearizable cross-node key-ID uniqueness — the
// guarantee an in-process lock cannot provide.
func (b *Backend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	ctx, err := b.callContext(ctx)
	if err != nil {
		return false, &BackendError{Op: "put-if-absent", Key: key, Err: err}
	}
	// A client can implement GuardedKVClient and still be unable to perform
	// the operation: the capability is a property of the TRANSPORT, while
	// executing it is a property of the server's state machine. So a
	// capability refusal here falls through to the transaction, which may
	// well be able to do it. ONLY a capability refusal falls through; any
	// other failure may already have reached the state machine, and retrying
	// via another route risks a double-apply. See CompareAndDelete for the
	// same reasoning stated at length.
	var guardedErr error
	if guarded, ok := b.client.(transport.GuardedKVClient); ok {
		stored, err := guarded.PutIfAbsent(ctx, key, value)
		if err == nil {
			return stored, nil
		}
		var unsupported *transport.CapabilityUnsupportedError
		if !errors.As(err, &unsupported) {
			return false, &BackendError{Op: "put-if-absent", Key: key, Err: err}
		}
		guardedErr = err
	}

	txClient, ok := b.client.(transport.TransactionClient)
	if !ok {
		cause := error(ErrTransactionsUnsupported)
		if guardedErr != nil {
			cause = guardedErr
		}
		return false, &BackendError{Op: "put-if-absent", Key: key, Err: cause}
	}

	req := &transport.TransactionRequest{
		Compares: []transport.Compare{
			{
				Key:     []byte(key),
				Target:  transport.CompareVersion,
				Result:  transport.CompareEqual,
				Version: 0, // version 0 ⇒ key has never been written (absent)
			},
		},
		SuccessOps: []transport.Op{
			{
				Type:  transport.OpPut,
				Key:   []byte(key),
				Value: value,
			},
		},
	}

	resp, err := txClient.ExecuteTransaction(ctx, req)
	if err != nil {
		return false, &BackendError{Op: "put-if-absent", Key: key, Err: err}
	}
	return resp.Succeeded, nil
}

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

// CompareAndDelete atomically removes key only when its stored value still
// equals expected, with the comparison evaluated inside the cluster so the
// guarantee holds across nodes: at most one of N concurrent releasers holding
// the same observed value wins.
//
// It prefers transport.GuardedKVClient — the SDK's native guarded-write
// capability — over the compare-and-swap TRANSACTION that PutIfAbsent and
// CompareAndSwap use, because the embedded transport wires no transaction
// service (#125) but does implement the guarded capability, delegating straight
// to the KV service. The transaction fallback covers the reverse case: a remote
// transport whose protocol carries transactions but not yet the guarded verbs.
//
// AVAILABLE FROM EVERY EMBEDDED CONSTRUCTOR in factory.go, on the guarded path,
// as of go-qrdb v0.16.3-alpha (go-xkms#406). It was not, and the history is
// worth keeping because it is what the dispatch order above was built for: the
// FastStateMachine newEmbedded builds had no handler for the guarded-delete
// opcode (go-qrdb#175), so the guarded path refused with a
// CapabilityUnsupportedError, that refusal fell through to the transaction, and
// the transaction failed where PutIfAbsent still does — the embedded transport
// wires no transaction service (#125) — so the error a caller saw was the
// second one. The state machine now serves the opcode, so the guarded path
// answers and nothing falls through. Re-measured 2026-09-06 against go-qrdb
// v0.16.3-alpha through the constructors themselves; see
// backend_compareanddelete_test.go.
//
// PutIfAbsent and CompareAndSwap are unchanged by that: they route through the
// transaction the embedded transport still does not wire (#125), which is why
// this verb's availability and theirs are separate questions.
//
// A caller cannot ask a Backend whether the operation is available; that needs
// a capability on the interface and is an owner decision (#29). Until then the
// constructor doc in factory.go is the reference.
//
// Both paths are linearizable, so neither is a degraded mode. When neither is
// available, this refuses rather than falling back to a read followed by an
// unguarded delete: that fallback reintroduces precisely the window the
// operation exists to close, and a plausible-looking deleted=true would be a
// lie about a guard that never ran.
func (b *Backend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	// A client can implement GuardedKVClient and still be unable to perform the
	// operation: the capability is a property of the TRANSPORT, while executing
	// it is a property of the server's state machine. The embedded transport is
	// exactly that case — it forwards the verb, and the FastStateMachine behind
	// it has no handler for the opcode — and a partially upgraded cluster is the
	// same shape. So a capability refusal here falls through to the transaction,
	// which may well be able to do it.
	//
	// ONLY a capability refusal falls through. It is the one error that means
	// the operation was NOT performed, so retrying by another route cannot
	// double-execute. Any other failure may have reached the state machine, and
	// re-issuing a delete after one that might have applied is how a guarded
	// verb turns into an unguarded one.
	var guardedErr error
	if guarded, ok := b.client.(transport.GuardedKVClient); ok {
		deleted, err := guarded.CompareAndDelete(ctx, key, expected)
		if err == nil {
			return deleted, nil
		}
		var unsupported *transport.CapabilityUnsupportedError
		if !errors.As(err, &unsupported) {
			return false, &BackendError{Op: "compare-and-delete", Key: key, Err: err}
		}
		guardedErr = err
	}

	txClient, ok := b.client.(transport.TransactionClient)
	if !ok {
		// Report the capability refusal when there was one: it names what the
		// server actually lacks, which is more use than a generic statement
		// about transactions the client never claimed to support.
		cause := error(ErrTransactionsUnsupported)
		if guardedErr != nil {
			cause = guardedErr
		}
		return false, &BackendError{Op: "compare-and-delete", Key: key, Err: cause}
	}

	// TWO preconditions, ANDed by the state machine, and the presence one is not
	// redundant. QRDB evaluates a value compare against a nil value for a key
	// that does not exist, and bytes.Compare(nil, nil) is 0 — so a value-only
	// compare with an empty or nil expected MATCHES AN ABSENT KEY. The
	// transaction would succeed, the Delete would remove nothing, and this
	// method would report deleted=true for a key that was never there, which is
	// exactly the outcome the contract says must be deleted=false.
	//
	// Version > 0 holds only for a key that has been written, so it pins
	// presence independently of what the guard bytes happen to be. PutIfAbsent
	// uses the same field for the mirror-image condition (version == 0 to
	// require absence).
	req := &transport.TransactionRequest{
		Compares: []transport.Compare{
			{
				Key:     []byte(key),
				Target:  transport.CompareVersion,
				Result:  transport.CompareGreater,
				Version: 0, // version > 0 ⇒ the key exists
			},
			{
				Key:    []byte(key),
				Target: transport.CompareValue,
				Result: transport.CompareEqual,
				Value:  expected,
			},
		},
		SuccessOps: []transport.Op{{Type: transport.OpDelete, Key: []byte(key)}},
	}

	resp, err := txClient.ExecuteTransaction(ctx, req)
	if err != nil {
		return false, &BackendError{Op: "compare-and-delete", Key: key, Err: err}
	}
	return resp.Succeeded, nil
}

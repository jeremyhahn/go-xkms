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

// NOT AVAILABLE FROM THE EMBEDDED CONSTRUCTORS in factory.go. This is a
// transaction, and the embedded transport built by newEmbedded wires no
// transaction service, so it fails for memory, file and pebble alike with
// "embedded: TransactionServicer must not be nil" (#125). Measured 2026-08-21
// against go-qrdb v0.9.0-alpha through the constructors themselves; see
// factory_cas_characterization_test.go. This is distinct from #61 (the
// pkg/server `storage.backend: qrdb` node path), which is fixed in go-qrdb
// v0.11.0-alpha.
//
// A caller cannot ask a Backend whether the operation is available; that needs
// a capability on the interface and is an owner decision (#29). Until then the
// constructor doc in factory.go is the reference.
//
// PutIfAbsent atomically stores value at key only if key is absent, using a
// QRDB compare-and-swap transaction applied through Raft consensus. The
// precondition "key version == 0" holds exactly when the key has never been
// written, so the success op (Put) executes only on the first writer; every
// concurrent writer on any node observes Succeeded=false. This gives
// linearizable cross-node key-ID uniqueness — the guarantee an in-process lock
// cannot provide.
func (b *Backend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	txClient, ok := b.client.(transport.TransactionClient)
	if !ok {
		return false, &BackendError{Op: "put-if-absent", Key: key, Err: ErrTransactionsUnsupported}
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

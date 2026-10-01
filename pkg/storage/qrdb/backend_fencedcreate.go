// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// PutIfAllAbsent stores value at key only when key and every fence are
// absent, as one QRDB compare-and-swap transaction applied through Raft: it
// compares every key's version with zero -- the precondition PutIfAbsent's
// transaction uses, which holds exactly when the key is absent -- and puts the
// key only when all compares hold. Every replica decides from the same log
// position, so the guarantee holds across nodes.
//
// The KV service has no native fenced-create opcode, so there is no guarded
// path to prefer; a client without transactions reports
// ErrTransactionsUnsupported rather than checking and then writing.
func (b *Backend) PutIfAllAbsent(ctx context.Context, key string, value []byte, fences ...string) (bool, error) {
	txClient, ok := b.client.(transport.TransactionClient)
	if !ok {
		return false, &BackendError{Op: "put-if-all-absent", Key: key, Err: ErrTransactionsUnsupported}
	}
	compares := make([]transport.Compare, 0, 1+len(fences))
	for _, k := range append([]string{key}, fences...) {
		compares = append(compares, transport.Compare{
			Key:     []byte(k),
			Target:  transport.CompareVersion,
			Result:  transport.CompareEqual,
			Version: 0,
		})
	}
	resp, err := txClient.ExecuteTransaction(ctx, &transport.TransactionRequest{
		Compares:   compares,
		SuccessOps: []transport.Op{{Type: transport.OpPut, Key: []byte(key), Value: value}},
	})
	if err != nil {
		return false, &BackendError{Op: "put-if-all-absent", Key: key, Err: err}
	}
	return resp.Succeeded, nil
}

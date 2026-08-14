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

package kvadapter

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// Secondary indexing is deliberately out of scope for KVStoreAdapter.
//
// The adapter bridges a storage.Backend, whose values are opaque bytes, to
// the KVStore contract. Maintaining an index requires decoding each entity
// payload to extract the indexed JSON fields, and the encoding is chosen by
// the DAO (JSON, CBOR, MsgPack) and never communicated to the store. An
// index built at this layer could therefore never be kept correct, and
// index ownership belongs to the go-qrdb storage engines, which see typed
// entities.
//
// Every index method consequently fails loudly with
// ErrIndexingNotSupported rather than reporting an empty result, so a
// caller can never mistake "this store cannot answer index queries" for
// "the index matched nothing". Callers that can degrade gracefully detect
// the sentinel with errors.Is and fall back to Scan or List.

// RegisterEntityIndexes reports ErrIndexingNotSupported. Registration is
// refused rather than silently accepted so a caller cannot be left holding
// a store it believes maintains indexes. The go-qrdb DAO factory ignores
// this error and simply performs unindexed scans.
func (a *KVStoreAdapter) RegisterEntityIndexes(entityType string, _ []qrdbsdk.EntityIndex) error {
	return &IndexingNotSupportedError{Op: "RegisterEntityIndexes", Name: entityType}
}

// QueryIndex reports ErrIndexingNotSupported for an exact-match index query.
func (a *KVStoreAdapter) QueryIndex(_ context.Context, indexName string, _ []byte) ([][]byte, error) {
	return nil, &IndexingNotSupportedError{Op: "QueryIndex", Name: indexName}
}

// ScanIndex reports ErrIndexingNotSupported for an index range scan.
func (a *KVStoreAdapter) ScanIndex(_ context.Context, indexName string, _, _ []byte) (map[string][][]byte, error) {
	return nil, &IndexingNotSupportedError{Op: "ScanIndex", Name: indexName}
}

// QueryCompoundIndex reports ErrIndexingNotSupported for an exact-match
// compound index query.
func (a *KVStoreAdapter) QueryCompoundIndex(_ context.Context, indexName string, _ [][]byte) ([][]byte, error) {
	return nil, &IndexingNotSupportedError{Op: "QueryCompoundIndex", Name: indexName}
}

// ScanCompoundIndex reports ErrIndexingNotSupported for a compound index
// prefix and range scan.
func (a *KVStoreAdapter) ScanCompoundIndex(_ context.Context, indexName string, _ [][]byte, _, _ []byte) (map[string][][]byte, error) {
	return nil, &IndexingNotSupportedError{Op: "ScanCompoundIndex", Name: indexName}
}

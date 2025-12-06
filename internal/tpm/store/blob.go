// Package store provides blob storage implementations
package store

import (
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
)

// FSBlobStore is re-exported from the public package
type FSBlobStore = store.FSBlobStore

// NewFSBlobStore creates a new blob store using storage.Backend
func NewFSBlobStore(logger Logger, backend storage.Backend) BlobStorer {
	return store.NewFSBlobStore(logger, backend)
}

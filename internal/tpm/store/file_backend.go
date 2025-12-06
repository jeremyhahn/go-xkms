// Package store provides file backend implementations
package store

import (
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
)

// FileBackend is re-exported from the public package
type FileBackend = store.FileBackend

// NewFileBackend creates a new file-based key backend using storage.Backend
func NewFileBackend(logger Logger, backend storage.Backend) KeyBackend {
	return store.NewFileBackend(logger, backend)
}

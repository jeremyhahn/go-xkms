// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package keychain

import (
	"log"

	"github.com/jeremyhahn/go-keychain/pkg/certstore"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Backend returns the underlying backend for direct access if needed.
// This allows users to access backend-specific features not exposed
// through the KeyStore interface.
func (ks *compositeKeyStore) Backend() types.Backend {
	return ks.backend
}

// CertStorage returns the underlying certificate storage for direct access if needed.
// This allows users to access storage-specific features not exposed
// through the KeyStore interface.
func (ks *compositeKeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return ks.certStorage
}

// Backend returns the raw storage backend (for testing and migration).
// Deprecated: Use CertStorage() for certificate operations.

// Close releases all resources held by the keychain.
// This closes both the backend and certificate storage.
//
// After calling Close, the keychain should not be used.
func (ks *compositeKeyStore) Close() error {
	// Close backend first
	if err := ks.backend.Close(); err != nil {
		// Try to close cert storage even if backend close fails
		if closeErr := ks.certStorage.Close(); closeErr != nil {
			log.Printf("failed to close certificate storage: %v", closeErr)
		}
		return err
	}

	// Close certificate storage
	return ks.certStorage.Close()
}

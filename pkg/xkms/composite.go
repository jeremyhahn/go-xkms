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

package xkms

import (
	"log"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// KeyProvider returns the underlying key provider for direct access if needed.
// This allows users to access key-provider-specific features not exposed
// through the Backend interface.
func (c *compositeBackend) KeyProvider() types.KeyProvider {
	return c.backend
}

// CertStorage returns the underlying certificate storage for direct access if needed.
// This allows users to access storage-specific features not exposed
// through the Backend interface.
func (c *compositeBackend) CertStorage() certstore.CertificateStorageAdapter {
	return c.certStorage
}

// Close releases all resources held by the xkms.
// This closes both the key provider and certificate storage.
//
// After calling Close, the xkms should not be used.
func (c *compositeBackend) Close() error {
	// Close key provider first
	if err := c.backend.Close(); err != nil {
		// Try to close cert storage even if key provider close fails
		if closeErr := c.certStorage.Close(); closeErr != nil {
			log.Printf("failed to close certificate storage: %v", closeErr)
		}
		return err
	}

	// Close certificate storage
	return c.certStorage.Close()
}

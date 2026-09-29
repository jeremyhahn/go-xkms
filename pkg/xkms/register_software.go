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

// Package xkms provides the software backend registration and factory.
//
// The software backend uses in-memory or file-based key storage with pure
// software cryptographic operations. This backend is always available and
// serves as the default fallback.
package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendSoftware)
	RegisterBackendFactory(BackendSoftware, newSoftwareKeyProvider)
}

// newSoftwareKeyProvider creates a software backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "key_storage" (storage.Backend): pre-built key storage -- the caller's
//     datastore handle (see AutoConfig.Datastore), already a key-prefixed
//     view for this backend. Absent, in-memory storage is used.
func newSoftwareKeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	keyStorage, ok := config["key_storage"].(storage.Backend)
	if !ok || keyStorage == nil {
		keyStorage = storage.New()
	}

	return software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
}

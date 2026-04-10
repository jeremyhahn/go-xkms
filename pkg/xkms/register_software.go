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
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendSoftware)
	RegisterBackendFactory(BackendSoftware, newSoftwareKeyProvider)
}

// newSoftwareKeyProvider creates a software backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "key_dir" (string): Directory for key storage. Empty or "memory" uses in-memory storage.
func newSoftwareKeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	keyDir, _ := config["key_dir"].(string)

	var keyStorage storage.Backend
	if keyDir == "" || keyDir == "memory" {
		keyStorage = storage.New()
	} else {
		var err error
		keyStorage, err = file.New(keyDir)
		if err != nil {
			return nil, err
		}
	}

	return software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
}

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

// Package xkms provides the PKCS#8 backend registration and factory.
//
// The PKCS#8 backend uses PKCS#8 encoded keys stored in memory or on disk.
// This backend is always available.
package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func init() {
	RegisterBackend(BackendPKCS8)
	RegisterBackendFactory(BackendPKCS8, newPKCS8KeyProvider)
}

// newPKCS8KeyProvider creates a PKCS#8 backend KeyProvider from configuration.
//
// Supported configuration keys:
//   - "key_storage" (storage.Backend): pre-built key storage -- the caller's
//     datastore handle (see AutoConfig.Datastore), already a key-prefixed
//     view for this backend. Absent, in-memory storage is used.
//   - "allow_plaintext_keys" (bool): When true, permits persisting unencrypted
//     PKCS#8 keys (no key password). Defaults to false (fail-closed): a key
//     generated without a password is rejected with ErrPlaintextKeyNotAllowed.
//     Set true only when the storage medium is encrypted out of band.
func newPKCS8KeyProvider(config map[string]interface{}) (types.KeyProvider, error) {
	allowPlaintext, _ := config["allow_plaintext_keys"].(bool)

	keyStorage, ok := config["key_storage"].(storage.Backend)
	if !ok || keyStorage == nil {
		keyStorage = storage.New()
	}

	return pkcs8.NewBackend(&pkcs8.Config{
		KeyStorage:         keyStorage,
		AllowPlaintextKeys: allowPlaintext,
	})
}

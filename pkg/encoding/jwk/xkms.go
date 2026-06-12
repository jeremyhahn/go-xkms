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

package jwk

import (
	"crypto"
)

// XKMSKeyGetter is a function type that retrieves a key from the xkms by ID.
// This is used for dependency injection to avoid circular imports with the xkms package.
type XKMSKeyGetter func(keyID string) (crypto.PrivateKey, error)

// XKMSSignerGetter is a function type that retrieves a signer from the xkms by ID.
// This is used for dependency injection to avoid circular imports with the xkms package.
type XKMSSignerGetter func(keyID string) (crypto.Signer, error)

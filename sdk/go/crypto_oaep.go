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
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ResolveOAEPHash resolves an RSA-OAEP hash name to a crypto.Hash, rejecting
// any digest weaker than SHA-256.
//
// It is re-exported so every RSA-OAEP entry point in the stack decides the
// same way. The transports previously disagreed — one accepted SHA-1 while
// another refused it — which meant the padding strength a caller got depended
// on which door they came through. Consumers outside pkg/ (the xkey PKCS#11
// transports among them) route their OAEP hash selection here rather than
// re-deriving the rule and drifting from it.
//
// The rejection is by name rather than by resolved hash, so it holds even
// where an operator has enabled weak hashes for signing: OAEP has no legacy
// blobs to read, so that escape hatch does not apply.
var ResolveOAEPHash = pkgxkms.ResolveOAEPHash

// ErrWeakOAEPHash is returned by ResolveOAEPHash when the requested digest is
// weaker than SHA-256.
var ErrWeakOAEPHash = pkgxkms.ErrWeakOAEPHash

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
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"
)

// NewSPKIPinnedTLSConfig returns a *tls.Config that pins the server's Subject
// Public Key Info (SPKI) to the given pin (base64 SHA-256 of the SPKI). It lets
// client binaries build SPKI-pinned transports (e.g. first-contact bootstrap)
// without importing pkg/crypto/spki directly.
var NewSPKIPinnedTLSConfig = spki.NewPinnedTLSConfig

// PKCS11TLSConfig configures a PKCS#11-backed mTLS client certificate (the
// private key stays in the HSM/token).
type PKCS11TLSConfig = auth.PKCS11TLSConfig

// NewPKCS11TLSConfig builds a *tls.Config whose client certificate is backed by
// a PKCS#11 token, returning a cleanup func for the session/module. It lets
// client binaries wire hardware-backed mTLS without importing pkg/auth.
var NewPKCS11TLSConfig = auth.NewPKCS11TLSConfig

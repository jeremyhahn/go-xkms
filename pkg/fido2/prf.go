// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package fido2

import "crypto/sha256"

// webAuthnPRFContext is the domain-separation label of the WebAuthn prf
// extension.
const webAuthnPRFContext = "WebAuthn PRF"

// WebAuthnPRFSalt returns the hmac-secret salt a browser sends the
// authenticator for a WebAuthn prf evaluation of salt:
//
//	SHA-256(UTF8("WebAuthn PRF") || 0x00 || salt)
//
// (WebAuthn Level 3, the prf extension). A platform that calls hmac-secret
// directly -- a CLI or a desktop client -- must apply the same transform to
// produce the output a browser's prf evaluation of salt would, so a
// credential enrolled on one surface evaluates identically on every other.
// salt is the application-level PRF salt (what a relying party stores); the
// result is the 32-byte CTAP2 hmac-secret salt.
func WebAuthnPRFSalt(salt []byte) []byte {
	h := sha256.New()
	h.Write([]byte(webAuthnPRFContext))
	h.Write([]byte{0x00})
	h.Write(salt)
	return h.Sum(nil)
}

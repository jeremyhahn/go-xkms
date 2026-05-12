// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package keys

import "golang.org/x/crypto/ssh"

// Fingerprint returns the standard OpenSSH SHA256 fingerprint
// ("SHA256:<base64-no-padding>") for pub. golang.org/x/crypto/ssh
// exposes this directly via FingerprintSHA256; this package exists so
// callers reach a single well-documented helper rather than the raw
// ssh API.
//
// Returns the empty string on a nil input — callers that need error
// diagnostics should validate the public key before calling.
func Fingerprint(pub ssh.PublicKey) string {
	if pub == nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

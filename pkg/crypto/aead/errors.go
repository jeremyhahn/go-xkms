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

package aead

import "errors"

var (
	// ErrNonceReuse is returned when a nonce is reused with the same key.
	// This is a critical security error for AEAD ciphers (AES-GCM, ChaCha20-Poly1305).
	//
	// Nonce reuse consequences:
	//   - AES-GCM: Breaks authentication and can leak the auth key
	//   - ChaCha20-Poly1305: Can leak keystream and compromise confidentiality
	//
	// If this error occurs, it indicates a serious bug or attack. The system should:
	//  1. Refuse to encrypt with the reused nonce
	//  2. Log the incident for security review
	//  3. Consider rotating the key immediately
	ErrNonceReuse = errors.New("aead: catastrophic nonce reuse detected - encryption rejected for security")
)

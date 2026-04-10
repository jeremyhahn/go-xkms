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

package aesgcm

import "errors"

var (
	// ErrInvalidKeySize is returned when the key is not exactly 32 bytes.
	ErrInvalidKeySize = errors.New("aesgcm: key must be exactly 32 bytes")

	// ErrCiphertextTooShort is returned when the ciphertext is shorter
	// than the minimum size of NonceSize + TagSize (28 bytes).
	ErrCiphertextTooShort = errors.New("aesgcm: ciphertext too short")

	// ErrDecryptionFailed is returned when GCM authentication fails,
	// indicating the ciphertext was tampered with, the key is wrong,
	// or the AAD does not match.
	ErrDecryptionFailed = errors.New("aesgcm: decryption failed")
)

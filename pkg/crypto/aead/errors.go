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

	// ErrNonceTrackerFull is returned when a bounded NonceTracker has reached
	// its limit and cannot record another nonce.
	//
	// The tracker fails closed rather than evicting an entry, because evicting
	// one turns a reuse it would have detected into one it would not, which is
	// the failure the tracker exists to prevent. Reaching the limit means the
	// key has been used for more encryptions than one process should perform
	// under it: rotate the key, or reinitialize the component that owns the
	// tracker.
	ErrNonceTrackerFull = errors.New("aead: nonce tracker is full - rotate the key or reinitialize the tracker")

	// ErrNonceGuardInput is returned by KeyNonceGuard when the key material or
	// the nonce is empty. Both are required: a guard that accepted an empty
	// value would map every such call onto a single tracker entry and report
	// unrelated operations as reuse.
	ErrNonceGuardInput = errors.New("aead: key material and nonce are both required to guard against nonce reuse")
)

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

package authenticator

// PINVerifier provides an external PIN state query for the FIDO2 authenticator.
// When set, the authenticator delegates PIN state queries to this verifier
// instead of relying solely on its internal state.PINSet field.
//
// This enables the PIN system to be the single source of truth for whether
// a PIN is configured, decoupling the authenticator from internal sync
// mechanisms like sealed PIN blobs.
//
// When PINVerifier is nil (standalone authenticator, tests), the authenticator
// falls back to its existing internal a.state.PINSet field.
type PINVerifier interface {
	// IsPINSet returns true if the user PIN has been configured in the
	// PIN system. The authenticator uses this in GetInfo() to report
	// the clientPin option.
	IsPINSet() bool

	// VerifyFIDO2Hash verifies a FIDO2 PIN hash (SHA-256(PIN)[:16]) against
	// the stored PIN. Returns true if the hash matches. Used for CTAP2 PIN
	// verification commands.
	VerifyFIDO2Hash(hash []byte) bool
}

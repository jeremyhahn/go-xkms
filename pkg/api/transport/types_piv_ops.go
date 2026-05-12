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

package transport

// This file defines request and response types for the three extended PIV
// operations that complement the existing key/cert management surface:
// slot-key signing, slot attestation, and device factory reset.

// PIVSignRequest contains parameters for signing a payload with a PIV slot key.
type PIVSignRequest struct {
	// Backend identifies the xkms backend (e.g., "software", "pkcs11://...").
	Backend string `json:"backend"`
	// Slot is the PIV slot identifier (e.g., "9a", "9c").
	Slot string `json:"slot"`
	// Payload is the raw bytes to sign. When Hashed is false this is hashed
	// before signing using the algorithm named in HashAlgorithm (or a sensible
	// default derived from the slot's key type). When Hashed is true the
	// payload is treated as a pre-computed digest and passed directly to
	// crypto.Signer.Sign.
	Payload []byte `json:"payload"`
	// Hashed indicates whether Payload is a pre-computed digest.
	Hashed bool `json:"hashed,omitempty"`
	// HashAlgorithm is the hash name to use when Hashed is false. One of
	// "sha256", "sha384", "sha512". Empty string selects a default based on
	// the key algorithm (sha256 for P-256/RSA-2048, sha384 for P-384, etc.).
	// Ignored for Ed25519, which signs the raw message.
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	// PIN optionally carries a user PIN for backends that require one
	// (pkcs11, hardware tokens). Ignored by software backends.
	PIN string `json:"pin,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// PIVSignResponse contains the result of signing.
type PIVSignResponse struct {
	// Slot echoes the signing slot.
	Slot string `json:"slot"`
	// Signature is the raw signature bytes. Encoding depends on the key type:
	// DER-encoded ECDSA signatures, PKCS#1 v1.5 RSA signatures, and raw
	// Ed25519 signatures follow Go's crypto/* conventions.
	Signature []byte `json:"signature"`
	// HashAlgorithm reports the algorithm used to hash Payload. Empty when
	// the payload was already hashed or the key type requires no hash
	// (Ed25519).
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
}

// PIVAttestRequest contains parameters for retrieving attestation material
// for a PIV slot.
type PIVAttestRequest struct {
	// Backend identifies the xkms backend.
	Backend string `json:"backend"`
	// Slot is the PIV slot identifier to attest.
	Slot string `json:"slot"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// PIVAttestResponse contains attestation material for a slot.
//
// The attestation model follows YubiKey PIV conventions: the slot's own
// certificate is treated as the attestation statement, and the device-level
// attestation certificate at slot f9 forms the chain back to the vendor's
// attestation CA. Software backends return the slot cert and empty chain.
type PIVAttestResponse struct {
	// Slot echoes the attested slot.
	Slot string `json:"slot"`
	// Certificate is the PEM-encoded attestation statement for the slot.
	Certificate []byte `json:"certificate"`
	// Chain is the PEM-encoded attestation CA chain (may be empty for
	// backends without a hardware attestation CA).
	Chain []byte `json:"chain,omitempty"`
}

// PIVResetDeviceRequest contains parameters for factory-resetting a PIV
// device (clears all certificates from the backend's store).
type PIVResetDeviceRequest struct {
	// Backend identifies the xkms backend to reset. Required.
	Backend string `json:"backend"`
	// Confirm must be set to true for the reset to proceed. This mirrors
	// the double-confirmation a human administrator would perform at a
	// CLI prompt and is intended to guard against accidental API-level
	// invocation.
	Confirm bool `json:"confirm"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

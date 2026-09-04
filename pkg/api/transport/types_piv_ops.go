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

// ImportPIVKeyRequest contains parameters for importing an externally held
// private key into a PIV slot.
//
// Import is a distinct trust class from generation. A slot-generated key
// cannot have existed anywhere before it existed in the slot; an imported one
// can, and nothing the slot can say afterwards distinguishes a key that was
// only ever there from a copy. An attestation over an imported key therefore
// asserts residency but not exclusivity. Callers deciding what an attestation
// is worth must account for that — see docs/piv-smartcard/architecture.md.
type ImportPIVKeyRequest struct {
	// Backend identifies the xkms backend (e.g., "software", "pkcs11://...").
	Backend string `json:"backend"`
	// Slot is the PIV slot identifier (e.g., "9a", "9c").
	Slot string `json:"slot"`
	// PrivateKey is the key material to import: a PEM block or raw DER, in
	// PKCS#8, SEC 1 (EC) or PKCS#1 (RSA) encoding. The encoding is detected
	// rather than declared, because a caller forwarding a key it already
	// holds should not have to re-encode it.
	PrivateKey []byte `json:"private_key"`
	// Algorithm optionally declares the expected PIV algorithm ("rsa2048",
	// "rsa4096", "ecdsap256", "ecdsap384", "ed25519"). When set it is
	// checked against the supplied key and a disagreement is an error: a
	// caller that believes it is importing one algorithm must not silently
	// end up with another. When empty the algorithm is derived from the key.
	Algorithm string `json:"algorithm,omitempty"`
	// PIN optionally carries a user PIN for backends that require one
	// (pkcs11, hardware tokens). Ignored by software backends.
	PIN string `json:"pin,omitempty"`
	// TenantID optionally scopes this operation to a specific tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// ImportPIVKeyResponse reports the result of importing a key into a slot.
type ImportPIVKeyResponse struct {
	// Slot echoes the slot the key was imported into.
	Slot string `json:"slot"`
	// PublicKey is the PEM-encoded public half of the imported key, so a
	// caller can confirm the slot holds the key it supplied.
	PublicKey []byte `json:"public_key"`
	// Algorithm reports the PIV algorithm the key was imported as.
	Algorithm string `json:"algorithm"`
}

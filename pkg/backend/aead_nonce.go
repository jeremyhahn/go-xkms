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

package backend

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// sealedAEADKeyDomain separates a sealedID-derived nonce-guard identity from
// every identity derived from a key's own material, so a key that cannot
// release its bytes (PKCS#11, every cloud-KMS backend) can never collide
// with a key claimed by its bytes; see ClaimAEADNonce.
const sealedAEADKeyDomain = "go-xkms/pkg/backend sealed key\x00"

// errAEADKeyMaterialUnresolved is returned when a caller reports success
// (keyMaterialErr is nil) but supplies no key material. Silently keying on
// empty bytes would collapse every such call onto one guard entry, which is
// exactly the collision the guard exists to prevent.
var errAEADKeyMaterialUnresolved = &errs.Message{Msg: "backend: aead key material unresolved"}

// ClaimAEADNonce is the single point every backend's AEAD Encrypt path --
// the software symmetric backend, Azure Key Vault, PKCS#11, TPM2, and the
// post-quantum KEM hybrid encrypter alike -- calls to atomically claim a
// (key, nonce) pair immediately before Seal.
//
// It is the lowest layer common to a caller that reaches a backend through
// XKMSService and one that constructs a backend directly (sdk/go, xkey):
// before go-xkms#1201's second half, only the XKMSService servicer layer
// claimed through the persistent, atomic aead.KeyNonceGuard, so a caller
// holding a Backend directly -- bypassing the service -- had no protection
// beyond each backend's own AEADSafetyTracker, which checked and recorded in
// two separate steps (a TOCTOU race) and knew nothing about a key it did not
// register in this process. Backend Encrypt is the one call both callers
// pass through, so claiming here closes the gap for both without claiming
// the pair twice for the caller that goes through the service.
//
// keyMaterial and keyMaterialErr are exactly what the backend's own key type
// resolves for the key being used, in whatever form the backend already has
// it in hand for the encryption itself: non-empty bytes and a nil error when
// the backend can supply key material (the software symmetric backend,
// Azure Key Vault's locally generated keys, and TPM2's software AES-GCM path,
// which unseals the key into process memory for exactly this call), or
// ErrNotSupported when it cannot (PKCS#11, whose key material never leaves
// the token). Neither branch takes ownership of keyMaterial or wipes it:
// this function only reads it to derive the guard's identity, the same way
// aead.KeyNonceGuard's own HMAC derivation does, so the caller's existing
// key-material lifecycle is unaffected.
//
// sealedID identifies the key when keyMaterial is unavailable. It must be
// stable for one physical key and distinct across every other key this
// process -- or another node sharing the persistent store -- could claim
// against, so callers build it from types.KeyAttributes.ID(), which already
// encodes the tenant, partition, backend (StoreType), key type, common name
// and algorithm.
//
// Any other keyMaterialErr means the key could not be resolved at all, and
// is returned as-is: an identity derived after an unexplained failure would
// be an identity nobody could reason about, and nothing may be claimed or
// sealed under it.
func ClaimAEADNonce(ctx context.Context, keyMaterial []byte, keyMaterialErr error, sealedID string, nonce []byte) error {
	guard, err := aead.SharedAEADNonceGuard()
	if err != nil {
		return err
	}
	return ClaimAEADNonceIn(ctx, guard, keyMaterial, keyMaterialErr, sealedID, nonce)
}

// ClaimAEADNonceIn is ClaimAEADNonce against a given guard. Production code
// always resolves through ClaimAEADNonce, which passes the process-wide
// aead.SharedAEADNonceGuard; this variant exists so a caller's refusal
// policy -- including a bounded tracker filling up -- can be exercised
// against a guard small enough to fill without exhausting the real one.
func ClaimAEADNonceIn(ctx context.Context, guard *aead.KeyNonceGuard, keyMaterial []byte, keyMaterialErr error, sealedID string, nonce []byte) error {
	identity, err := aeadNonceIdentity(keyMaterial, keyMaterialErr, sealedID)
	if err != nil {
		return err
	}
	return guard.UseContext(ctx, identity, nonce)
}

// ClaimGeneratedAEADNonce is ClaimAEADNonce for a nonce the backend
// generated itself -- opts.Nonce was nil, so the caller supplied none --
// rather than one a caller presented.
//
// The distinction matters only once the guard's bounded in-memory tracker is
// full. A generated nonce is fresh by construction (NIST SP 800-38D section
// 8.2.2: it comes from the backend's own RNG or from a FIPS-mode
// random-nonce GCM construction, never from outside), so its own ciphertext
// is safe to produce whether or not the guard has room left to record it;
// the record only protects against a LATER caller-supplied nonce colliding
// with it. And once the tracker is full, ClaimAEADNonce already refuses
// every caller-supplied nonce, so an unrecorded generated nonce cannot be
// replayed through this path either. Refusing a generated nonce here as well
// would turn a bounded memory cap into a process-wide outage of symmetric
// encryption that any encrypt-capable caller could trigger simply by
// consuming the tracker's capacity.
func ClaimGeneratedAEADNonce(ctx context.Context, keyMaterial []byte, keyMaterialErr error, sealedID string, nonce []byte) error {
	guard, err := aead.SharedAEADNonceGuard()
	if err != nil {
		return err
	}
	return ClaimGeneratedAEADNonceIn(ctx, guard, keyMaterial, keyMaterialErr, sealedID, nonce)
}

// ClaimGeneratedAEADNonceIn is ClaimGeneratedAEADNonce against a given
// guard; see ClaimAEADNonceIn.
func ClaimGeneratedAEADNonceIn(ctx context.Context, guard *aead.KeyNonceGuard, keyMaterial []byte, keyMaterialErr error, sealedID string, nonce []byte) error {
	err := ClaimAEADNonceIn(ctx, guard, keyMaterial, keyMaterialErr, sealedID, nonce)
	if errors.Is(err, aead.ErrNonceTrackerFull) {
		return nil
	}
	return err
}

// aeadNonceIdentity derives the bytes ClaimAEADNonce claims a (key, nonce)
// pair under; see ClaimAEADNonce's doc comment for the two cases this
// chooses between.
func aeadNonceIdentity(keyMaterial []byte, keyMaterialErr error, sealedID string) ([]byte, error) {
	switch {
	case keyMaterialErr == nil && len(keyMaterial) > 0:
		return keyMaterial, nil
	case keyMaterialErr == nil:
		return nil, errAEADKeyMaterialUnresolved
	case errors.Is(keyMaterialErr, ErrNotSupported):
		return []byte(sealedAEADKeyDomain + sealedID), nil
	default:
		return nil, keyMaterialErr
	}
}

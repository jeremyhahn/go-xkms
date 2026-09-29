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
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

const (
	// gcmWrapOperation names an AES-GCM key wrap in the errors it returns.
	gcmWrapOperation = "aes-gcm wrap"

	// aeadEncryptOperation names the generic Encrypt RPC's AEAD path in the
	// errors it returns.
	aeadEncryptOperation = "aead encrypt"
)

// sealedKeyGuardDomain separates the identities of keys whose material a
// backend will not release from every other input the AEAD nonce guard is
// given, so a key named this way can never collide with a key claimed by its
// own bytes.
const sealedKeyGuardDomain = "go-xkms/xkms sealed key\x00"

// aeadKeyIdentity returns the bytes identifying a symmetric key to the AEAD
// nonce guard, together with a function that releases them. It is the one
// identity every service-layer AEAD path claims under -- the AES-GCM wrap and
// the generic Encrypt RPC alike -- so a nonce consumed by one is a nonce
// consumed for the other.
//
// The identity is the key's own material wherever the backend will release it.
// NIST SP 800-38D section 8.2 constrains the (key, IV) PAIR, and the same key
// stored under two common names, in two backends, or reached through two
// service instances is one key to the cipher: an identity taken from the name
// would report those encryptions as unrelated and let the second one through,
// which is the whole failure the guard exists to catch. The material is wiped
// as soon as the claim is made -- the guard keeps only an HMAC of it under a
// per-process salt.
//
// A backend that seals its key material cannot offer bytes to key on: every
// HSM, TPM and cloud-KMS backend answers types.SymmetricKey.Raw with
// backend.ErrNotSupported. For exactly the same reason it cannot be aliased
// either -- material that never leaves the device cannot also be present under
// a second name -- so those keys are identified by attrs.ID(), which names the
// tenant, the store, the key type and the common name.
//
// Any OTHER failure to read the material is not that case: it means the key
// could not be resolved, and it is returned rather than quietly degraded,
// because an identity chosen after an unexplained failure is an identity
// nobody can reason about.
func aeadKeyIdentity(ctx context.Context, b Backend, attrs *types.KeyAttributes, operation string) ([]byte, func(), error) {
	raw, err := rawSymmetricWrappingKey(ctx, b, attrs)
	switch {
	case err == nil && len(raw) > 0:
		return raw, func() { secure.Wipe(raw) }, nil
	case err == nil:
		// A backend that answers with empty material has named no key. Keying
		// on it would collapse every such key onto one guard entry.
		return nil, nil, &ErrKeyOperation{Operation: operation, KeyID: attrs.CN, Err: ErrOperationFailed}
	case errors.Is(err, backend.ErrNotSupported):
		return []byte(sealedKeyGuardDomain + attrs.ID()), func() {}, nil
	default:
		return nil, nil, err
	}
}

// claimAEADNonce claims the (key, nonce) pair an AEAD encryption is about to
// consume -- or, for a nonce the provider generated, has just consumed -- and
// refuses when that pair was already consumed anywhere in this process.
//
// Two encryptions under one (key, nonce) reuse the keystream, so the XOR of
// the two ciphertexts is the XOR of the two plaintexts, and the shared
// authenticator key (GHASH's H for AES-GCM, the one-time Poly1305 key for
// ChaCha20-Poly1305) makes forging tags feasible. The claim goes to the
// process-wide aead.SharedAEADNonceGuard, whose Use makes the check and the
// record one atomic step, so two concurrent callers presenting one nonce
// cannot both pass.
//
// The guard is deliberately independent of any tracking a particular provider
// does: types.AEADSafetyTracker is optional, per backend instance, keyed by
// key id, and blind to any key it was not told about in this process, so it
// sees neither a second instance of the same backend, nor one key material
// reachable under two ids, nor a key created before the process started.
//
// The guard's in-memory tracker alone would forget every claim on restart and
// never see another process's claims. Production wiring closes that gap by
// attaching a PersistentNonceStore to the shared guard at startup
// (pkg/server's initializeAEADNonceStore), so the claim this function makes
// (through UseContext) survives a restart and is visible to every node
// sharing the configured storage backend; see
// docs/symmetric-aead/architecture.md.
func claimAEADNonce(ctx context.Context, b Backend, attrs *types.KeyAttributes, operation string, nonce []byte) error {
	guard, err := aead.SharedAEADNonceGuard()
	if err != nil {
		return &ErrKeyOperation{Operation: operation, KeyID: attrs.CN, Err: err}
	}
	return claimAEADNonceIn(ctx, guard, b, attrs, operation, nonce)
}

// claimAEADNonceIn is claimAEADNonce against a given guard. Production code
// always passes the process-wide one; the parameter exists so the refusal
// policy can be exercised against a guard small enough to fill.
func claimAEADNonceIn(ctx context.Context, guard *aead.KeyNonceGuard, b Backend, attrs *types.KeyAttributes, operation string, nonce []byte) error {
	identity, release, err := aeadKeyIdentity(ctx, b, attrs, operation)
	if err != nil {
		return err
	}
	defer release()

	// UseContext, not Use: this is the service-layer claim, so it also
	// claims through any PersistentNonceStore attached to guard (production
	// wiring: pkg/server's initializeAEADNonceStore, on the shared guard
	// every call here resolves through claimAEADNonce/claimGeneratedAEADNonce).
	// That durability is what closes go-xkms#1201 -- an in-memory-only claim
	// forgets every reuse across a restart, which is exactly the gap the
	// issue reported.
	if err := guard.UseContext(ctx, identity, nonce); err != nil {
		return &ErrKeyOperation{Operation: operation, KeyID: attrs.CN, Err: err}
	}
	return nil
}

// claimGeneratedAEADNonce records a nonce the provider generated for an
// Encrypt RPC, so that no caller can later present it as its own.
//
// That is the attack the record exists to stop: a principal allowed to encrypt
// but not to decrypt reads the nonce off a victim's ciphertext, encrypts chosen
// plaintext under it, and recovers the victim's keystream. A repeat reported
// here means either that or a provider RNG that has stopped producing fresh
// values, and the ciphertext is withheld in both cases.
//
// A full guard is not a refusal on this path. A generated nonce is fresh by
// construction (SP 800-38D section 8.2.2), so its own ciphertext is safe
// whether or not it is recorded; the record only protects against a LATER
// caller-supplied nonce. And once the guard is full, claimAEADNonce refuses
// every caller-supplied nonce on every path in the process, so an unrecorded
// generated nonce cannot be replayed through this service either. Refusing
// here instead would turn a bounded memory cap into a process-wide outage of
// symmetric encryption that any encrypt-capable caller could trigger.
func claimGeneratedAEADNonce(ctx context.Context, b Backend, attrs *types.KeyAttributes, nonce []byte) error {
	guard, err := aead.SharedAEADNonceGuard()
	if err != nil {
		return &ErrKeyOperation{Operation: aeadEncryptOperation, KeyID: attrs.CN, Err: err}
	}
	return claimGeneratedAEADNonceIn(ctx, guard, b, attrs, nonce)
}

// claimGeneratedAEADNonceIn is claimGeneratedAEADNonce against a given guard;
// see claimAEADNonceIn.
func claimGeneratedAEADNonceIn(ctx context.Context, guard *aead.KeyNonceGuard, b Backend, attrs *types.KeyAttributes, nonce []byte) error {
	err := claimAEADNonceIn(ctx, guard, b, attrs, aeadEncryptOperation, nonce)
	if errors.Is(err, aead.ErrNonceTrackerFull) {
		return nil
	}
	return err
}

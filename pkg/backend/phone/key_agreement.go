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

package phone

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// Compile-time interface satisfaction check.
var _ types.KeyAgreementProvider = (*Backend)(nil)

// phoneSupportedCurves defines the elliptic curves supported by the Android
// Keystore for key agreement. These are the NIST curves available in
// TEE/StrongBox secure hardware.
var phoneSupportedCurves = []string{"P-256", "P-384", "P-521"}

// SupportedCurves returns the list of elliptic curves supported for key
// agreement by the Android Keystore hardware backend.
//
// Supported curves:
//   - "P-256" (secp256r1, prime256v1) - 128-bit security
//   - "P-384" (secp384r1) - 192-bit security
//   - "P-521" (secp521r1) - 256-bit security
func (b *Backend) SupportedCurves() []string {
	return phoneSupportedCurves
}

// DeriveKeyECDH performs ECDH key agreement by delegating the raw ECDH
// computation to the Android phone's secure hardware via JSON-RPC, then
// optionally applying a KDF locally to derive the final key material.
//
// The operation:
//  1. Sends the peer's public key to the phone via local.ecdh JSON-RPC
//  2. The phone performs ECDH using its hardware-protected private key
//  3. Returns the raw shared secret
//  4. If kdfParams is non-nil, applies the specified KDF locally
//
// The private key never leaves the phone's TEE/StrongBox secure hardware.
// Only the resulting shared secret is returned over the Noise-encrypted channel.
//
// Parameters:
//   - ctx: Context for cancellation and deadline propagation
//   - privateKeyAttrs: Attributes identifying the phone-resident private key (uses CN as key ID)
//   - peerPublicKey: The peer's DER-encoded public key
//   - kdfParams: Parameters for the key derivation function; if nil, the raw shared secret is returned
func (b *Backend) DeriveKeyECDH(
	ctx context.Context,
	privateKeyAttrs *types.KeyAttributes,
	peerPublicKey []byte,
	kdfParams *types.KDFParams,
) ([]byte, error) {

	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if privateKeyAttrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	if len(peerPublicKey) == 0 {
		return nil, ErrInvalidPeerPublicKey
	}

	// Send the ECDH request to the phone. The phone performs the raw ECDH
	// in its secure hardware and returns the shared secret.
	params := &phoneproto.LocalECDHParams{
		KeyID:         privateKeyAttrs.CN,
		PeerPublicKey: peerPublicKey,
	}

	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalECDH, params)
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalECDHResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	if len(result.SharedSecret) == 0 {
		return nil, ErrEmptySharedSecret
	}

	// If no KDF params, return the raw shared secret.
	if kdfParams == nil {
		return result.SharedSecret, nil
	}

	// Validate and apply defaults to the KDF parameters.
	if err := kdfParams.Validate(); err != nil {
		return nil, ErrInvalidKDFParams
	}

	return applyKDF(result.SharedSecret, kdfParams)
}

// applyKDF derives a key from the raw shared secret using the canonical KDF
// implementation in pkg/crypto/kdf, reached through types.KDFParams.Derive.
// Every backend derives through that one entry point, so the same parameters
// yield the same bytes here as on the TPM 2.0, software, and PKCS#11
// backends.
func applyKDF(sharedSecret []byte, params *types.KDFParams) ([]byte, error) {
	if params == nil {
		return nil, ErrInvalidKDFParams
	}
	return params.Derive(sharedSecret)
}

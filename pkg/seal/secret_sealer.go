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

package seal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// secretSealerInfo is the HKDF context string binding a derived data key to
// this sealer's purpose, so the same secret used elsewhere cannot produce a
// colliding key.
const secretSealerInfo = "go-xkms/seal/secret-sealer/v1"

// ErrSecretSealerEmptySecret is returned when a secret sealer is constructed
// with no key material.
var ErrSecretSealerEmptySecret = errors.New("seal: secret sealer requires non-empty secret")

// ErrSecretSealerNilSealedData is returned when Unseal is called with a nil
// sealed data envelope.
var ErrSecretSealerNilSealedData = errors.New("seal: sealed data is nil")

// SecretSealer is a types.Sealer that encrypts arbitrary values with
// AES-256-GCM under a key derived (HKDF-SHA256) from a caller-supplied secret.
// It is the software bridge that lets a node-local key store be sealed under a
// secret that is ITSELF protected by a stronger mechanism — a TPM-sealed random
// key (the xkey "software key encrypted with a key sealed to the TPM" pattern)
// or an operator passphrase — resolved by KeyProtection. The secret never
// leaves process memory beyond the derived data key held here.
//
// It is deliberately a small, standalone AES-GCM sealer (not tied to any key
// store or the barrier) so it can wrap node-local key storage at construction
// time, before the qrdb node or barrier exist.
type SecretSealer struct {
	dataKey []byte // 32-byte AES-256 key derived from the secret
}

// NewSecretSealer derives an AES-256 data key from secret via HKDF-SHA256 and
// returns a sealer over it. The secret is not retained; only the derived key
// is held. Returns ErrSecretSealerEmptySecret for an empty secret.
func NewSecretSealer(secret []byte) (*SecretSealer, error) {
	if len(secret) == 0 {
		return nil, ErrSecretSealerEmptySecret
	}
	// crypto/hkdf.Key (the stdlib RFC 5869 implementation, Go 1.24+) is used
	// instead of golang.org/x/crypto/hkdf.New: the x/crypto Reader
	// constructor converts the stdlib's own FIPS 140-only refusals (a secret
	// under 112 bits) into a panic, which would crash this process instead
	// of returning the error this constructor promises.
	dataKey, err := hkdf.Key(sha256.New, secret, nil, secretSealerInfo, 32)
	if err != nil {
		return nil, err
	}
	return &SecretSealer{dataKey: dataKey}, nil
}

// CanSeal reports whether the sealer holds a usable data key.
func (s *SecretSealer) CanSeal() bool {
	return s != nil && len(s.dataKey) == 32
}

// Seal encrypts data with AES-256-GCM under the derived data key, binding
// opts.AAD (when opts is non-nil) as additional authenticated data. A value
// sealed without AAD is byte-for-byte what earlier builds produced.
func (s *SecretSealer) Seal(_ context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if !s.CanSeal() {
		return nil, ErrSecretSealerEmptySecret
	}
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	var aad []byte
	if opts != nil {
		aad = opts.AAD
	}
	// Seal generates the nonce inside the module and prepends it. Split it back
	// out so SealedData keeps its existing shape: the Nonce and Ciphertext
	// fields hold exactly what they held before, so blobs sealed by earlier
	// builds still unseal and blobs sealed now are readable by them.
	sealed := gcm.Seal(nil, nil, data, aad)
	return &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: sealed[gcmNonceSize:],
		Nonce:      sealed[:gcmNonceSize],
	}, nil
}

// Unseal decrypts sealed data produced by Seal, authenticating opts.AAD
// (when opts is non-nil) as the additional authenticated data Seal bound.
//
// Sealed-data authentication: the error matches
// types.ErrSealedDataAuthentication, joined with the AEAD's error where it
// produced one, exactly when the sealed data is at fault -- sealed.Backend is
// not the software backend Seal stamps, the nonce is not 12 bytes, or
// gcm.Open refuses a ciphertext that was tampered with, truncated or
// extended, sealed under another secret, or sealed under different AAD. A
// cancelled or expired ctx, and a sealer without a usable key, are not.
func (s *SecretSealer) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	return s.open(ctx, nil, sealed, opts)
}

// open authenticates and decrypts sealed, appending the plaintext to dst. It
// is the one implementation behind Unseal and UnsealInto.
func (s *SecretSealer) open(ctx context.Context, dst []byte, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, ErrSecretSealerNilSealedData
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.CanSeal() {
		return nil, ErrSecretSealerEmptySecret
	}
	if err := checkEnvelope(sealed); err != nil {
		return nil, err
	}
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	var aad []byte
	if opts != nil {
		aad = opts.AAD
	}
	// The random-nonce AEAD expects its nonce at the head of the payload
	// rather than passed separately. Only the ciphertext is reassembled here;
	// Open writes the plaintext straight into dst.
	blob := make([]byte, 0, len(sealed.Nonce)+len(sealed.Ciphertext))
	blob = append(blob, sealed.Nonce...)
	blob = append(blob, sealed.Ciphertext...)
	plaintext, err := gcm.Open(dst, nil, blob, aad)
	if err != nil {
		return nil, types.SealedDataAuthenticationError("seal: AES-GCM open", err)
	}
	return plaintext, nil
}

// checkEnvelope rejects sealed data whose shape is not one Seal produces: a
// backend other than the software backend Seal stamps, or a nonce that is not
// 12 bytes. Both are sealed-data authentication failures. The nonce arrives
// from stored or caller data; the random-nonce AEAD would reject a short one
// too, but checking here names the defect.
func checkEnvelope(sealed *types.SealedData) error {
	if sealed.Backend != types.BackendTypeSoftware {
		return types.SealedDataAuthenticationError(
			fmt.Sprintf("seal: sealed data was not created by the secret sealer (backend %s)", sealed.Backend), nil)
	}
	if len(sealed.Nonce) != gcmNonceSize {
		return types.SealedDataAuthenticationError(
			fmt.Sprintf("seal: nonce is %d bytes, want %d", len(sealed.Nonce), gcmNonceSize), nil)
	}
	return nil
}

// gcmNonceSize is the 96-bit GCM nonce length. cipher.NewGCMWithRandomNonce
// reports a NonceSize of zero because it manages the nonce itself, so the
// length has to be named here to keep splitting it out of the sealed blob.
const gcmNonceSize = 12

// gcm builds the AES-256-GCM AEAD over the derived data key.
func (s *SecretSealer) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.dataKey)
	if err != nil {
		return nil, err
	}
	// NewGCMWithRandomNonce, not NewGCM: FIPS 140-3 (SP 800-38D, CMVP IG C.H)
	// requires the GCM IV be generated inside the module boundary, and
	// GODEBUG=fips140=only rejects an externally supplied one. The AEAD
	// prepends the same 96-bit nonce to the ciphertext, so the stored layout is
	// unchanged once Seal splits it back into SealedData.Nonce.
	return cipher.NewGCMWithRandomNonce(block)
}

// Compile-time check.
var _ types.Sealer = (*SecretSealer)(nil)

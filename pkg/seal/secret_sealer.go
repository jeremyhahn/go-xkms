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
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// secretSealerInfo is the HKDF context string binding a derived data key to
// this sealer's purpose, so the same secret used elsewhere cannot produce a
// colliding key.
const secretSealerInfo = "go-xkms/seal/secret-sealer/v1"

// ErrSecretSealerEmptySecret is returned when a secret sealer is constructed
// with no key material.
var ErrSecretSealerEmptySecret = errors.New("seal: secret sealer requires non-empty secret")

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
	dataKey := make([]byte, 32)
	kdf := hkdf.New(sha256.New, secret, nil, []byte(secretSealerInfo))
	if _, err := io.ReadFull(kdf, dataKey); err != nil {
		return nil, err
	}
	return &SecretSealer{dataKey: dataKey}, nil
}

// CanSeal reports whether the sealer holds a usable data key.
func (s *SecretSealer) CanSeal() bool {
	return s != nil && len(s.dataKey) == 32
}

// Seal encrypts data with AES-256-GCM under the derived data key.
func (s *SecretSealer) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	if !s.CanSeal() {
		return nil, ErrSecretSealerEmptySecret
	}
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return &types.SealedData{
		Backend:    types.BackendTypeSoftware,
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

// Unseal decrypts sealed data produced by Seal.
func (s *SecretSealer) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, errors.New("seal: sealed data is nil")
	}
	if !s.CanSeal() {
		return nil, ErrSecretSealerEmptySecret
	}
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	// crypto/cipher panics rather than returning an error when the nonce is
	// not exactly NonceSize bytes. The nonce arrives from stored/caller data,
	// so without this check a corrupted or malicious sealed blob takes the
	// whole process down.
	if len(sealed.Nonce) != gcm.NonceSize() {
		return nil, &errs.Message{Msg: fmt.Sprintf(
			"seal: nonce is %d bytes, want %d", len(sealed.Nonce), gcm.NonceSize())}
	}
	return gcm.Open(nil, sealed.Nonce, sealed.Ciphertext, nil)
}

// gcm builds the AES-256-GCM AEAD over the derived data key.
func (s *SecretSealer) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.dataKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Compile-time check.
var _ types.Sealer = (*SecretSealer)(nil)

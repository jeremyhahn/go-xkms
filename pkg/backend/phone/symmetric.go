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

// Compile-time interface satisfaction check for SymmetricBackend.
var _ types.SymmetricKeyProvider = (*Backend)(nil)

// symmetricAlgorithmMapping maps types.SymmetricAlgorithm values to the phone
// protocol algorithm strings using O(1) map-based dispatch.
var symmetricAlgorithmMapping = map[types.SymmetricAlgorithm]string{
	types.SymmetricAES128GCM:         "AES128-GCM",
	types.SymmetricAES192GCM:         "AES192-GCM",
	types.SymmetricAES256GCM:         "AES256-GCM",
	types.SymmetricChaCha20Poly1305:  "CHACHA20-POLY1305",
	types.SymmetricXChaCha20Poly1305: "XCHACHA20-POLY1305",
}

// phoneAlgorithmToSymmetric provides the reverse mapping from phone protocol
// algorithm strings back to types.SymmetricAlgorithm using O(1) map-based dispatch.
var phoneAlgorithmToSymmetric = map[string]types.SymmetricAlgorithm{
	"AES128-GCM":         types.SymmetricAES128GCM,
	"AES192-GCM":         types.SymmetricAES192GCM,
	"AES256-GCM":         types.SymmetricAES256GCM,
	"AES128":             types.SymmetricAES128GCM,
	"AES256":             types.SymmetricAES256GCM,
	"CHACHA20-POLY1305":  types.SymmetricChaCha20Poly1305,
	"XCHACHA20-POLY1305": types.SymmetricXChaCha20Poly1305,
}

// phoneSymmetricKey represents a symmetric key held in the phone's secure
// hardware. The key material never leaves the TEE/StrongBox, so Raw()
// returns ErrExportNotSupported.
type phoneSymmetricKey struct {
	keyID     string
	algorithm string
	keySize   int
}

// Algorithm returns the symmetric algorithm identifier for this key.
func (k *phoneSymmetricKey) Algorithm() string {
	return k.algorithm
}

// KeySize returns the key size in bits.
func (k *phoneSymmetricKey) KeySize() int {
	return k.keySize
}

// Raw returns ErrExportNotSupported because hardware-backed symmetric keys
// cannot expose their key material.
func (k *phoneSymmetricKey) Raw() ([]byte, error) {
	return nil, ErrExportNotSupported
}

// phoneSymmetricEncrypter proxies symmetric encrypt/decrypt operations to the
// phone's secure hardware via Noise-encrypted JSON-RPC.
type phoneSymmetricEncrypter struct {
	backend   *Backend
	keyID     string
	algorithm string
}

// GenerateSymmetricKey generates a new symmetric key on the phone's hardware
// keystore. The key material remains in the TEE/StrongBox and is never exported.
func (b *Backend) GenerateSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if attrs == nil {
		return nil, ErrInvalidConfig
	}

	phoneAlgo, err := mapSymmetricAlgorithm(attrs.SymmetricAlgorithm)
	if err != nil {
		return nil, err
	}

	params := &phoneproto.LocalGenerateKeyParams{
		KeyID:     attrs.CN,
		Algorithm: phoneAlgo,
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.config.RequestTimeout)
	defer cancel()

	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalGenerateKey, params)
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalGenerateKeyResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	symAlgo := resolveSymmetricAlgorithm(result.Algorithm, attrs.SymmetricAlgorithm)

	return &phoneSymmetricKey{
		keyID:     result.KeyID,
		algorithm: string(symAlgo),
		keySize:   symAlgo.KeySize(),
	}, nil
}

// GetSymmetricKey retrieves metadata for an existing symmetric key from the
// phone's hardware keystore. The returned SymmetricKey provides algorithm and
// size information but cannot export key material.
func (b *Backend) GetSymmetricKey(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if attrs == nil {
		return nil, ErrInvalidConfig
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.config.RequestTimeout)
	defer cancel()

	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalGetKeyInfo, &phoneproto.LocalGetKeyInfoParams{
		KeyID: attrs.CN,
	})
	if err != nil {
		return nil, err
	}

	keyInfo, err := phoneproto.DecodeResult[phoneproto.LocalGetKeyInfoResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	symAlgo := resolveSymmetricAlgorithm(keyInfo.Algorithm, attrs.SymmetricAlgorithm)

	return &phoneSymmetricKey{
		keyID:     keyInfo.KeyID,
		algorithm: string(symAlgo),
		keySize:   symAlgo.KeySize(),
	}, nil
}

// SymmetricEncrypter returns a SymmetricEncrypter that proxies encrypt/decrypt
// operations to the phone's secure hardware for the key identified by attrs.
// The key must exist on the phone before calling this method.
func (b *Backend) SymmetricEncrypter(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}
	if attrs == nil {
		return nil, ErrInvalidConfig
	}

	ctx, cancel := context.WithTimeout(context.Background(), b.config.RequestTimeout)
	defer cancel()

	// Verify the key exists on the phone.
	resp, err := b.sendLocalRequest(ctx, phoneproto.MethodLocalGetKeyInfo, &phoneproto.LocalGetKeyInfoParams{
		KeyID: attrs.CN,
	})
	if err != nil {
		return nil, err
	}

	keyInfo, err := phoneproto.DecodeResult[phoneproto.LocalGetKeyInfoResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	return &phoneSymmetricEncrypter{
		backend:   b,
		keyID:     attrs.CN,
		algorithm: keyInfo.Algorithm,
	}, nil
}

// Encrypt sends the plaintext to the phone for symmetric encryption via
// local.symmetricEncrypt. The phone's secure hardware performs the encryption
// and returns the ciphertext blob (IV + encrypted data + tag). The returned
// EncryptedData stores the raw blob in the Ciphertext field since the phone
// manages nonce generation and tag appending internally.
func (e *phoneSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	if plaintext == nil {
		return nil, ErrSymmetricEncryptFailed
	}

	params := &phoneproto.LocalSymmetricEncryptParams{
		KeyID:     e.keyID,
		Plaintext: plaintext,
	}

	if opts != nil && len(opts.AdditionalData) > 0 {
		params.AAD = opts.AdditionalData
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.backend.config.RequestTimeout)
	defer cancel()

	resp, err := e.backend.sendLocalRequest(ctx, phoneproto.MethodLocalSymmetricEncrypt, params)
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalSymmetricEncryptResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	return &types.EncryptedData{
		Ciphertext: result.Ciphertext,
		Algorithm:  e.algorithm,
	}, nil
}

// Decrypt sends ciphertext to the phone for symmetric decryption via
// local.symmetricDecrypt. The phone expects the ciphertext blob in the same
// format it produced during encryption (IV + encrypted data + tag).
func (e *phoneSymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	if data == nil {
		return nil, ErrSymmetricDecryptFailed
	}

	params := &phoneproto.LocalSymmetricDecryptParams{
		KeyID:      e.keyID,
		Ciphertext: data.Ciphertext,
	}

	if opts != nil && len(opts.AdditionalData) > 0 {
		params.AAD = opts.AdditionalData
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.backend.config.RequestTimeout)
	defer cancel()

	resp, err := e.backend.sendLocalRequest(ctx, phoneproto.MethodLocalSymmetricDecrypt, params)
	if err != nil {
		return nil, err
	}

	result, err := phoneproto.DecodeResult[phoneproto.LocalSymmetricDecryptResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	return result.Plaintext, nil
}

// mapSymmetricAlgorithm converts a types.SymmetricAlgorithm to the phone
// protocol algorithm string. Returns ErrUnsupportedAlgorithm if the algorithm
// is not recognized.
func mapSymmetricAlgorithm(algo types.SymmetricAlgorithm) (string, error) {
	if phoneAlgo, ok := symmetricAlgorithmMapping[algo]; ok {
		return phoneAlgo, nil
	}
	return "", ErrUnsupportedAlgorithm
}

// resolveSymmetricAlgorithm maps a phone protocol algorithm string back to a
// types.SymmetricAlgorithm. If the phone's response algorithm is not in the
// reverse map, it falls back to the original requested algorithm. This ensures
// a valid SymmetricAlgorithm is always returned for key metadata.
func resolveSymmetricAlgorithm(phoneAlgo string, requested types.SymmetricAlgorithm) types.SymmetricAlgorithm {
	if symAlgo, ok := phoneAlgorithmToSymmetric[phoneAlgo]; ok {
		return symAlgo
	}
	return requested
}

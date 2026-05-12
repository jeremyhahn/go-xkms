// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

// Package wrapping implements the RSA-OAEP and hybrid RSA+AES-KWP key
// wrapping algorithms used by xkms backends during the key-import and
// key-export ceremonies.
//
// # Memory discipline
//
// Every sensitive intermediate produced during wrap / unwrap — the
// ephemeral AES wrapping key, the padded plaintext, the unwrapped
// material — lives in a *secure.Buffer with an immediate deferred
// Destroy(). Only at the boundary of this package (the public
// []byte-returning signatures) is the material copied out into a
// plain slice, and that slice is the caller's responsibility to move
// into its own *secure.Buffer or *secure.Secret as soon as possible.
//
// The public signatures remain []byte-in / []byte-out for drop-in
// compatibility with the HSM / cloud backends (awskms, azurekv,
// gcpkms, pkcs11) that are migrated in a later phase; the internal
// hardening still bounces the secret off the Go heap for the duration
// of the arithmetic.
package wrapping

import (
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// hashFuncForAlgorithm resolves the hash.Hash to use for a given
// wrapping algorithm. Returns *UnsupportedAlgorithmError for algorithms
// this package does not implement.
func hashFuncForAlgorithm(algorithm backend.WrappingAlgorithm) (hash.Hash, error) {
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1:
		return sha1.New(), nil
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		return sha256.New(), nil
	default:
		return nil, &UnsupportedAlgorithmError{Algorithm: string(algorithm)}
	}
}

// WrapRSAOAEP wraps key material using RSA-OAEP encryption. Suitable
// only for small material (up to RSA key size minus OAEP overhead);
// for larger material use WrapRSAAES.
//
// Parameters:
//   - keyMaterial: plaintext to wrap. Callers should hold this in a
//     *secure.Buffer and pass the Bytes() slice, then Destroy their
//     Buffer after this function returns — the slice is read-only
//     here.
//   - publicKey: the RSA public key to encrypt with.
//   - algorithm: one of the RSAES_OAEP_* values.
func WrapRSAOAEP(keyMaterial []byte, publicKey *rsa.PublicKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(keyMaterial) == 0 {
		return nil, &EmptyInputError{Field: "keyMaterial"}
	}
	if publicKey == nil {
		return nil, &NilInputError{Field: "publicKey"}
	}
	h, err := hashFuncForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	wrapped, encErr := rsa.EncryptOAEP(h, rand.Reader, publicKey, keyMaterial, nil)
	if encErr != nil {
		return nil, &CryptoError{Op: "rsa.EncryptOAEP", Err: encErr}
	}
	return wrapped, nil
}

// UnwrapRSAOAEP unwraps key material that was encrypted with
// WrapRSAOAEP. The returned plaintext is a fresh heap-allocated slice;
// callers MUST move it into a *secure.Buffer / *secure.Secret
// immediately and wipe the returned slice. This package does its own
// internal wipes but cannot reach into the caller's stack frame.
func UnwrapRSAOAEP(wrappedKey []byte, privateKey *rsa.PrivateKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(wrappedKey) == 0 {
		return nil, &EmptyInputError{Field: "wrappedKey"}
	}
	if privateKey == nil {
		return nil, &NilInputError{Field: "privateKey"}
	}
	h, err := hashFuncForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	// rsa.DecryptOAEP allocates the output slice. It is sensitive —
	// move it into a Buffer, copy out for the return value, destroy
	// the Buffer.
	raw, decErr := rsa.DecryptOAEP(h, rand.Reader, privateKey, wrappedKey, nil)
	if decErr != nil {
		return nil, &CryptoError{Op: "rsa.DecryptOAEP", Err: decErr}
	}
	return encloseAndCopy(raw)
}

// WrapRSAAES wraps key material using the hybrid RSA-OAEP + AES-KWP
// construction (AWS KMS "RSA_AES_KEY_WRAP_SHA_*" scheme). Flow:
//
//  1. Generate a random 256-bit AES wrapping key (secure.Buffer).
//  2. Wrap the AES key with RSA-OAEP using the caller's public key.
//  3. Wrap keyMaterial with AES-KWP (RFC 5649).
//  4. Emit [4-byte wrappedAESKey length][wrappedAESKey][AES-wrapped].
//
// All intermediate sensitive buffers are held in *secure.Buffer for
// the duration of this call and destroyed before returning.
func WrapRSAAES(keyMaterial []byte, publicKey *rsa.PublicKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(keyMaterial) == 0 {
		return nil, &EmptyInputError{Field: "keyMaterial"}
	}
	if publicKey == nil {
		return nil, &NilInputError{Field: "publicKey"}
	}
	h, err := hashFuncForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	// Step 1: Random 256-bit AES wrapping key, into a Buffer.
	aesKeyBuf, err := secure.NewBuffer(32)
	if err != nil {
		return nil, &CryptoError{Op: "alloc aes key buffer", Err: err}
	}
	defer aesKeyBuf.Destroy()
	if _, rerr := rand.Read(aesKeyBuf.Bytes()); rerr != nil {
		return nil, &CryptoError{Op: "read random aes key", Err: rerr}
	}

	// Step 2: Wrap the AES key with RSA-OAEP. The AES key plaintext is
	// provided from the Buffer; the wrapped output is non-sensitive.
	wrappedAESKey, encErr := rsa.EncryptOAEP(h, rand.Reader, publicKey, aesKeyBuf.Bytes(), nil)
	if encErr != nil {
		return nil, &CryptoError{Op: "rsa.EncryptOAEP (aes key)", Err: encErr}
	}

	// Step 3: Wrap keyMaterial with AES-KWP. wrapKeyWithAESKWP reads
	// the AES key and plaintext; its own internal intermediates use
	// secure.Buffer.
	wrappedMaterial, kwpErr := wrapKeyWithAESKWP(keyMaterial, aesKeyBuf.Bytes())
	if kwpErr != nil {
		return nil, kwpErr
	}

	// Step 4: Concatenate with length prefix.
	aesKeyLen := uint32(len(wrappedAESKey))
	out := make([]byte, 4+len(wrappedAESKey)+len(wrappedMaterial))
	binary.BigEndian.PutUint32(out[0:4], aesKeyLen)
	copy(out[4:4+len(wrappedAESKey)], wrappedAESKey)
	copy(out[4+len(wrappedAESKey):], wrappedMaterial)
	return out, nil
}

// UnwrapRSAAES inverts WrapRSAAES. Like UnwrapRSAOAEP, the returned
// plaintext is caller-owned and sensitive; callers must immediately
// move it into a Buffer / Secret and wipe.
func UnwrapRSAAES(wrappedKey []byte, privateKey *rsa.PrivateKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(wrappedKey) < 4 {
		return nil, &MalformedWrappedKeyError{Reason: "too short"}
	}
	if privateKey == nil {
		return nil, &NilInputError{Field: "privateKey"}
	}
	h, err := hashFuncForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	aesKeyLen := binary.BigEndian.Uint32(wrappedKey[0:4])
	if aesKeyLen > uint32(len(wrappedKey)-4) {
		return nil, &MalformedWrappedKeyError{Reason: "aes key length overflow"}
	}
	if len(wrappedKey) < int(4+aesKeyLen) {
		return nil, &MalformedWrappedKeyError{Reason: "truncated"}
	}
	wrappedAESKey := wrappedKey[4 : 4+aesKeyLen]
	wrappedMaterial := wrappedKey[4+aesKeyLen:]

	// Unwrap the AES key straight into a Buffer. rsa.DecryptOAEP
	// returns a fresh slice; we move it into a Buffer (which wipes
	// the source) and destroy on return.
	rawAES, decErr := rsa.DecryptOAEP(h, rand.Reader, privateKey, wrappedAESKey, nil)
	if decErr != nil {
		return nil, &CryptoError{Op: "rsa.DecryptOAEP (aes key)", Err: decErr}
	}
	aesBuf, bufErr := secure.NewBufferFromBytes(rawAES)
	if bufErr != nil {
		// NewBufferFromBytes wipes rawAES even on error paths for
		// non-empty input; the len==0 case here would imply the RSA
		// ciphertext decrypted to nothing, which is a malformed
		// input.
		return nil, &MalformedWrappedKeyError{Reason: "empty aes key after unwrap"}
	}
	defer aesBuf.Destroy()

	// Unwrap the material using the AES key inside the Buffer. The
	// returned plaintext is sensitive — hand it off to the caller.
	plaintext, kwpErr := unwrapKeyWithAESKWP(wrappedMaterial, aesBuf.Bytes())
	if kwpErr != nil {
		return nil, kwpErr
	}
	return plaintext, nil
}

// wrapKeyWithAESKWP implements AES-KWP (RFC 5649). Intermediate state
// (padded plaintext, register buffer) lives in *secure.Buffer.
func wrapKeyWithAESKWP(plaintext, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, &InvalidKeySizeError{Algorithm: "aes-kwp", Size: len(key)}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &CryptoError{Op: "aes.NewCipher (wrap)", Err: err}
	}

	// RFC 5649 Alternative Initial Value.
	aiv := [8]byte{}
	binary.BigEndian.PutUint32(aiv[0:4], 0xA65959A6)
	binary.BigEndian.PutUint32(aiv[4:8], uint32(len(plaintext)))

	// Pad plaintext to an 8-byte multiple inside a Buffer.
	padLen := (8 - (len(plaintext) % 8)) % 8
	padded, pErr := secure.NewBuffer(len(plaintext) + padLen)
	if pErr != nil {
		return nil, &CryptoError{Op: "alloc padded plaintext", Err: pErr}
	}
	defer padded.Destroy()
	copy(padded.Bytes(), plaintext)
	paddedBytes := padded.Bytes()

	// Special case: total padded length == 8.
	if len(paddedBytes) == 8 {
		// C[0] = E(K, A || P[1])
		in := [16]byte{}
		copy(in[0:8], aiv[:])
		copy(in[8:16], paddedBytes)
		out := make([]byte, 16)
		block.Encrypt(out, in[:])
		return out, nil
	}

	// General case: n * 8-byte blocks plus AIV.
	n := len(paddedBytes) / 8
	regLen := (n + 1) * 8
	registers, rerr := secure.NewBuffer(regLen)
	if rerr != nil {
		return nil, &CryptoError{Op: "alloc register buffer", Err: rerr}
	}
	defer registers.Destroy()
	rb := registers.Bytes()
	copy(rb[0:8], aiv[:])
	copy(rb[8:], paddedBytes)

	// Perform 6*n rounds. The register buffer is sliced into 8-byte
	// windows R[0..n]; we keep a scratch buffer for B = E(K, A || R[i]).
	// B itself is not sensitive per-iteration (ciphertext), but we keep
	// it small and stack-local by reusing the same 16-byte array.
	var b [16]byte
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(b[0:8], rb[0:8])
			copy(b[8:16], rb[i*8:(i+1)*8])
			block.Encrypt(b[:], b[:])

			// A = MSB(64, B) XOR t
			t := uint64(n*j + i)
			copy(rb[0:8], b[0:8])
			for k := 7; k >= 0; k-- {
				rb[7-k] ^= byte(t >> (uint(k) * 8))
			}
			// R[i] = LSB(64, B)
			copy(rb[i*8:(i+1)*8], b[8:16])
		}
	}

	// Copy the register contents to the returned []byte. The returned
	// ciphertext is not sensitive — it's the wrapped output intended
	// for external storage.
	out := make([]byte, regLen)
	copy(out, rb)
	return out, nil
}

// unwrapKeyWithAESKWP inverts wrapKeyWithAESKWP. The unwrapped output
// IS sensitive and is returned as a plain []byte — the caller is
// expected to immediately move it into a secure.Buffer.
func unwrapKeyWithAESKWP(ciphertext, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, &InvalidKeySizeError{Algorithm: "aes-kwp", Size: len(key)}
	}
	if len(ciphertext) < 16 || len(ciphertext)%8 != 0 {
		return nil, &MalformedWrappedKeyError{Reason: "ciphertext must be >= 16 bytes and multiple of 8"}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &CryptoError{Op: "aes.NewCipher (unwrap)", Err: err}
	}

	n := (len(ciphertext) / 8) - 1

	// Special case: n == 1.
	if n == 1 {
		out := make([]byte, 16)
		block.Decrypt(out, ciphertext)
		if binary.BigEndian.Uint32(out[0:4]) != 0xA65959A6 {
			return nil, &MalformedWrappedKeyError{Reason: "invalid AIV"}
		}
		mli := binary.BigEndian.Uint32(out[4:8])
		if mli > 8 {
			return nil, &MalformedWrappedKeyError{Reason: "invalid MLI"}
		}
		// The plaintext portion (out[8:8+mli]) is sensitive — move it
		// into a Buffer briefly, then return a caller-owned slice.
		return encloseAndCopy(out[8 : 8+mli])
	}

	// General case: unwrap into a register buffer (secure.Buffer).
	regLen := (n + 1) * 8
	registers, rerr := secure.NewBuffer(regLen)
	if rerr != nil {
		return nil, &CryptoError{Op: "alloc register buffer (unwrap)", Err: rerr}
	}
	defer registers.Destroy()
	rb := registers.Bytes()
	copy(rb, ciphertext)

	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			copy(b[0:8], rb[0:8])
			t := uint64(n*j + i)
			for k := 7; k >= 0; k-- {
				b[7-k] ^= byte(t >> (uint(k) * 8))
			}
			copy(b[8:16], rb[i*8:(i+1)*8])
			block.Decrypt(b[:], b[:])
			copy(rb[0:8], b[0:8])
			copy(rb[i*8:(i+1)*8], b[8:16])
		}
	}

	if binary.BigEndian.Uint32(rb[0:4]) != 0xA65959A6 {
		return nil, &MalformedWrappedKeyError{Reason: "invalid AIV"}
	}
	mli := binary.BigEndian.Uint32(rb[4:8])
	if mli > uint32(n*8) {
		return nil, &MalformedWrappedKeyError{Reason: "invalid MLI"}
	}

	// The unwrapped plaintext sits in rb[8 : 8+mli]. Copy it out; the
	// register buffer is destroyed by the deferred Destroy above.
	return encloseAndCopy(rb[8 : 8+mli])
}

// encloseAndCopy runs the sensitive src through a *secure.Buffer and
// returns a fresh caller-owned slice. The source slice is wiped via
// secure.Wipe.
//
// This helper exists so every "returning sensitive bytes to a caller"
// site has the same pattern: the material takes a round trip through
// a locked buffer even though we cannot control what the caller does
// next. Combined with the documented contract ("callers MUST move
// immediately into a Buffer/Secret"), this bounds the plaintext
// lifetime to a single stack frame on both sides of the boundary.
func encloseAndCopy(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, &EmptyInputError{Field: "src"}
	}
	buf, err := secure.NewBuffer(len(src))
	if err != nil {
		return nil, &CryptoError{Op: "enclose sensitive result", Err: err}
	}
	defer buf.Destroy()
	copy(buf.Bytes(), src)
	out := make([]byte, len(src))
	copy(out, buf.Bytes())
	// Best-effort wipe of our caller-supplied source.
	secure.Wipe(src)
	return out, nil
}

// GetHashForAlgorithm returns the crypto.Hash ID for the given
// wrapping algorithm. Kept for backward compatibility with callers
// that need the hash identifier separately (e.g., PKCS#11 mechanisms).
func GetHashForAlgorithm(algorithm backend.WrappingAlgorithm) (crypto.Hash, error) {
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1:
		return crypto.SHA1, nil
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		return crypto.SHA256, nil
	default:
		return 0, &UnsupportedAlgorithmError{Algorithm: string(algorithm)}
	}
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package wrapping

import (
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/jeremyhahn/go-keychain/pkg/backend"
)

// WrapRSAOAEP wraps key material using RSA-OAEP encryption.
// The algorithm parameter specifies which hash function to use (SHA-1 or SHA-256).
// This method is suitable for wrapping small amounts of key material (up to the RSA key size minus overhead).
// For larger key material, use WrapRSAAES which employs a hybrid approach.
//
// Parameters:
//   - keyMaterial: The plaintext key material to wrap (must fit within RSA key size limits)
//   - publicKey: The RSA public key to use for wrapping
//   - algorithm: Must be WrappingAlgorithmRSAES_OAEP_SHA_1 or WrappingAlgorithmRSAES_OAEP_SHA_256
//
// Returns:
//   - The wrapped (encrypted) key material
//   - An error if wrapping fails or parameters are invalid
func WrapRSAOAEP(keyMaterial []byte, publicKey *rsa.PublicKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(keyMaterial) == 0 {
		return nil, fmt.Errorf("key material cannot be nil or empty")
	}
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	var hashFunc hash.Hash
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1:
		hashFunc = sha1.New()
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		hashFunc = sha256.New()
	default:
		return nil, fmt.Errorf("unsupported wrapping algorithm: %s", algorithm)
	}

	// Encrypt the key material with RSA-OAEP
	wrapped, err := rsa.EncryptOAEP(hashFunc, rand.Reader, publicKey, keyMaterial, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key material with RSA-OAEP: %w", err)
	}

	return wrapped, nil
}

// UnwrapRSAOAEP unwraps key material that was encrypted using RSA-OAEP.
// The algorithm parameter must match the algorithm used during wrapping.
//
// Parameters:
//   - wrappedKey: The encrypted key material to unwrap
//   - privateKey: The RSA private key corresponding to the public key used for wrapping
//   - algorithm: Must be WrappingAlgorithmRSAES_OAEP_SHA_1 or WrappingAlgorithmRSAES_OAEP_SHA_256
//
// Returns:
//   - The unwrapped (plaintext) key material
//   - An error if unwrapping fails or parameters are invalid
func UnwrapRSAOAEP(wrappedKey []byte, privateKey *rsa.PrivateKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(wrappedKey) == 0 {
		return nil, fmt.Errorf("wrapped key cannot be nil or empty")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	var hashFunc hash.Hash
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1:
		hashFunc = sha1.New()
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		hashFunc = sha256.New()
	default:
		return nil, fmt.Errorf("unsupported wrapping algorithm: %s", algorithm)
	}

	// Decrypt the key material with RSA-OAEP
	unwrapped, err := rsa.DecryptOAEP(hashFunc, rand.Reader, privateKey, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key material with RSA-OAEP: %w", err)
	}

	return unwrapped, nil
}

// WrapRSAAES wraps key material using a hybrid RSA + AES-KWP algorithm.
// This is required for wrapping large key material (e.g., RSA private keys) that exceed
// the size limits of direct RSA encryption.
//
// The wrapping process:
//  1. Generate a random 256-bit AES key
//  2. Wrap the AES key using RSA-OAEP with the specified hash function
//  3. Wrap the target key material using AES Key Wrap with Padding (RFC 5649)
//  4. Return: [4-byte length][wrapped AES key][wrapped key material]
//
// The 4-byte length prefix allows proper parsing during unwrapping.
//
// Parameters:
//   - keyMaterial: The plaintext key material to wrap (can be any size)
//   - publicKey: The RSA public key to use for wrapping the AES key
//   - algorithm: Must be WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1 or WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256
//
// Returns:
//   - The wrapped key material (length prefix + wrapped AES key + AES-wrapped data)
//   - An error if wrapping fails or parameters are invalid
func WrapRSAAES(keyMaterial []byte, publicKey *rsa.PublicKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(keyMaterial) == 0 {
		return nil, fmt.Errorf("key material cannot be nil or empty")
	}
	if publicKey == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}

	var hashFunc hash.Hash
	switch algorithm {
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1:
		hashFunc = sha1.New()
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		hashFunc = sha256.New()
	default:
		return nil, fmt.Errorf("unsupported wrapping algorithm: %s", algorithm)
	}

	// Step 1: Generate a random 256-bit AES key
	aesKey := make([]byte, 32) // 256 bits
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate random AES key: %w", err)
	}

	// Step 2: Wrap the AES key with RSA-OAEP
	wrappedAESKey, err := rsa.EncryptOAEP(hashFunc, rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap AES key with RSA-OAEP: %w", err)
	}

	// Step 3: Wrap the key material with AES-KWP (RFC 5649)
	wrappedKeyMaterial, err := wrapKeyWithAESKWP(keyMaterial, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key material with AES-KWP: %w", err)
	}

	// Step 4: Concatenate with length prefix
	// Format: [4-byte wrapped AES key length][wrapped AES key][wrapped key material]
	wrappedAESKeyLen := uint32(len(wrappedAESKey))
	result := make([]byte, 4+len(wrappedAESKey)+len(wrappedKeyMaterial))
	binary.BigEndian.PutUint32(result[0:4], wrappedAESKeyLen)
	copy(result[4:4+len(wrappedAESKey)], wrappedAESKey)
	copy(result[4+len(wrappedAESKey):], wrappedKeyMaterial)

	return result, nil
}

// UnwrapRSAAES unwraps key material that was encrypted using the hybrid RSA + AES-KWP algorithm.
// The algorithm parameter must match the algorithm used during wrapping.
//
// The unwrapping process:
//  1. Parse the length prefix to determine where the wrapped AES key ends
//  2. Unwrap the AES key using RSA-OAEP with the specified hash function
//  3. Unwrap the target key material using AES Key Wrap with Padding (RFC 5649)
//
// Parameters:
//   - wrappedKey: The wrapped key material (length prefix + wrapped AES key + AES-wrapped data)
//   - privateKey: The RSA private key corresponding to the public key used for wrapping
//   - algorithm: Must be WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1 or WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256
//
// Returns:
//   - The unwrapped (plaintext) key material
//   - An error if unwrapping fails or parameters are invalid
func UnwrapRSAAES(wrappedKey []byte, privateKey *rsa.PrivateKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(wrappedKey) < 4 {
		return nil, fmt.Errorf("wrapped key is too short or nil")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	var hashFunc hash.Hash
	switch algorithm {
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1:
		hashFunc = sha1.New()
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		hashFunc = sha256.New()
	default:
		return nil, fmt.Errorf("unsupported wrapping algorithm: %s", algorithm)
	}

	// Step 1: Parse the length prefix
	wrappedAESKeyLen := binary.BigEndian.Uint32(wrappedKey[0:4])

	// Check for overflow and validate length
	if wrappedAESKeyLen > uint32(len(wrappedKey)-4) {
		return nil, fmt.Errorf("wrapped key is corrupted: invalid AES key length %d, max allowed %d",
			wrappedAESKeyLen, len(wrappedKey)-4)
	}

	if len(wrappedKey) < int(4+wrappedAESKeyLen) {
		return nil, fmt.Errorf("wrapped key is corrupted: insufficient data for wrapped AES key")
	}

	// Step 2: Extract wrapped AES key and wrapped key material
	wrappedAESKey := wrappedKey[4 : 4+wrappedAESKeyLen]
	wrappedKeyMaterial := wrappedKey[4+wrappedAESKeyLen:]

	// Step 3: Unwrap the AES key with RSA-OAEP
	aesKey, err := rsa.DecryptOAEP(hashFunc, rand.Reader, privateKey, wrappedAESKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap AES key with RSA-OAEP: %w", err)
	}

	// Step 4: Unwrap the key material with AES-KWP
	keyMaterial, err := unwrapKeyWithAESKWP(wrappedKeyMaterial, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key material with AES-KWP: %w", err)
	}

	return keyMaterial, nil
}

// wrapKeyWithAESKWP wraps key material using AES Key Wrap with Padding (RFC 5649).
// This is also known as AES-KWP and provides authenticated encryption for key material.
//
// RFC 5649 extends RFC 3394 to handle plaintext of any length (not just multiples of 8 bytes).
func wrapKeyWithAESKWP(plaintext, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 16, 24, or 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// RFC 5649 Alternative Initial Value (AIV)
	// AIV = 0xA65959A6 || MLI
	// where MLI is the 32-bit message length in big-endian
	aiv := make([]byte, 8)
	binary.BigEndian.PutUint32(aiv[0:4], 0xA65959A6)
	binary.BigEndian.PutUint32(aiv[4:8], uint32(len(plaintext)))

	// Pad plaintext to multiple of 8 bytes
	padLen := (8 - (len(plaintext) % 8)) % 8
	paddedPlaintext := make([]byte, len(plaintext)+padLen)
	copy(paddedPlaintext, plaintext)

	// If plaintext is 8 bytes or less, use special case
	if len(paddedPlaintext) == 8 {
		// C[0] = E(K, A || P[1])
		input := make([]byte, 16)
		copy(input[0:8], aiv)
		copy(input[8:16], paddedPlaintext)
		output := make([]byte, 16)
		block.Encrypt(output, input)
		return output, nil
	}

	// For larger plaintexts, use the standard key wrap algorithm
	n := len(paddedPlaintext) / 8 // number of 64-bit blocks

	// Initialize with AIV and plaintext blocks
	r := make([][]byte, n+1)
	r[0] = aiv
	for i := 0; i < n; i++ {
		r[i+1] = paddedPlaintext[i*8 : (i+1)*8]
	}

	// Perform 6*n rounds of wrapping
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			// B = E(K, A || R[i])
			b := make([]byte, 16)
			copy(b[0:8], r[0])
			copy(b[8:16], r[i])
			block.Encrypt(b, b)

			// A = MSB(64, B) XOR t where t = (n*j)+i
			t := uint64(n*j + i)
			r[0] = b[0:8]
			for k := 7; k >= 0; k-- {
				r[0][k] ^= byte(t >> ((7 - k) * 8))
			}

			// R[i] = LSB(64, B)
			r[i] = b[8:16]
		}
	}

	// Concatenate all blocks
	result := make([]byte, (n+1)*8)
	for i := 0; i <= n; i++ {
		copy(result[i*8:(i+1)*8], r[i])
	}

	return result, nil
}

// unwrapKeyWithAESKWP unwraps key material using AES Key Wrap with Padding (RFC 5649).
func unwrapKeyWithAESKWP(ciphertext, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 16, 24, or 32 bytes")
	}
	if len(ciphertext) < 16 || len(ciphertext)%8 != 0 {
		return nil, fmt.Errorf("ciphertext must be at least 16 bytes and a multiple of 8")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	n := (len(ciphertext) / 8) - 1

	// Special case for n = 1
	if n == 1 {
		// P[1] = D(K, C[0] || C[1])
		output := make([]byte, 16)
		block.Decrypt(output, ciphertext)

		// Check AIV
		if binary.BigEndian.Uint32(output[0:4]) != 0xA65959A6 {
			return nil, fmt.Errorf("invalid AIV in wrapped key")
		}

		mli := binary.BigEndian.Uint32(output[4:8])
		if mli > 8 {
			return nil, fmt.Errorf("invalid message length in AIV: %d", mli)
		}

		return output[8 : 8+mli], nil
	}

	// Initialize registers
	r := make([][]byte, n+1)
	for i := 0; i <= n; i++ {
		r[i] = ciphertext[i*8 : (i+1)*8]
	}

	// Perform 6*n rounds of unwrapping
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			// B = D(K, (A XOR t) || R[i]) where t = n*j+i
			b := make([]byte, 16)
			copy(b[0:8], r[0])

			t := uint64(n*j + i)
			for k := 7; k >= 0; k-- {
				b[k] ^= byte(t >> ((7 - k) * 8))
			}

			copy(b[8:16], r[i])
			block.Decrypt(b, b)

			// A = MSB(64, B)
			r[0] = b[0:8]

			// R[i] = LSB(64, B)
			r[i] = b[8:16]
		}
	}

	// Verify AIV and extract plaintext length
	if binary.BigEndian.Uint32(r[0][0:4]) != 0xA65959A6 {
		return nil, fmt.Errorf("invalid AIV in wrapped key")
	}

	mli := binary.BigEndian.Uint32(r[0][4:8])
	if mli > uint32(n*8) {
		return nil, fmt.Errorf("invalid message length in AIV: %d", mli)
	}

	// Extract and return plaintext
	plaintext := make([]byte, n*8)
	for i := 1; i <= n; i++ {
		copy(plaintext[(i-1)*8:i*8], r[i])
	}

	return plaintext[:mli], nil
}

// GetHashForAlgorithm returns the hash function for the given wrapping algorithm.
// This is useful for determining the correct hash to use with RSA-OAEP operations.
func GetHashForAlgorithm(algorithm backend.WrappingAlgorithm) (crypto.Hash, error) {
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1:
		return crypto.SHA1, nil
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		return crypto.SHA256, nil
	default:
		return 0, fmt.Errorf("unsupported wrapping algorithm: %s", algorithm)
	}
}

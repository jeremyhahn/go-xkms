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

package secretservice

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// DH parameters for IETF RFC 2409 Group 14 (2048-bit MODP Group)
// https://www.rfc-editor.org/rfc/rfc3526#section-3
var (
	// dhPrime is the 2048-bit MODP prime from RFC 3526 Section 3.
	dhPrime = mustParseBigInt(
		"FFFFFFFF" + "FFFFFFFF" + "C90FDAA2" + "2168C234" +
			"C4C6628B" + "80DC1CD1" + "29024E08" + "8A67CC74" +
			"020BBEA6" + "3B139B22" + "514A0879" + "8E3404DD" +
			"EF9519B3" + "CD3A431B" + "302B0A6D" + "F25F1437" +
			"4FE1356D" + "6D51C245" + "E485B576" + "625E7EC6" +
			"F44C42E9" + "A637ED6B" + "0BFF5CB6" + "F406B7ED" +
			"EE386BFB" + "5A899FA5" + "AE9F2411" + "7C4B1FE6" +
			"49286651" + "ECE45B3D" + "C2007CB8" + "A163BF05" +
			"98DA4836" + "1C55D39A" + "69163FA8" + "FD24CF5F" +
			"83655D23" + "DCA3AD96" + "1C62F356" + "208552BB" +
			"9ED52907" + "7096966D" + "670C354E" + "4ABC9804" +
			"F1746C08" + "CA18217C" + "32905E46" + "2E36CE3B" +
			"E39E772C" + "180E8603" + "9B2783A2" + "EC07A28F" +
			"B5C55DF0" + "6F4C52C9" + "DE2BCBF6" + "95581718" +
			"3995497C" + "EA956AE5" + "15D22618" + "98FA0510" +
			"15728E5A" + "8AACAA68" + "FFFFFFFF" + "FFFFFFFF",
	)

	// dhGenerator is the generator for the DH group.
	dhGenerator = big.NewInt(2)
)

// mustParseBigInt parses a hex string into a big.Int or panics.
func mustParseBigInt(hex string) *big.Int {
	n := new(big.Int)
	_, ok := n.SetString(hex, 16)
	if !ok {
		panic("invalid hex string for big.Int")
	}
	return n
}

// DHKeyPair holds a Diffie-Hellman key pair.
type DHKeyPair struct {
	// Private is the private key (random exponent).
	Private *big.Int

	// Public is the public key (g^private mod p).
	Public *big.Int
}

// GenerateDHKeyPair generates a new Diffie-Hellman key pair.
func GenerateDHKeyPair() (*DHKeyPair, error) {
	// Generate random private key (256 bits is sufficient for 2048-bit DH).
	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return nil, ErrDHKeyExchangeFailed
	}

	private := new(big.Int).SetBytes(privateBytes)

	// Compute public key: g^private mod p
	public := new(big.Int).Exp(dhGenerator, private, dhPrime)

	return &DHKeyPair{
		Private: private,
		Public:  public,
	}, nil
}

// ComputeSharedSecret computes the DH shared secret given our private key
// and the peer's public key.
func ComputeSharedSecret(privateKey *big.Int, peerPublicKey *big.Int) *big.Int {
	// shared = peerPublic^private mod p
	return new(big.Int).Exp(peerPublicKey, privateKey, dhPrime)
}

// DeriveAESKey derives a 16-byte AES-128 key from the DH shared secret
// using SHA-256 and taking the first 16 bytes.
func DeriveAESKey(sharedSecret *big.Int) []byte {
	// Hash the shared secret
	hash := sha256.Sum256(sharedSecret.Bytes())
	// Take first 16 bytes for AES-128
	return hash[:16]
}

// SessionCrypto provides encryption/decryption for a Secret Service session.
type SessionCrypto struct {
	// AESKey is the 16-byte AES-128 key.
	AESKey []byte
}

// NewSessionCrypto creates a SessionCrypto from the DH shared secret.
func NewSessionCrypto(sharedSecret *big.Int) *SessionCrypto {
	return &SessionCrypto{
		AESKey: DeriveAESKey(sharedSecret),
	}
}

// NewSessionCryptoFromKey creates a SessionCrypto from a raw AES key.
func NewSessionCryptoFromKey(aesKey []byte) *SessionCrypto {
	return &SessionCrypto{
		AESKey: aesKey,
	}
}

// Encrypt encrypts plaintext using AES-128-CBC with PKCS#7 padding.
// Returns the IV and ciphertext.
func (sc *SessionCrypto) Encrypt(plaintext []byte) (iv []byte, ciphertext []byte, err error) {
	block, err := aes.NewCipher(sc.AESKey)
	if err != nil {
		return nil, nil, ErrEncryptionFailed
	}

	// Generate random IV
	iv = make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, ErrEncryptionFailed
	}

	// PKCS#7 padding
	padded := pkcs7Pad(plaintext, aes.BlockSize)

	// Encrypt
	ciphertext = make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return iv, ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-128-CBC with PKCS#7 padding.
func (sc *SessionCrypto) Decrypt(iv []byte, ciphertext []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, ErrDecryptionFailed
	}

	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrDecryptionFailed
	}

	block, err := aes.NewCipher(sc.AESKey)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return unpadded, nil
}

// pkcs7Pad adds PKCS#7 padding to data.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padBytes := make([]byte, padding)
	for i := range padBytes {
		padBytes[i] = byte(padding)
	}
	return append(data, padBytes...)
}

// pkcs7Unpad removes PKCS#7 padding from data.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrDecryptionFailed
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, ErrDecryptionFailed
	}

	// Verify padding bytes
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, ErrDecryptionFailed
		}
	}

	return data[:len(data)-padding], nil
}

// PublicKeyToBytes converts a DH public key to wire format (big-endian bytes).
func PublicKeyToBytes(pub *big.Int) []byte {
	return pub.Bytes()
}

// PublicKeyFromBytes converts wire format bytes to a DH public key.
func PublicKeyFromBytes(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

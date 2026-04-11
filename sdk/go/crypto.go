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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/mem"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/rand"
	"github.com/jeremyhahn/go-xkms/pkg/signing"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Shamir secret sharing types and functions re-exported via go-qrdb/sdk/go.
// These allow SDK consumers to split and reconstruct secrets without importing
// the internal shamir package directly.
type (
	// ShamirShare represents a single share in a Shamir secret sharing scheme.
	ShamirShare = qrdbsdk.ShamirShare
)

// Shamir secret sharing functions.
var (
	// ShamirSplit divides a secret into N shares where any M shares can reconstruct it.
	//
	// Parameters:
	//   - secret: The secret data to split
	//   - threshold: Minimum number of shares needed to reconstruct (M)
	//   - total: Total number of shares to create (N)
	ShamirSplit = qrdbsdk.ShamirSplit

	// ShamirCombine reconstructs the original secret from M or more shares.
	ShamirCombine = qrdbsdk.ShamirCombine

	// ShamirVerifyShare checks if a share is valid and consistent with other shares.
	ShamirVerifyShare = qrdbsdk.ShamirVerifyShare
)

// Signing types re-exported from pkg/signing.
type (
	// SignerOpts extends crypto.SignerOpts with additional options for
	// flexible signing operations including blob-based signing and RSA-PSS.
	SignerOpts = signing.SignerOpts
)

// Signing constructor functions.
var (
	// NewSignerOpts creates a new SignerOpts with the specified hash function.
	NewSignerOpts = signing.NewSignerOpts
)

// Crypto adapter error types.
type (
	// ErrSignerKeyFetch is returned when the signer fails to fetch the public key.
	ErrSignerKeyFetch struct {
		KeyID   string
		Backend string
		Err     error
	}

	// ErrSignerParsePEM is returned when the public key PEM cannot be parsed.
	ErrSignerParsePEM struct {
		KeyID string
		Err   error
	}

	// ErrSignerSign is returned when a signing operation fails.
	ErrSignerSign struct {
		KeyID string
		Err   error
	}

	// ErrDecrypterKeyFetch is returned when the decrypter fails to fetch the public key.
	ErrDecrypterKeyFetch struct {
		KeyID   string
		Backend string
		Err     error
	}

	// ErrDecrypterParsePEM is returned when the public key PEM cannot be parsed.
	ErrDecrypterParsePEM struct {
		KeyID string
		Err   error
	}

	// ErrDecrypterDecrypt is returned when a decryption operation fails.
	ErrDecrypterDecrypt struct {
		KeyID string
		Err   error
	}
)

func (e *ErrSignerKeyFetch) Error() string {
	return "xkms signer: failed to fetch key " + e.KeyID + " from backend " + e.Backend + ": " + e.Err.Error()
}

func (e *ErrSignerKeyFetch) Unwrap() error { return e.Err }

func (e *ErrSignerParsePEM) Error() string {
	return "xkms signer: failed to parse public key PEM for key " + e.KeyID + ": " + e.Err.Error()
}

func (e *ErrSignerParsePEM) Unwrap() error { return e.Err }

func (e *ErrSignerSign) Error() string {
	return "xkms signer: signing failed for key " + e.KeyID + ": " + e.Err.Error()
}

func (e *ErrSignerSign) Unwrap() error { return e.Err }

func (e *ErrDecrypterKeyFetch) Error() string {
	return "xkms decrypter: failed to fetch key " + e.KeyID + " from backend " + e.Backend + ": " + e.Err.Error()
}

func (e *ErrDecrypterKeyFetch) Unwrap() error { return e.Err }

func (e *ErrDecrypterParsePEM) Error() string {
	return "xkms decrypter: failed to parse public key PEM for key " + e.KeyID + ": " + e.Err.Error()
}

func (e *ErrDecrypterParsePEM) Unwrap() error { return e.Err }

func (e *ErrDecrypterDecrypt) Error() string {
	return "xkms decrypter: decryption failed for key " + e.KeyID + ": " + e.Err.Error()
}

func (e *ErrDecrypterDecrypt) Unwrap() error { return e.Err }

// hashToString maps crypto.Hash values to the string representation
// expected by the XKMS transport layer.
var hashToString = map[crypto.Hash]string{
	crypto.SHA256:     "SHA-256",
	crypto.SHA384:     "SHA-384",
	crypto.SHA512:     "SHA-512",
	crypto.SHA1:       "SHA-1",
	crypto.SHA512_256: "SHA-512/256",
}

// XKMSSigner wraps an XKMS SDK client key into the crypto.Signer interface.
// This allows XKMS-managed keys to be used with standard Go TLS and x509
// packages, enabling hardware-backed keys (TPM, HSM, cloud KMS) to participate
// in TLS handshakes and certificate signing operations transparently.
type XKMSSigner struct {
	client    Client
	backend   string
	keyID     string
	publicKey crypto.PublicKey
}

// Compile-time assertion that XKMSSigner implements crypto.Signer.
var _ crypto.Signer = (*XKMSSigner)(nil)

// NewXKMSSigner creates a crypto.Signer backed by an XKMS SDK client key.
// It fetches the public key from the specified backend and key ID, parsing
// the PEM-encoded public key from the server response.
func NewXKMSSigner(client Client, backend, keyID string) (*XKMSSigner, error) {
	pub, err := fetchPublicKey(client, backend, keyID)
	if err != nil {
		return nil, &ErrSignerKeyFetch{KeyID: keyID, Backend: backend, Err: err}
	}
	return &XKMSSigner{
		client:    client,
		backend:   backend,
		keyID:     keyID,
		publicKey: pub,
	}, nil
}

// Public returns the public key associated with the XKMS-managed private key.
func (s *XKMSSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the digest with the XKMS-managed key. The rand parameter is
// ignored because the randomness is managed server-side by the XKMS backend.
// The opts parameter is used to determine the hash algorithm to communicate
// to the server.
func (s *XKMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashStr := ""
	if opts != nil {
		if h, ok := hashToString[opts.HashFunc()]; ok {
			hashStr = h
		}
	}

	resp, err := s.client.Sign(context.Background(), &transport.SignRequest{
		Backend: s.backend,
		KeyID:   s.keyID,
		Data:    digest,
		Hash:    hashStr,
	})
	if err != nil {
		return nil, &ErrSignerSign{KeyID: s.keyID, Err: err}
	}

	return resp.Signature, nil
}

// XKMSDecrypter wraps an XKMS SDK client key into the crypto.Decrypter interface.
// This allows XKMS-managed keys to be used with standard Go TLS for RSA key
// exchange, enabling hardware-backed decryption operations transparently.
type XKMSDecrypter struct {
	client    Client
	backend   string
	keyID     string
	publicKey crypto.PublicKey
}

// Compile-time assertion that XKMSDecrypter implements crypto.Decrypter.
var _ crypto.Decrypter = (*XKMSDecrypter)(nil)

// NewXKMSDecrypter creates a crypto.Decrypter backed by an XKMS SDK client key.
// It fetches the public key from the specified backend and key ID, parsing
// the PEM-encoded public key from the server response.
func NewXKMSDecrypter(client Client, backend, keyID string) (*XKMSDecrypter, error) {
	pub, err := fetchPublicKey(client, backend, keyID)
	if err != nil {
		return nil, &ErrDecrypterKeyFetch{KeyID: keyID, Backend: backend, Err: err}
	}
	return &XKMSDecrypter{
		client:    client,
		backend:   backend,
		keyID:     keyID,
		publicKey: pub,
	}, nil
}

// Public returns the public key associated with the XKMS-managed private key.
func (d *XKMSDecrypter) Public() crypto.PublicKey {
	return d.publicKey
}

// Decrypt decrypts the ciphertext with the XKMS-managed key. The rand parameter
// is ignored because the randomness is managed server-side by the XKMS backend.
// The opts parameter is currently unused but reserved for future OAEP label support.
func (d *XKMSDecrypter) Decrypt(_ io.Reader, ciphertext []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	resp, err := d.client.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    d.backend,
		KeyID:      d.keyID,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return nil, &ErrDecrypterDecrypt{KeyID: d.keyID, Err: err}
	}

	return resp.Plaintext, nil
}

// fetchPublicKey retrieves and parses the PEM-encoded public key for a key
// from the XKMS server. This is shared by both XKMSSigner and XKMSDecrypter.
func fetchPublicKey(client Client, backend, keyID string) (crypto.PublicKey, error) {
	resp, err := client.GetKey(context.Background(), backend, keyID)
	if err != nil {
		return nil, err
	}

	return parsePublicKeyPEM(resp.PublicKeyPEM)
}

// parsePublicKeyPEM decodes a PEM-encoded public key and returns the parsed
// crypto.PublicKey.
func parsePublicKeyPEM(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, &ErrSignerParsePEM{KeyID: "unknown", Err: errNoPEMBlock}
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// errNoPEMBlock is a sentinel used when PEM decoding yields no block.
var errNoPEMBlock = &XKMSError{
	Code:    ErrCodeInvalidRequest,
	Message: "no PEM block found in public key data",
}

// ---------------------------------------------------------------------------
// AES-GCM encryption/decryption re-exported from pkg/crypto/aesgcm.
// These allow SDK consumers to perform AES-256-GCM authenticated encryption
// without importing the internal aesgcm package directly.
// ---------------------------------------------------------------------------

// AES-GCM constants re-exported from pkg/crypto/aesgcm.
const (
	// AESGCMKeySize is the required AES-256 key size in bytes (32).
	AESGCMKeySize = aesgcm.KeySize

	// AESGCMNonceSize is the GCM standard nonce size in bytes (12).
	AESGCMNonceSize = aesgcm.NonceSize

	// AESGCMTagSize is the GCM authentication tag size in bytes (16).
	AESGCMTagSize = aesgcm.TagSize

	// AESGCMOverhead is the total overhead added to plaintext (nonce + tag).
	AESGCMOverhead = aesgcm.Overhead
)

// AES-GCM functions re-exported from pkg/crypto/aesgcm.
var (
	// AESGCMEncrypt encrypts plaintext using AES-256-GCM with a random nonce.
	// The key must be exactly 32 bytes (AES-256).
	// Returns [nonce:12][ciphertext+tag] on success.
	AESGCMEncrypt = aesgcm.Encrypt

	// AESGCMDecrypt decrypts ciphertext produced by AESGCMEncrypt.
	// The key must be exactly 32 bytes (AES-256).
	// Input format: [nonce:12][ciphertext+tag]
	AESGCMDecrypt = aesgcm.Decrypt

	// AESGCMEncryptWithAAD encrypts plaintext using AES-256-GCM with additional
	// authenticated data (AAD). The key must be exactly 32 bytes (AES-256).
	// Returns [nonce:12][ciphertext+tag] on success.
	AESGCMEncryptWithAAD = aesgcm.EncryptWithAAD

	// AESGCMDecryptWithAAD decrypts ciphertext produced by AESGCMEncryptWithAAD
	// with the same additional authenticated data. The key must be exactly 32 bytes
	// (AES-256). Input format: [nonce:12][ciphertext+tag]
	AESGCMDecryptWithAAD = aesgcm.DecryptWithAAD
)

// AES-GCM sentinel errors re-exported from pkg/crypto/aesgcm.
var (
	// AESGCMErrInvalidKeySize is returned when the key is not exactly 32 bytes.
	AESGCMErrInvalidKeySize = aesgcm.ErrInvalidKeySize

	// AESGCMErrCiphertextTooShort is returned when the ciphertext is shorter
	// than the minimum size of NonceSize + TagSize (28 bytes).
	AESGCMErrCiphertextTooShort = aesgcm.ErrCiphertextTooShort

	// AESGCMErrDecryptionFailed is returned when GCM authentication fails.
	AESGCMErrDecryptionFailed = aesgcm.ErrDecryptionFailed
)

// ---------------------------------------------------------------------------
// Secure memory utilities re-exported from pkg/crypto/mem.
// These allow SDK consumers to securely wipe and guard sensitive memory
// without importing the internal mem package directly.
// ---------------------------------------------------------------------------

// SecureMemGuardedBuffer is a type alias for mem.GuardedBuffer. It holds
// sensitive key material in OS-protected memory with guard pages (Linux)
// or guaranteed zeroing on free (other platforms).
type SecureMemGuardedBuffer = mem.GuardedBuffer

// Secure memory functions re-exported from pkg/crypto/mem.
var (
	// SecureMemZero overwrites the byte slice with zeros.
	// This is used to clear sensitive data like keys and passwords from memory.
	SecureMemZero = mem.Zero

	// SecureMemNewGuardedBuffer allocates a new guarded buffer of the given size.
	// On Linux, the buffer is backed by an anonymous mmap region with
	// guard pages and mlock protection. On other platforms, a plain heap
	// allocation is used.
	SecureMemNewGuardedBuffer = mem.NewGuardedBuffer

	// SecureMemZeroAndFree zeros and frees a GuardedBuffer. Safe to call with nil.
	SecureMemZeroAndFree = mem.ZeroAndFree
)

// Secure memory error types re-exported from pkg/crypto/mem.
type (
	// SecureMemErrInvalidSize is returned when a guarded buffer is requested
	// with a non-positive size.
	SecureMemErrInvalidSize = mem.ErrInvalidSize

	// SecureMemErrMmapFailed is returned when the mmap system call fails
	// during guarded buffer allocation.
	SecureMemErrMmapFailed = mem.ErrMmapFailed

	// SecureMemErrMprotectFailed is returned when mprotect fails while
	// setting up guard pages for a guarded buffer.
	SecureMemErrMprotectFailed = mem.ErrMprotectFailed
)

// ---------------------------------------------------------------------------
// Random number generation re-exported from pkg/crypto/rand.
// These allow SDK consumers to create configurable RNG resolvers backed by
// hardware (TPM2, PKCS#11) or software sources without importing the
// internal rand package directly.
// ---------------------------------------------------------------------------

// RNG mode constants re-exported from pkg/crypto/rand.
const (
	// RandModeAuto automatically selects the best available RNG.
	// Preference order: TPM2 > PKCS#11 > Software
	RandModeAuto = rand.ModeAuto

	// RandModeSoftware uses crypto/rand (stdlib secure random).
	RandModeSoftware = rand.ModeSoftware

	// RandModeTPM2 uses Trusted Platform Module 2.0 hardware RNG.
	RandModeTPM2 = rand.ModeTPM2

	// RandModePKCS11 uses PKCS#11 hardware security module RNG.
	RandModePKCS11 = rand.ModePKCS11
)

// RNG types re-exported from pkg/crypto/rand.
type (
	// RandMode specifies which RNG source to use.
	RandMode = rand.Mode

	// RandConfig contains RNG configuration.
	RandConfig = rand.Config

	// RandTPM2Config contains TPM2-specific RNG configuration.
	RandTPM2Config = rand.TPM2Config

	// RandPKCS11Config contains PKCS#11-specific RNG configuration.
	RandPKCS11Config = rand.PKCS11Config

	// RandSource represents a random number generator source.
	RandSource = rand.Source

	// RandResolver provides the main interface for generating random numbers.
	// It implements io.Reader, making it compatible with crypto/rand.Reader.
	RandResolver = rand.Resolver
)

// RNG functions re-exported from pkg/crypto/rand.
var (
	// RandNewResolver creates a new RNG resolver with the given configuration.
	// Accepts nil (auto mode), a rand.Mode string, or a *rand.Config.
	// Returns an error if the primary mode is unavailable and no fallback
	// is configured.
	RandNewResolver = rand.NewResolver
)

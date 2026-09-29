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

package encoding

import (
	"crypto"
	"crypto/x509"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/youmark/pkcs8"
)

// pbkdf2IterationCount is the PBKDF2-HMAC-SHA256 iteration count used to
// encrypt a PKCS#8 key: 600,000, OWASP's 2023 recommendation for
// PBKDF2-SHA256 (go-xkms#1286), replacing this package's prior default of
// 10,000. A key already encrypted at a lower iteration count stays
// decryptable: PBES2 records its own iteration count in the encrypted blob,
// and DecodePKCS8/youmark/pkcs8 read it from there rather than assuming this
// constant.
const pbkdf2IterationCount = 600000

// Compile-time assertion that pbkdf2IterationCount does not regress below
// the package-wide PBKDF2 floor.
var _ [pbkdf2IterationCount - kdf.MinPBKDF2Iterations]struct{}

// PKCS8EncryptOpts pins the PBKDF2 salt size and iteration count
// youmark/pkcs8 uses to encrypt a PKCS#8 key, instead of leaving
// MarshalPrivateKey to fall back to its own package-level pkcs8.DefaultOpts.
// It is the single shared options value for this backend and
// pkg/keyprovider/pkcs8; the two package-level duplicates that used to exist
// were consolidated here (go-xkms#1286) since a divergence between them
// would give one caller a weaker iteration count than the other with no
// signal that they had drifted.
//
// DefaultOpts.KDFOpts.SaltSize is 8 bytes (64 bits). Go's crypto/pbkdf2
// refuses any salt under 128 bits under GODEBUG=fips140=only, and it refuses
// by panicking (golang.org/x/crypto/pbkdf2.Key converts the stdlib's error
// return into a panic) -- a wrong-salt-size call otherwise crashes the
// process instead of returning an error. The cipher is carried over
// unchanged from DefaultOpts; the salt grows to the FIPS floor and the
// iteration count to pbkdf2IterationCount.
var PKCS8EncryptOpts = &pkcs8.Opts{
	Cipher: pkcs8.AES256CBC,
	KDFOpts: pkcs8.PBKDF2Opts{
		SaltSize:       16,
		IterationCount: pbkdf2IterationCount,
		HMACHash:       crypto.SHA256,
	},
}

// EncodePKCS8 encodes a private key to ASN.1 DER PKCS#8 format.
// If a password is provided, the key will be encrypted.
// If password is nil or empty, the key will be encoded without encryption.
//
// Supported key types: *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey
//
// Example:
//
//	der, err := encoding.EncodePKCS8(privateKey, []byte("mypassword"))
func EncodePKCS8(privateKey crypto.PrivateKey, password []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}

	// Use youmark/pkcs8 package which handles encryption
	der, err := pkcs8.MarshalPrivateKey(privateKey, password, PKCS8EncryptOpts)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal PKCS#8", Err: err}
	}

	return der, nil
}

// DecodePKCS8 decodes ASN.1 DER PKCS#8 encoded data to a private key.
// If the data is encrypted, a password must be provided.
// If password is nil or empty and the data is encrypted, this will return ErrPasswordRequired.
//
// Returns the private key as crypto.PrivateKey (type assert to specific type if needed).
//
// Example:
//
//	key, err := encoding.DecodePKCS8(derData, []byte("mypassword"))
//	rsaKey := key.(*rsa.PrivateKey)
func DecodePKCS8(data []byte, password []byte) (crypto.PrivateKey, error) {
	if len(data) == 0 {
		return nil, ErrInvalidData
	}

	// Parse the PKCS#8 data
	key, err := pkcs8.ParsePKCS8PrivateKey(data, password)
	if err != nil {
		// Check for common error cases
		if isPasswordError(err) {
			return nil, ErrInvalidPassword
		}
		return nil, &errs.Wrapped{Msg: "failed to parse PKCS#8", Err: err}
	}

	// Type assertion - pkcs8 returns interface{}
	privKey, ok := key.(crypto.PrivateKey)
	if !ok {
		return nil, ErrInvalidPrivateKey
	}

	return privKey, nil
}

// EncodePublicKeyPKIX encodes a public key to ASN.1 DER PKIX format.
// This is the standard format for public keys (SubjectPublicKeyInfo).
//
// Supported key types: *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
//
// Example:
//
//	der, err := encoding.EncodePublicKeyPKIX(publicKey)
func EncodePublicKeyPKIX(publicKey crypto.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to marshal PKIX public key", Err: err}
	}

	return der, nil
}

// DecodePublicKeyPKIX decodes ASN.1 DER PKIX encoded data to a public key.
//
// Returns the public key as crypto.PublicKey (type assert to specific type if needed).
//
// Example:
//
//	key, err := encoding.DecodePublicKeyPKIX(derData)
//	rsaPub := key.(*rsa.PublicKey)
func DecodePublicKeyPKIX(data []byte) (crypto.PublicKey, error) {
	if len(data) == 0 {
		return nil, ErrInvalidData
	}

	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to parse PKIX public key", Err: err}
	}

	return pubKey, nil
}

// isPasswordError checks if an error is related to incorrect password.
// The pkcs8 package returns various error messages for password issues.
func isPasswordError(err error) bool {
	if err == nil {
		return false
	}

	errMsg := err.Error()

	// Common password-related error messages from youmark/pkcs8
	passwordErrors := []string{
		"pkcs8: incorrect password",
		"incorrect password",
		"asn1: structure error",
		"tags don't match",
	}

	for _, msg := range passwordErrors {
		if contains(errMsg, msg) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring (case-sensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			indexOf(s, substr) >= 0)
}

// indexOf returns the index of substr in s, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

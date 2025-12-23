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

package types

import (
	"crypto/x509"
	"strings"
)

// =============================================================================
// Key Algorithm String Constants
// =============================================================================
// These string constants match Go standard library naming conventions and
// provide consistent algorithm identifiers throughout the codebase.

// KeyAlgorithmString represents asymmetric key algorithm identifiers.
// These match x509.PublicKeyAlgorithm values in string form.
type KeyAlgorithmString string

const (
	// AlgorithmRSA represents RSA public key algorithm.
	// Maps to x509.RSA.
	AlgorithmRSA KeyAlgorithmString = "RSA"

	// AlgorithmECDSA represents ECDSA public key algorithm.
	// Maps to x509.ECDSA.
	AlgorithmECDSA KeyAlgorithmString = "ECDSA"

	// AlgorithmEd25519 represents Ed25519 public key algorithm.
	// Maps to x509.Ed25519.
	AlgorithmEd25519 KeyAlgorithmString = "Ed25519"

	// AlgorithmDSA represents DSA public key algorithm (legacy).
	// Maps to x509.DSA.
	AlgorithmDSA KeyAlgorithmString = "DSA"

	// AlgorithmSymmetric represents symmetric key algorithms.
	AlgorithmSymmetric KeyAlgorithmString = "Symmetric"

	// AlgorithmAES represents AES symmetric encryption.
	AlgorithmAES KeyAlgorithmString = "AES"
)

// String returns the string representation.
func (a KeyAlgorithmString) String() string {
	return string(a)
}

// Lower returns the lowercase form of the algorithm string.
func (a KeyAlgorithmString) Lower() string {
	return strings.ToLower(string(a))
}

// Equals performs case-insensitive comparison for protocol compatibility.
func (a KeyAlgorithmString) Equals(s string) bool {
	return strings.EqualFold(string(a), s)
}

// ToX509 converts the KeyAlgorithmString to x509.PublicKeyAlgorithm.
func (a KeyAlgorithmString) ToX509() x509.PublicKeyAlgorithm {
	switch KeyAlgorithmString(strings.ToUpper(string(a))) {
	case AlgorithmRSA:
		return x509.RSA
	case AlgorithmECDSA:
		return x509.ECDSA
	case AlgorithmEd25519:
		return x509.Ed25519
	case AlgorithmDSA:
		return x509.DSA
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
}

// =============================================================================
// Curve Name Constants
// =============================================================================
// Curve names follow NIST naming conventions (P-256, P-384, P-521).

// EllipticCurve represents elliptic curve identifiers.
type EllipticCurve string

const (
	// CurveP224 is NIST P-224 curve (secp224r1).
	CurveP224 EllipticCurve = "P-224"

	// CurveP256 is NIST P-256 curve (secp256r1, prime256v1).
	// This is the most commonly used curve for ECDSA.
	CurveP256 EllipticCurve = "P-256"

	// CurveP384 is NIST P-384 curve (secp384r1).
	CurveP384 EllipticCurve = "P-384"

	// CurveP521 is NIST P-521 curve (secp521r1).
	CurveP521 EllipticCurve = "P-521"

	// CurveSecp256k1 is the secp256k1 curve used in Bitcoin/Ethereum.
	CurveSecp256k1 EllipticCurve = "secp256k1"

	// CurveX25519 is Curve25519 for key agreement (X25519).
	CurveX25519 EllipticCurve = "X25519"

	// CurveEd25519 is the Edwards curve used for Ed25519 signatures.
	CurveEd25519 EllipticCurve = "Ed25519"
)

// String returns the string representation.
func (c EllipticCurve) String() string {
	return string(c)
}

// Lower returns the lowercase form of the curve name.
func (c EllipticCurve) Lower() string {
	return strings.ToLower(string(c))
}

// Equals performs case-insensitive comparison for protocol compatibility.
func (c EllipticCurve) Equals(s string) bool {
	return strings.EqualFold(string(c), s)
}

// =============================================================================
// Hash Algorithm String Constants
// =============================================================================
// Hash names follow the standard library crypto.Hash naming with dashes.

// HashName represents hash algorithm identifiers.
type HashName string

const (
	// HashMD4 is MD4 (legacy, insecure).
	HashMD4 HashName = "MD4"

	// HashMD5 is MD5 (legacy, insecure).
	HashMD5 HashName = "MD5"

	// HashSHA1 is SHA-1 (legacy, use SHA-256+ for new applications).
	HashSHA1 HashName = "SHA-1"

	// HashSHA224 is SHA-224.
	HashSHA224 HashName = "SHA-224"

	// HashSHA256 is SHA-256 (recommended minimum).
	HashSHA256 HashName = "SHA-256"

	// HashSHA384 is SHA-384.
	HashSHA384 HashName = "SHA-384"

	// HashSHA512 is SHA-512.
	HashSHA512 HashName = "SHA-512"

	// HashSHA512_224 is SHA-512/224.
	HashSHA512_224 HashName = "SHA-512/224"

	// HashSHA512_256 is SHA-512/256.
	HashSHA512_256 HashName = "SHA-512/256"

	// HashSHA3_224 is SHA3-224.
	HashSHA3_224 HashName = "SHA3-224"

	// HashSHA3_256 is SHA3-256.
	HashSHA3_256 HashName = "SHA3-256"

	// HashSHA3_384 is SHA3-384.
	HashSHA3_384 HashName = "SHA3-384"

	// HashSHA3_512 is SHA3-512.
	HashSHA3_512 HashName = "SHA3-512"

	// HashBLAKE2s_256 is BLAKE2s-256.
	HashBLAKE2s_256 HashName = "BLAKE2s-256"

	// HashBLAKE2b_256 is BLAKE2b-256.
	HashBLAKE2b_256 HashName = "BLAKE2b-256"

	// HashBLAKE2b_384 is BLAKE2b-384.
	HashBLAKE2b_384 HashName = "BLAKE2b-384"

	// HashBLAKE2b_512 is BLAKE2b-512.
	HashBLAKE2b_512 HashName = "BLAKE2b-512"
)

// String returns the string representation.
func (h HashName) String() string {
	return string(h)
}

// Lower returns the lowercase form of the hash name.
func (h HashName) Lower() string {
	return strings.ToLower(string(h))
}

// Equals performs case-insensitive comparison for protocol compatibility.
func (h HashName) Equals(s string) bool {
	return strings.EqualFold(string(h), s)
}

// =============================================================================
// Signature Algorithm String Constants
// =============================================================================
// Signature algorithm names follow x509.SignatureAlgorithm naming conventions.

// SignatureAlgorithmName represents signature algorithm identifiers.
type SignatureAlgorithmName string

const (
	// SigMD2WithRSA is MD2-RSA (legacy, insecure).
	SigMD2WithRSA SignatureAlgorithmName = "MD2-RSA"

	// SigMD5WithRSA is MD5-RSA (legacy, insecure).
	SigMD5WithRSA SignatureAlgorithmName = "MD5-RSA"

	// SigSHA1WithRSA is SHA1-RSA (legacy).
	SigSHA1WithRSA SignatureAlgorithmName = "SHA1-RSA"

	// SigSHA256WithRSA is SHA256-RSA (RSASSA-PKCS1-v1_5).
	SigSHA256WithRSA SignatureAlgorithmName = "SHA256-RSA"

	// SigSHA384WithRSA is SHA384-RSA (RSASSA-PKCS1-v1_5).
	SigSHA384WithRSA SignatureAlgorithmName = "SHA384-RSA"

	// SigSHA512WithRSA is SHA512-RSA (RSASSA-PKCS1-v1_5).
	SigSHA512WithRSA SignatureAlgorithmName = "SHA512-RSA"

	// SigSHA256WithRSAPSS is SHA256-RSA-PSS (RSASSA-PSS).
	SigSHA256WithRSAPSS SignatureAlgorithmName = "SHA256-RSA-PSS"

	// SigSHA384WithRSAPSS is SHA384-RSA-PSS (RSASSA-PSS).
	SigSHA384WithRSAPSS SignatureAlgorithmName = "SHA384-RSA-PSS"

	// SigSHA512WithRSAPSS is SHA512-RSA-PSS (RSASSA-PSS).
	SigSHA512WithRSAPSS SignatureAlgorithmName = "SHA512-RSA-PSS"

	// SigDSAWithSHA1 is DSA-SHA1 (legacy).
	SigDSAWithSHA1 SignatureAlgorithmName = "DSA-SHA1"

	// SigDSAWithSHA256 is DSA-SHA256.
	SigDSAWithSHA256 SignatureAlgorithmName = "DSA-SHA256"

	// SigECDSAWithSHA1 is ECDSA-SHA1 (legacy).
	SigECDSAWithSHA1 SignatureAlgorithmName = "ECDSA-SHA1"

	// SigECDSAWithSHA256 is ECDSA-SHA256.
	SigECDSAWithSHA256 SignatureAlgorithmName = "ECDSA-SHA256"

	// SigECDSAWithSHA384 is ECDSA-SHA384.
	SigECDSAWithSHA384 SignatureAlgorithmName = "ECDSA-SHA384"

	// SigECDSAWithSHA512 is ECDSA-SHA512.
	SigECDSAWithSHA512 SignatureAlgorithmName = "ECDSA-SHA512"

	// SigEd25519 is Ed25519 (pure EdDSA, no pre-hashing).
	SigEd25519 SignatureAlgorithmName = "Ed25519"
)

// String returns the string representation.
func (s SignatureAlgorithmName) String() string {
	return string(s)
}

// Lower returns the lowercase form of the signature algorithm name.
func (s SignatureAlgorithmName) Lower() string {
	return strings.ToLower(string(s))
}

// Equals performs case-insensitive comparison for protocol compatibility.
func (s SignatureAlgorithmName) Equals(other string) bool {
	return strings.EqualFold(string(s), other)
}

// ToX509 converts to x509.SignatureAlgorithm.
func (s SignatureAlgorithmName) ToX509() x509.SignatureAlgorithm {
	switch s {
	case SigMD2WithRSA:
		return x509.MD2WithRSA
	case SigMD5WithRSA:
		return x509.MD5WithRSA
	case SigSHA1WithRSA:
		return x509.SHA1WithRSA
	case SigSHA256WithRSA:
		return x509.SHA256WithRSA
	case SigSHA384WithRSA:
		return x509.SHA384WithRSA
	case SigSHA512WithRSA:
		return x509.SHA512WithRSA
	case SigSHA256WithRSAPSS:
		return x509.SHA256WithRSAPSS
	case SigSHA384WithRSAPSS:
		return x509.SHA384WithRSAPSS
	case SigSHA512WithRSAPSS:
		return x509.SHA512WithRSAPSS
	case SigDSAWithSHA1:
		return x509.DSAWithSHA1
	case SigDSAWithSHA256:
		return x509.DSAWithSHA256
	case SigECDSAWithSHA1:
		return x509.ECDSAWithSHA1
	case SigECDSAWithSHA256:
		return x509.ECDSAWithSHA256
	case SigECDSAWithSHA384:
		return x509.ECDSAWithSHA384
	case SigECDSAWithSHA512:
		return x509.ECDSAWithSHA512
	case SigEd25519:
		return x509.PureEd25519
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// =============================================================================
// AEAD Algorithm String Constants
// =============================================================================
// AEAD (Authenticated Encryption with Associated Data) algorithm names.

// AEADAlgorithm represents AEAD algorithm identifiers.
type AEADAlgorithm string

const (
	// AEADAES128GCM is AES-128 in GCM mode.
	AEADAES128GCM AEADAlgorithm = "AES-128-GCM"

	// AEADAES192GCM is AES-192 in GCM mode.
	AEADAES192GCM AEADAlgorithm = "AES-192-GCM"

	// AEADAES256GCM is AES-256 in GCM mode (recommended).
	AEADAES256GCM AEADAlgorithm = "AES-256-GCM"

	// AEADChaCha20Poly1305 is ChaCha20 with Poly1305 MAC.
	AEADChaCha20Poly1305 AEADAlgorithm = "ChaCha20-Poly1305"

	// AEADXChaCha20Poly1305 is XChaCha20 with Poly1305 MAC (extended nonce).
	AEADXChaCha20Poly1305 AEADAlgorithm = "XChaCha20-Poly1305"
)

// String returns the string representation.
func (a AEADAlgorithm) String() string {
	return string(a)
}

// Lower returns the lowercase form of the AEAD algorithm name.
func (a AEADAlgorithm) Lower() string {
	return strings.ToLower(string(a))
}

// Equals performs case-insensitive comparison for protocol compatibility.
func (a AEADAlgorithm) Equals(s string) bool {
	return strings.EqualFold(string(a), s)
}

// ToSymmetricAlgorithm converts to SymmetricAlgorithm (internal format).
func (a AEADAlgorithm) ToSymmetricAlgorithm() SymmetricAlgorithm {
	switch a {
	case AEADAES128GCM:
		return SymmetricAES128GCM
	case AEADAES192GCM:
		return SymmetricAES192GCM
	case AEADAES256GCM:
		return SymmetricAES256GCM
	case AEADChaCha20Poly1305:
		return SymmetricChaCha20Poly1305
	case AEADXChaCha20Poly1305:
		return SymmetricXChaCha20Poly1305
	default:
		return ""
	}
}

// =============================================================================
// Key Wrapping Algorithm Constants
// =============================================================================
// Key wrapping algorithms for import/export operations.

// KeyWrapAlgorithm represents key wrapping algorithm identifiers.
type KeyWrapAlgorithm string

const (
	// WrapRSAOAEPSHA1 is RSA-OAEP with SHA-1 (legacy).
	WrapRSAOAEPSHA1 KeyWrapAlgorithm = "RSAES_OAEP_SHA_1"

	// WrapRSAOAEPSHA256 is RSA-OAEP with SHA-256 (recommended).
	WrapRSAOAEPSHA256 KeyWrapAlgorithm = "RSAES_OAEP_SHA_256"

	// WrapRSAAESKWSHA1 is RSA-AES-KEY-WRAP with SHA-1 (legacy).
	WrapRSAAESKWSHA1 KeyWrapAlgorithm = "RSA_AES_KEY_WRAP_SHA_1"

	// WrapRSAAESKWSHA256 is RSA-AES-KEY-WRAP with SHA-256.
	WrapRSAAESKWSHA256 KeyWrapAlgorithm = "RSA_AES_KEY_WRAP_SHA_256"

	// WrapAESKWP is AES Key Wrap with Padding (RFC 5649).
	WrapAESKWP KeyWrapAlgorithm = "AES_KWP"

	// WrapAES128KWP is AES-128 Key Wrap with Padding.
	WrapAES128KWP KeyWrapAlgorithm = "AES_128_KWP"

	// WrapAES256KWP is AES-256 Key Wrap with Padding.
	WrapAES256KWP KeyWrapAlgorithm = "AES_256_KWP"
)

// String returns the string representation.
func (w KeyWrapAlgorithm) String() string {
	return string(w)
}

// Lower returns the lowercase form of the key wrap algorithm name.
func (w KeyWrapAlgorithm) Lower() string {
	return strings.ToLower(string(w))
}

// Equals performs case-insensitive comparison for protocol compatibility.
func (w KeyWrapAlgorithm) Equals(s string) bool {
	return strings.EqualFold(string(w), s)
}

// =============================================================================
// CLI Key Type Constants
// =============================================================================
// Key type identifiers used in CLI commands and API requests.

// CLIKeyType represents key type identifiers for CLI operations.
type CLIKeyType string

const (
	// CLIKeyTypeTLS is for TLS certificate keys.
	CLIKeyTypeTLS CLIKeyType = "tls"

	// CLIKeyTypeSigning is for digital signature keys.
	CLIKeyTypeSigning CLIKeyType = "signing"

	// CLIKeyTypeEncryption is for asymmetric encryption keys.
	CLIKeyTypeEncryption CLIKeyType = "encryption"

	// CLIKeyTypeAES is for AES symmetric encryption keys.
	CLIKeyTypeAES CLIKeyType = "aes"

	// CLIKeyTypeHMAC is for HMAC keys.
	CLIKeyTypeHMAC CLIKeyType = "hmac"

	// CLIKeyTypeSecret is for generic secret keys.
	CLIKeyTypeSecret CLIKeyType = "secret"
)

// String returns the string representation.
func (k CLIKeyType) String() string {
	return string(k)
}

// Lower returns the lowercase form of the CLI key type.
func (k CLIKeyType) Lower() string {
	return strings.ToLower(string(k))
}

// Equals performs case-insensitive comparison for protocol compatibility.
func (k CLIKeyType) Equals(s string) bool {
	return strings.EqualFold(string(k), s)
}

// ToKeyType converts CLI key type to internal KeyType.
func (k CLIKeyType) ToKeyType() KeyType {
	switch k {
	case CLIKeyTypeTLS:
		return KeyTypeTLS
	case CLIKeyTypeSigning:
		return KeyTypeSigning
	case CLIKeyTypeEncryption:
		return KeyTypeEncryption
	case CLIKeyTypeAES:
		return KeyTypeSecret
	case CLIKeyTypeHMAC:
		return KeyTypeHMAC
	case CLIKeyTypeSecret:
		return KeyTypeSecret
	default:
		return 0
	}
}

// =============================================================================
// RSA Key Size Constants
// =============================================================================
// Standard RSA key sizes.

const (
	// RSAKeySize2048 is 2048-bit RSA (minimum recommended).
	RSAKeySize2048 = 2048

	// RSAKeySize3072 is 3072-bit RSA (recommended for longer security).
	RSAKeySize3072 = 3072

	// RSAKeySize4096 is 4096-bit RSA (high security).
	RSAKeySize4096 = 4096
)

// =============================================================================
// AES Key Size Constants
// =============================================================================
// Standard AES key sizes in bits.

const (
	// AESKeySize128 is 128-bit AES.
	AESKeySize128 = 128

	// AESKeySize192 is 192-bit AES.
	AESKeySize192 = 192

	// AESKeySize256 is 256-bit AES (recommended).
	AESKeySize256 = 256
)

// =============================================================================
// Algorithm Parsing Helpers
// =============================================================================

// ParseAEADAlgorithm converts a string to AEADAlgorithm.
func ParseAEADAlgorithm(s string) AEADAlgorithm {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "-")

	switch s {
	case "aes-128-gcm", "aes128-gcm", "aes128gcm":
		return AEADAES128GCM
	case "aes-192-gcm", "aes192-gcm", "aes192gcm":
		return AEADAES192GCM
	case "aes-256-gcm", "aes256-gcm", "aes256gcm":
		return AEADAES256GCM
	case "chacha20-poly1305", "chacha20poly1305":
		return AEADChaCha20Poly1305
	case "xchacha20-poly1305", "xchacha20poly1305":
		return AEADXChaCha20Poly1305
	default:
		return ""
	}
}

// ParseCLIKeyType converts a string to CLIKeyType.
func ParseCLIKeyType(s string) CLIKeyType {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "tls":
		return CLIKeyTypeTLS
	case "signing":
		return CLIKeyTypeSigning
	case "encryption":
		return CLIKeyTypeEncryption
	case "aes":
		return CLIKeyTypeAES
	case "hmac":
		return CLIKeyTypeHMAC
	case "secret":
		return CLIKeyTypeSecret
	default:
		return ""
	}
}

// ParseKeyAlgorithmString converts a string to KeyAlgorithmString.
func ParseKeyAlgorithmString(s string) KeyAlgorithmString {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "rsa":
		return AlgorithmRSA
	case "ecdsa", "ec", "ecc":
		return AlgorithmECDSA
	case "ed25519":
		return AlgorithmEd25519
	case "dsa":
		return AlgorithmDSA
	default:
		return ""
	}
}

// ParseEllipticCurve converts a string to EllipticCurve.
func ParseEllipticCurve(s string) EllipticCurve {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "P-224", "P224", "SECP224R1":
		return CurveP224
	case "P-256", "P256", "SECP256R1", "PRIME256V1":
		return CurveP256
	case "P-384", "P384", "SECP384R1":
		return CurveP384
	case "P-521", "P521", "SECP521R1":
		return CurveP521
	case "SECP256K1":
		return CurveSecp256k1
	case "X25519":
		return CurveX25519
	case "ED25519":
		return CurveEd25519
	default:
		return ""
	}
}

// ParseHashName converts a string to HashName.
func ParseHashName(s string) HashName {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "-")

	switch s {
	case "MD4":
		return HashMD4
	case "MD5":
		return HashMD5
	case "SHA-1", "SHA1":
		return HashSHA1
	case "SHA-224", "SHA224":
		return HashSHA224
	case "SHA-256", "SHA256":
		return HashSHA256
	case "SHA-384", "SHA384":
		return HashSHA384
	case "SHA-512", "SHA512":
		return HashSHA512
	case "SHA-512/224", "SHA512-224":
		return HashSHA512_224
	case "SHA-512/256", "SHA512-256":
		return HashSHA512_256
	case "SHA3-224":
		return HashSHA3_224
	case "SHA3-256":
		return HashSHA3_256
	case "SHA3-384":
		return HashSHA3_384
	case "SHA3-512":
		return HashSHA3_512
	case "BLAKE2S-256":
		return HashBLAKE2s_256
	case "BLAKE2B-256":
		return HashBLAKE2b_256
	case "BLAKE2B-384":
		return HashBLAKE2b_384
	case "BLAKE2B-512":
		return HashBLAKE2b_512
	default:
		return ""
	}
}

// IsValidAEADAlgorithm returns true if the string is a valid AEAD algorithm.
func IsValidAEADAlgorithm(s string) bool {
	return ParseAEADAlgorithm(s) != ""
}

// IsValidCLIKeyType returns true if the string is a valid CLI key type.
func IsValidCLIKeyType(s string) bool {
	return ParseCLIKeyType(s) != ""
}

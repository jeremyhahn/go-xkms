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

package backend

import (
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// This file provides convenience re-exports of types from pkg/types to the backend package.
// This prevents import cycles and provides an ergonomic API where backend implementations
// can use backend.KeyAttributes instead of importing types separately.
//
// These are type aliases, not duplicated code, and are the standard Go pattern for
// organizing packages with cyclic dependencies.

// Type re-exports
type (
	// KeyType represents the type of cryptographic key.
	KeyType = types.KeyType

	// StoreType represents the backend storage type for keys.
	StoreType = types.StoreType

	// KeyAttributes contains metadata about a cryptographic key.
	KeyAttributes = types.KeyAttributes

	// Partition represents a logical storage partition for organizing keys.
	Partition = types.Partition

	// FSExtension represents file extension types.
	FSExtension = types.FSExtension

	// BackendType identifies the type of cryptographic backend.
	BackendType = types.BackendType

	// SymmetricAlgorithm represents symmetric encryption algorithms.
	SymmetricAlgorithm = types.SymmetricAlgorithm
)

// KeyType constant re-exports
const (
	KEY_TYPE_ATTESTATION = types.KeyTypeAttestation
	KEY_TYPE_CA          = types.KeyTypeCA
	KEY_TYPE_ENCRYPTION  = types.KeyTypeEncryption
	KEY_TYPE_ENDORSEMENT = types.KeyTypeEndorsement
	KEY_TYPE_HMAC        = types.KeyTypeHMAC
	KEY_TYPE_IDEVID      = types.KeyTypeIDevID
	KEY_TYPE_TPM         = types.KeyTypeTPM
	KEY_TYPE_SECRET      = types.KeyTypeSecret
	KEY_TYPE_SIGNING     = types.KeyTypeSigning
	KEY_TYPE_STORAGE     = types.KeyTypeStorage
	KEY_TYPE_TLS         = types.KeyTypeTLS
)

// StoreType constant re-exports
const (
	// STORE_SW is an alias for software-based key storage
	STORE_SW      = types.StoreSoftware
	STORE_TPM2    = types.StoreTPM2
	STORE_PKCS11  = types.StorePKCS11
	STORE_AWSKMS  = types.StoreAWSKMS
	STORE_GCPKMS  = types.StoreGCPKMS
	STORE_AZUREKV = types.StoreAzureKV
	STORE_VAULT   = types.StoreVault
)

// BackendType constant re-exports
const (
	BackendTypeSymmetric    = types.BackendTypeSymmetric
	BackendTypeSoftware     = types.BackendTypeSoftware
	BackendTypePKCS11       = types.BackendTypePKCS11
	BackendTypeSmartCardHSM = types.BackendTypeSmartCardHSM
	BackendTypeTPM2         = types.BackendTypeTPM2
	BackendTypeAWSKMS       = types.BackendTypeAWSKMS
	BackendTypeGCPKMS       = types.BackendTypeGCPKMS
	BackendTypeAzureKV      = types.BackendTypeAzureKV
	BackendTypeVault        = types.BackendTypeVault
)

// FSExtension constant re-exports
const (
	FSEXT_PRIVATE_PKCS8     = types.FSExtPrivatePKCS8
	FSEXT_PRIVATE_PKCS8_PEM = types.FSExtPrivatePKCS8PEM
	FSEXT_PUBLIC_PKCS1      = types.FSExtPublicPKCS1
	FSEXT_PUBLIC_PEM        = types.FSExtPublicPEM
	FSEXT_PRIVATE_BLOB      = types.FSExtPrivateBlob
	FSEXT_PUBLIC_BLOB       = types.FSExtPublicBlob
	FSEXT_SIGNATURE         = types.FSExtSignature
	FSEXT_DIGEST            = types.FSExtDigest
)

// Partition constant re-exports
const (
	PARTITION_ROOT            = types.PartitionRoot
	PARTITION_TLS             = types.PartitionTLS
	PARTITION_HMAC            = types.PartitionHMAC
	PARTITION_SECRETS         = types.PartitionSecrets
	PARTITION_ENCRYPTION_KEYS = types.PartitionEncryptionKeys
	PARTITION_SIGNING_KEYS    = types.PartitionSigningKeys
)

// Algorithm type re-exports from pkg/types/algorithms.go
type (
	// KeyAlgorithmString represents asymmetric key algorithm identifiers.
	KeyAlgorithmString = types.KeyAlgorithmString

	// EllipticCurve represents elliptic curve identifiers.
	EllipticCurve = types.EllipticCurve

	// HashName represents hash algorithm identifiers.
	HashName = types.HashName

	// SignatureAlgorithmName represents signature algorithm identifiers.
	SignatureAlgorithmName = types.SignatureAlgorithmName

	// AEADAlgorithm represents AEAD algorithm identifiers.
	AEADAlgorithm = types.AEADAlgorithm

	// KeyWrapAlgorithm represents key wrapping algorithm identifiers.
	KeyWrapAlgorithm = types.KeyWrapAlgorithm

	// CLIKeyType represents key type identifiers for CLI operations.
	CLIKeyType = types.CLIKeyType
)

// Algorithm string constants re-exports
const (
	// Asymmetric key algorithms
	AlgorithmRSA     = types.AlgorithmRSA
	AlgorithmECDSA   = types.AlgorithmECDSA
	AlgorithmEd25519 = types.AlgorithmEd25519

	// Elliptic curves
	CurveP224      = types.CurveP224
	CurveP256      = types.CurveP256
	CurveP384      = types.CurveP384
	CurveP521      = types.CurveP521
	CurveSecp256k1 = types.CurveSecp256k1
	CurveX25519    = types.CurveX25519

	// Hash algorithms
	HashSHA256 = types.HashSHA256
	HashSHA384 = types.HashSHA384
	HashSHA512 = types.HashSHA512

	// AEAD algorithms
	AEADAES128GCM         = types.AEADAES128GCM
	AEADAES192GCM         = types.AEADAES192GCM
	AEADAES256GCM         = types.AEADAES256GCM
	AEADChaCha20Poly1305  = types.AEADChaCha20Poly1305
	AEADXChaCha20Poly1305 = types.AEADXChaCha20Poly1305

	// Key wrapping algorithms
	WrapRSAOAEPSHA1    = types.WrapRSAOAEPSHA1
	WrapRSAOAEPSHA256  = types.WrapRSAOAEPSHA256
	WrapRSAAESKWSHA1   = types.WrapRSAAESKWSHA1
	WrapRSAAESKWSHA256 = types.WrapRSAAESKWSHA256

	// CLI key types
	CLIKeyTypeTLS        = types.CLIKeyTypeTLS
	CLIKeyTypeSigning    = types.CLIKeyTypeSigning
	CLIKeyTypeEncryption = types.CLIKeyTypeEncryption
	CLIKeyTypeAES        = types.CLIKeyTypeAES

	// Symmetric algorithm identifiers
	AlgorithmSymmetric = types.AlgorithmSymmetric
	AlgorithmAES       = types.AlgorithmAES
)

// Key size constants
const (
	RSAKeySize2048 = types.RSAKeySize2048
	RSAKeySize3072 = types.RSAKeySize3072
	RSAKeySize4096 = types.RSAKeySize4096

	AESKeySize128 = types.AESKeySize128
	AESKeySize192 = types.AESKeySize192
	AESKeySize256 = types.AESKeySize256
)

// KeyAlgorithm is a string-based algorithm type for simplified algorithm handling.
// Deprecated: Use KeyAlgorithmString or AEADAlgorithm for type-safe algorithm handling.
type KeyAlgorithm string

// KeyAlgorithm constants
// Deprecated: Use the typed constants from types.AlgorithmRSA, types.AEADAES256GCM, etc.
const (
	ALG_RSA                KeyAlgorithm = "rsa"
	ALG_ECDSA              KeyAlgorithm = "ecdsa"
	ALG_ED25519            KeyAlgorithm = "ed25519"
	ALG_AES128_GCM         KeyAlgorithm = "aes128-gcm"
	ALG_AES192_GCM         KeyAlgorithm = "aes192-gcm"
	ALG_AES256_GCM         KeyAlgorithm = "aes256-gcm"
	ALG_CHACHA20_POLY1305  KeyAlgorithm = "chacha20-poly1305"
	ALG_XCHACHA20_POLY1305 KeyAlgorithm = "xchacha20-poly1305"
)

// IsSymmetric returns true if the algorithm is a symmetric algorithm.
func (ka KeyAlgorithm) IsSymmetric() bool {
	switch ka {
	case ALG_AES128_GCM, ALG_AES192_GCM, ALG_AES256_GCM, ALG_CHACHA20_POLY1305, ALG_XCHACHA20_POLY1305:
		return true
	default:
		return false
	}
}

// IsAsymmetric returns true if the algorithm is an asymmetric algorithm.
func (ka KeyAlgorithm) IsAsymmetric() bool {
	switch ka {
	case ALG_RSA, ALG_ECDSA, ALG_ED25519:
		return true
	default:
		return false
	}
}

// String returns the string representation of the KeyAlgorithm.
func (ka KeyAlgorithm) String() string {
	return string(ka)
}

// StaticPassword is a simple password implementation for tests.
type StaticPassword string

func (p StaticPassword) Bytes() []byte {
	return []byte(p)
}

func (p StaticPassword) String() (string, error) {
	return string(p), nil
}

func (p StaticPassword) Clear() {
	// Strings are immutable in Go, can't clear
}

// NoPassword is an empty password implementation for tests.
type NoPassword struct{}

func (p NoPassword) Bytes() []byte {
	return nil
}

func (p NoPassword) String() (string, error) {
	return "", nil
}

func (p NoPassword) Clear() {
	// Nothing to clear
}

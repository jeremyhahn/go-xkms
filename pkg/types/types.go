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

// Package types re-exports shared type definitions from go-common/pki for backward compatibility.
// All core PKI types (KeyAttributes, Backend, Password, etc.) are now provided by go-common/pki,
// which serves as the single source of truth to avoid circular dependencies between projects.
//
// This package also contains go-keychain-specific types like FSExtension and Partition that are
// not part of the shared PKI abstractions.
package types

import (
	"github.com/jeremyhahn/go-common/pki"
)

// =============================================================================
// Re-exported types from go-common/pki
// =============================================================================
//
// These types are the authoritative definitions from go-common/pki.
// go-keychain re-exports them for backward compatibility so existing code
// can continue to use types.KeyAttributes, types.Backend, etc.

// Core types
type KeyAttributes = pki.KeyAttributes
type Password = pki.Password

// Store and key types
type StoreType = pki.StoreType
type KeyType = pki.KeyType

// Algorithm-specific attributes
type RSAAttributes = pki.RSAAttributes
type ECCAttributes = pki.ECCAttributes
type X25519Attributes = pki.X25519Attributes
type AESAttributes = pki.AESAttributes
type QuantumAttributes = pki.QuantumAttributes
type QuantumAlgorithm = pki.QuantumAlgorithm
type ThresholdAttributes = pki.ThresholdAttributes
type ThresholdAlgorithm = pki.ThresholdAlgorithm
type TPMAttributes = pki.TPMAttributes

// Symmetric encryption types
type SymmetricAlgorithm = pki.SymmetricAlgorithm
type SymmetricKey = pki.SymmetricKey
type SymmetricEncrypter = pki.SymmetricEncrypter
type EncryptOptions = pki.EncryptOptions
type DecryptOptions = pki.DecryptOptions
type EncryptedData = pki.EncryptedData
type AEADOptions = pki.AEADOptions
type AEADSafetyTracker = pki.AEADSafetyTracker

// Backend interfaces
type Backend = pki.Backend
type BackendType = pki.BackendType
type Capabilities = pki.Capabilities
type AttestingBackend = pki.AttestingBackend
type SymmetricBackend = pki.SymmetricBackend
type SymmetricBackendWithTracking = pki.SymmetricBackendWithTracking
type KeyAgreement = pki.KeyAgreement
type ECIESEncrypter = pki.ECIESEncrypter
type ECIESDecrypter = pki.ECIESDecrypter

// Re-export constants from pki

// Store type constants
const (
	StorePKCS8   = pki.StorePKCS8
	StorePKCS11  = pki.StorePKCS11
	StoreTPM2    = pki.StoreTPM2
	StoreAWSKMS  = pki.StoreAWSKMS
	StoreGCPKMS  = pki.StoreGCPKMS
	StoreAzureKV = pki.StoreAzureKV
	StoreVault   = pki.StoreVault
	StoreQuantum = pki.StoreQuantum
	StoreUnknown = pki.StoreUnknown
)

// go-keychain-specific store type
const (
	StoreThreshold StoreType = "threshold"
)

// Backend type constants
const (
	BackendTypeAES          = pki.BackendTypeAES
	BackendTypePKCS8        = pki.BackendTypePKCS8
	BackendTypeSoftware     = pki.BackendTypeSoftware
	BackendTypePKCS11       = pki.BackendTypePKCS11
	BackendTypeSmartCardHSM = pki.BackendTypeSmartCardHSM
	BackendTypeTPM2         = pki.BackendTypeTPM2
	BackendTypeAWSKMS       = pki.BackendTypeAWSKMS
	BackendTypeGCPKMS       = pki.BackendTypeGCPKMS
	BackendTypeAzureKV      = pki.BackendTypeAzureKV
	BackendTypeVault        = pki.BackendTypeVault
	BackendTypeQuantum      = pki.BackendTypeQuantum
	BackendTypeThreshold    = pki.BackendTypeThreshold
)

// Key type constants
const (
	KeyTypeAttestation = pki.KeyTypeAttestation
	KeyTypeCA          = pki.KeyTypeCA
	KeyTypeEncryption  = pki.KeyTypeEncryption
	KeyTypeEndorsement = pki.KeyTypeEndorsement
	KeyTypeHMAC        = pki.KeyTypeHMAC
	KeyTypeIDevID      = pki.KeyTypeIDevID
	KeyTypeLDevID      = pki.KeyTypeLDevID
	KeyTypeSecret      = pki.KeyTypeSecret
	KeyTypeSigning     = pki.KeyTypeSigning
	KeyTypeStorage     = pki.KeyTypeStorage
	KeyTypeTLS         = pki.KeyTypeTLS
	KeyTypeTPM         = pki.KeyTypeTPM
)

// Symmetric algorithm constants
const (
	SymmetricAES128GCM         = pki.SymmetricAES128GCM
	SymmetricAES192GCM         = pki.SymmetricAES192GCM
	SymmetricAES256GCM         = pki.SymmetricAES256GCM
	SymmetricChaCha20Poly1305  = pki.SymmetricChaCha20Poly1305
	SymmetricXChaCha20Poly1305 = pki.SymmetricXChaCha20Poly1305
)

// Quantum algorithm constants
const (
	QuantumAlgorithmMLDSA44   = pki.QuantumAlgorithmMLDSA44
	QuantumAlgorithmMLDSA65   = pki.QuantumAlgorithmMLDSA65
	QuantumAlgorithmMLDSA87   = pki.QuantumAlgorithmMLDSA87
	QuantumAlgorithmMLKEM512  = pki.QuantumAlgorithmMLKEM512
	QuantumAlgorithmMLKEM768  = pki.QuantumAlgorithmMLKEM768
	QuantumAlgorithmMLKEM1024 = pki.QuantumAlgorithmMLKEM1024
)

// Threshold algorithm constants
const (
	ThresholdAlgorithmShamir = pki.ThresholdAlgorithmShamir
)

// Re-export helper functions from pki
var (
	DefaultAEADOptions                 = pki.DefaultAEADOptions
	NewSoftwareCapabilities            = pki.NewSoftwareCapabilities
	NewHardwareCapabilities            = pki.NewHardwareCapabilities
	NewUnifiedSoftwareCapabilities     = pki.NewUnifiedSoftwareCapabilities
	AvailableHashes                    = pki.AvailableHashes
	AvailableSignatureAlgorithms       = pki.AvailableSignatureAlgorithms
	SignatureAlgorithmHashes           = pki.SignatureAlgorithmHashes
	AvailableKeyAlgorithms             = pki.AvailableKeyAlgorithms
	IsRSAPSS                           = pki.IsRSAPSS
	IsECDSA                            = pki.IsECDSA
	KeyAlgorithmFromSignatureAlgorithm = pki.KeyAlgorithmFromSignatureAlgorithm
	FSHashName                         = pki.FSHashName
	FSExtKeyAlgorithm                  = pki.FSExtKeyAlgorithm
	KeyFileExtension                   = pki.KeyFileExtension
	HashFileExtension                  = pki.HashFileExtension
	Digest                             = pki.Digest
	ParseCurve                         = pki.ParseCurve
	ParseKeyAlgorithm                  = pki.ParseKeyAlgorithm
	ParseKeyType                       = pki.ParseKeyType
	ParseHash                          = pki.ParseHash
	ParseStoreType                     = pki.ParseStoreType
	CurveName                          = pki.CurveName
)

// =============================================================================
// go-keychain-specific types (not in go-common/pki)
// =============================================================================

// FSExtension represents file extension types used by the keychain
// file backend for storing cryptographic material.
type FSExtension = pki.FSExtension

// File extension constants for various key storage formats
const (
	FSExtBlob            = pki.FSExtBlob
	FSExtPrivatePKCS8    = pki.FSExtPrivatePKCS8
	FSExtPrivatePKCS8PEM = pki.FSExtPrivatePKCS8PEM
	FSExtPublicPKCS1     = pki.FSExtPublicPKCS1
	FSExtPublicPEM       = pki.FSExtPublicPEM
	FSExtPrivateBlob     = pki.FSExtPrivateBlob
	FSExtPublicBlob      = pki.FSExtPublicBlob
	FSExtDigest          = pki.FSExtDigest
	FSExtSignature       = pki.FSExtSignature
)

// Partition represents logical storage partitions within the keychain
// for organizing keys by their purpose.
type Partition = pki.Partition

// Partition constants for organizing keys by type
const (
	PartitionRoot           = pki.PartitionRoot
	PartitionTLS            = pki.PartitionTLS
	PartitionEncryptionKeys = pki.PartitionEncryptionKeys
	PartitionSigningKeys    = pki.PartitionSigningKeys
	PartitionHMAC           = pki.PartitionHMAC
	PartitionSecrets        = pki.PartitionSecrets
)

// Partitions is a list of all available partitions for iteration.
var Partitions = pki.Partitions

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

//go:build tpm2

// Package tpm2 provides a TPM 2.0 backend implementation for the keychain.
// It integrates with Trusted Platform Module 2.0 hardware or simulators to provide
// hardware-backed cryptographic key storage and operations.
//
// Key features:
//   - Storage Root Key (SRK) hierarchy under Endorsement Key
//   - RSA key support (2048, 3072, 4096 bits)
//   - ECDSA key support (P-256, P-384, P-521)
//   - TPM-native signing without private key export
//   - Password sealing using TPM keyed hash objects
//   - Platform PCR policy for measured boot integration
//   - Thread-safe concurrent operations
//
// Architecture:
//   - Private keys never leave the TPM
//   - Keys stored as TPM blobs (public + encrypted private)
//   - SRK is persistent at configured handle
//   - Application keys are transient, loaded on-demand
//
// Note: Ed25519 is not supported by TPM 2.0 and will return ErrUnsupportedKeyAlgorithm.
package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/tcp"

	kbackend "github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/opaque"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TPM2KeyStore implements keychain.KeyStore using TPM 2.0 for hardware-backed
// key storage and cryptographic operations.
//
// The keystore maintains a hierarchical key structure:
//   - Endorsement Key (EK) - TPM vendor-provisioned root
//   - Storage Root Key (SRK) - Application-specific root under EK
//   - Application Keys - Child keys under SRK
//
// All operations are thread-safe and can be called concurrently.
//
// Note: Application keys are transient handles loaded on-demand and flushed
// after each operation to prevent TPM resource exhaustion.
type TPM2KeyStore struct {
	config      *Config
	backend     types.Backend
	keyStorage  storage.Backend
	certStorage storage.Backend
	tpm         transport.TPMCloser
	srkHandle   tpm2.TPMHandle
	srkName     tpm2.TPM2BName // Cryptographic name of the SRK
	tracker     types.AEADSafetyTracker
	mu          sync.RWMutex
	closed      bool
}

// TPM returns the internal TPM transport for testing/debugging
func (ks *TPM2KeyStore) TPM() transport.TPMCloser {
	return ks.tpm
}

// NewTPM2KeyStore creates a new TPM 2.0 keystore instance.
//
// The function validates the configuration and optionally accepts a pre-opened TPM transport.
// It does NOT initialize the SRK - call Initialize() for first-time setup.
//
// Parameters:
//   - config: TPM configuration including device path and SRK handle
//   - backend: Storage backend for TPM key blobs (can be nil, TPM2KeyStore will use itself)
//   - keyStorage: Key storage for TPM key blobs (public/private)
//   - certStorage: Certificate storage backend for managing certificates
//   - tpmTransport: Optional pre-opened TPM transport (for testing/dependency injection). If nil, Initialize() will open the TPM.
//
// Returns an error if:
//   - config, keyStorage, or certStorage is nil
//   - config validation fails
func NewTPM2KeyStore(config *Config, backend types.Backend, keyStorage storage.Backend, certStorage storage.Backend, tpmTransport transport.TPMCloser) (*TPM2KeyStore, error) {
	if config == nil {
		return nil, errors.New("tpm2: config cannot be nil")
	}

	if keyStorage == nil {
		return nil, errors.New("tpm2: keyStorage cannot be nil")
	}

	if certStorage == nil {
		return nil, keychain.ErrCertStorageRequired
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("tpm2: invalid configuration: %w", err)
	}

	// Initialize AEAD tracker
	tracker := config.Tracker
	if tracker == nil {
		tracker = kbackend.NewMemoryAEADTracker()
	}

	ks := &TPM2KeyStore{
		config:      config,
		backend:     backend, // Can be nil - backend field is only used by Backend() accessor
		keyStorage:  keyStorage,
		certStorage: certStorage,
		srkHandle:   tpm2.TPMHandle(config.SRKHandle),
		tpm:         tpmTransport, // Optional pre-opened transport
		tracker:     tracker,
	}

	return ks, nil
}

// Type returns the store type identifier for TPM 2.0.
func (ks *TPM2KeyStore) Type() types.BackendType {
	return kbackend.BackendTypeTPM2
}

// Capabilities returns what features this TPM2 backend supports.
func (ks *TPM2KeyStore) Capabilities() types.Capabilities {
	return types.Capabilities{
		Keys:                true, // TPM supports key generation and storage
		HardwareBacked:      true, // Keys are hardware-backed in TPM
		Signing:             true, // TPM supports signing operations
		Decryption:          true, // TPM supports RSA decryption
		KeyRotation:         true, // Supports key rotation
		SymmetricEncryption: true, // Supports symmetric encryption (AES-128, AES-256)
		Import:              true, // Supports key import via wrapping
		Export:              true, // Supports key export (if FixedTPM=false)
	}
}

// Backend returns the underlying storage backend.
func (ks *TPM2KeyStore) Backend() types.Backend {
	return ks.backend
}

// Initialize sets up the TPM keystore by provisioning the Storage Root Key (SRK).
//
// This operation:
//   - Opens connection to TPM device or simulator
//   - Creates and persists the SRK under the Endorsement hierarchy
//   - Seals the user PIN to the TPM for future authentication
//   - Configures platform policy if enabled
//
// The soPIN authenticates to the TPM owner hierarchy for administrative operations.
// The userPIN protects the SRK and is sealed to the TPM for secure storage.
//
// This should only be called once during initial setup. Subsequent calls will
// return ErrAlreadyInitialized if the SRK already exists at the configured handle.
//
// Parameters:
//   - soPIN: Security Officer PIN for TPM hierarchy authentication
//   - userPIN: User PIN for SRK protection (sealed to TPM)
//
// Returns an error if:
//   - TPM is not accessible
//   - SRK already exists (ErrAlreadyInitialized)
//   - SRK creation fails
//   - PIN sealing fails
func (ks *TPM2KeyStore) Initialize(soPIN, userPIN types.Password) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Open TPM if not already open
	if ks.tpm == nil {
		tpmDevice, err := ks.openTPM()
		if err != nil {
			return fmt.Errorf("tpm2: failed to open TPM: %w", err)
		}
		ks.tpm = tpmDevice
	}

	// Check if SRK already exists
	readPubResp, err := tpm2.ReadPublic{
		ObjectHandle: ks.srkHandle,
	}.Execute(ks.tpm)

	if err == nil {
		// SRK exists - store its name for future use
		ks.srkName = readPubResp.Name
		return keychain.ErrAlreadyInitialized
	}

	// Create SRK
	if err := ks.createSRK(soPIN, userPIN); err != nil {
		return fmt.Errorf("tpm2: failed to create SRK: %w", err)
	}

	// Seal user PIN to TPM
	if userPIN != nil {
		if err := ks.sealPIN(userPIN); err != nil {
			return fmt.Errorf("tpm2: failed to seal user PIN: %w", err)
		}
	}

	return nil
}

// Close releases TPM resources and closes the connection.
// After calling Close, the keychain should not be used.
//
// Note: Transient key handles are flushed immediately after each operation,
// so no cleanup is needed here. Only the TPM connection needs to be closed.
func (ks *TPM2KeyStore) Close() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.closed {
		return keychain.ErrStorageClosed
	}

	ks.closed = true

	if ks.tpm != nil {
		if err := ks.tpm.Close(); err != nil {
			return fmt.Errorf("tpm2: failed to close TPM: %w", err)
		}
		ks.tpm = nil
	}

	return nil
}

// GenerateKey generates a new key pair based on the key algorithm in attrs.
// It delegates to GenerateRSA, GenerateECDSA, or returns an error for Ed25519.
func (ks *TPM2KeyStore) GenerateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		return ks.generateRSA(attrs)
	case x509.ECDSA:
		return ks.generateECDSA(attrs)
	case x509.Ed25519:
		return ks.generateEd25519(attrs)
	default:
		return nil, keychain.ErrInvalidKeyAlgorithm
	}
}

// generateRSA generates a new RSA key pair in the TPM.
//
// The key is created under the SRK and stored as a TPM blob in the backend.
// The private key never leaves the TPM in plaintext form.
//
// Supported key sizes: 2048, 3072, 4096 bits
//
// Parameters:
//   - attrs: Key attributes including RSA key size
//
// Returns:
//   - OpaqueKey wrapping the TPM-backed key
//   - Error if generation fails or attributes are invalid
func (ks *TPM2KeyStore) generateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := validateKeyAttributes(attrs); err != nil {
		return nil, err
	}

	if attrs.KeyAlgorithm != x509.RSA {
		return nil, keychain.ErrInvalidKeyAlgorithm
	}

	if attrs.RSAAttributes == nil {
		return nil, keychain.ErrInvalidRSAAttributes
	}

	// Validate RSA key size
	keySize := attrs.RSAAttributes.KeySize
	if keySize != 2048 && keySize != 3072 && keySize != 4096 {
		return nil, fmt.Errorf("tpm2: unsupported RSA key size %d, must be 2048, 3072, or 4096", keySize)
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Ensure TPM is open and SRK name is loaded
	if ks.tpm == nil {
		tpmDevice, err := ks.openTPM()
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to open TPM: %w", err)
		}
		ks.tpm = tpmDevice
	}

	// Load SRK name if not already loaded
	if len(ks.srkName.Buffer) == 0 {
		if err := ks.loadSRKName(); err != nil {
			return nil, fmt.Errorf("tpm2: failed to load SRK name: %w", err)
		}
	}

	// Build RSA template based on key type
	// Note: Keys under restricted storage parents cannot have both SignEncrypt and Decrypt
	// Use TPMAlgNull for scheme to allow flexible hash algorithms at signing time

	// Determine key usage based on KeyType
	var signEncrypt, decrypt bool
	switch attrs.KeyType {
	case kbackend.KEY_TYPE_ENCRYPTION:
		// Encryption keys need Decrypt attribute
		decrypt = true
	case kbackend.KEY_TYPE_TLS, kbackend.KEY_TYPE_CA:
		// TLS and CA keys are primarily for signing
		signEncrypt = true
	default:
		// Default to signing
		signEncrypt = true
	}

	template := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         signEncrypt,
			Decrypt:             decrypt,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull, // Allow flexible hash algorithms at signing time
				},
				KeyBits: tpm2.TPMKeyBits(keySize),
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, keySize/8),
			},
		),
	}

	// Create key under SRK
	createResp, err := tpm2.Create{
		ParentHandle: &tpm2.NamedHandle{
			Handle: ks.srkHandle,
			Name:   ks.srkName,
		},
		InPublic: tpm2.New2B(template),
	}.Execute(ks.tpm)

	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create RSA key: %w", err)
	}

	// Marshal the key blob for storage
	privateBlob := tpm2.Marshal(createResp.OutPrivate)
	publicBlob := tpm2.Marshal(createResp.OutPublic)

	// Save private blob
	privateKeyID := attrs.ID() + string(kbackend.FSEXT_PRIVATE_BLOB)
	if err := storage.SaveKey(ks.keyStorage, privateKeyID, privateBlob); err != nil {
		return nil, fmt.Errorf("tpm2: failed to save private blob: %w", err)
	}

	// Save public blob
	publicKeyID := attrs.ID() + string(kbackend.FSEXT_PUBLIC_BLOB)
	if err := storage.SaveKey(ks.keyStorage, publicKeyID, publicBlob); err != nil {
		return nil, fmt.Errorf("tpm2: failed to save public blob: %w", err)
	}

	// Extract public key
	pub, err := createResp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to get public key contents: %w", err)
	}

	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to get RSA details: %w", err)
	}

	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to get RSA unique: %w", err)
	}

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create RSA public key: %w", err)
	}

	opaqueKey, err := opaque.NewOpaqueKey(ks, attrs, rsaPub)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create opaque key: %w", err)
	}
	return opaqueKey, nil
}

// generateECDSA generates a new ECDSA key pair in the TPM.
//
// The key is created under the SRK and stored as a TPM blob in the backend.
// The private key never leaves the TPM in plaintext form.
//
// Supported curves: P-256, P-384, P-521
//
// Parameters:
//   - attrs: Key attributes including ECC curve
//
// Returns:
//   - OpaqueKey wrapping the TPM-backed key
//   - Error if generation fails or attributes are invalid
func (ks *TPM2KeyStore) generateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if err := validateKeyAttributes(attrs); err != nil {
		return nil, err
	}

	if attrs.KeyAlgorithm != x509.ECDSA {
		return nil, keychain.ErrInvalidKeyAlgorithm
	}

	if attrs.ECCAttributes == nil {
		return nil, keychain.ErrInvalidECCAttributes
	}

	// Map curve to TPM curve ID
	var tpmCurve tpm2.TPMECCCurve
	curve := attrs.ECCAttributes.Curve
	switch curve {
	case elliptic.P256():
		tpmCurve = tpm2.TPMECCNistP256
	case elliptic.P384():
		tpmCurve = tpm2.TPMECCNistP384
	case elliptic.P521():
		tpmCurve = tpm2.TPMECCNistP521
	default:
		return nil, fmt.Errorf("unsupported curve: %v", curve)
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Ensure TPM is open and SRK name is loaded
	if ks.tpm == nil {
		tpmDevice, err := ks.openTPM()
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to open TPM: %w", err)
		}
		ks.tpm = tpmDevice
	}

	// Load SRK name if not already loaded
	if len(ks.srkName.Buffer) == 0 {
		if err := ks.loadSRKName(); err != nil {
			return nil, fmt.Errorf("tpm2: failed to load SRK name: %w", err)
		}
	}

	// Build ECDSA template
	// Use TPMAlgNull for scheme to allow flexible hash algorithms at signing time
	template := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgNull, // Allow flexible hash algorithms at signing time
				},
				CurveID: tpmCurve,
			},
		),
	}

	// Create key under SRK
	createResp, err := tpm2.Create{
		ParentHandle: &tpm2.NamedHandle{
			Handle: ks.srkHandle,
			Name:   ks.srkName,
		},
		InPublic: tpm2.New2B(template),
	}.Execute(ks.tpm)

	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create ECDSA key: %w", err)
	}

	// Marshal the key blob for storage
	privateBlob := tpm2.Marshal(createResp.OutPrivate)
	publicBlob := tpm2.Marshal(createResp.OutPublic)

	// Save private blob
	privateKeyID := attrs.ID() + string(kbackend.FSEXT_PRIVATE_BLOB)
	if err := storage.SaveKey(ks.keyStorage, privateKeyID, privateBlob); err != nil {
		return nil, fmt.Errorf("tpm2: failed to save private blob: %w", err)
	}

	// Save public blob
	publicKeyID := attrs.ID() + string(kbackend.FSEXT_PUBLIC_BLOB)
	if err := storage.SaveKey(ks.keyStorage, publicKeyID, publicBlob); err != nil {
		return nil, fmt.Errorf("tpm2: failed to save public blob: %w", err)
	}

	// Extract public key
	pub, err := createResp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to get public key contents: %w", err)
	}

	eccDetail, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to get ECC details: %w", err)
	}

	eccUnique, err := pub.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to get ECC unique: %w", err)
	}

	goCurve, err := eccDetail.CurveID.Curve()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to get Go curve: %w", err)
	}

	ecdsaPub := &ecdsa.PublicKey{
		Curve: goCurve,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
	}

	opaqueKey, err := opaque.NewOpaqueKey(ks, attrs, ecdsaPub)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create opaque key: %w", err)
	}
	return opaqueKey, nil
}

// generateEd25519 always returns ErrUnsupportedKeyAlgorithm.
// TPM 2.0 does not support the Ed25519 algorithm.
func (ks *TPM2KeyStore) generateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, keychain.ErrUnsupportedKeyAlgorithm
}

// GenerateSecretKey generates a new secret key for symmetric operations.
//
// TPM 2.0 supports HMAC and secret key generation via keyed hash objects.
// The generated secret is sealed to the TPM and stored as a blob.
//
// Parameters:
//   - attrs: Key attributes specifying KeyTypeHMAC or KeyTypeSecret
//
// Returns an error if the key type is invalid or generation fails.
func (ks *TPM2KeyStore) GenerateSecretKey(attrs *types.KeyAttributes) error {
	// Validate key type
	if attrs.KeyType != kbackend.KEY_TYPE_SIGNING && attrs.KeyType != kbackend.KEY_TYPE_ENCRYPTION {
		return fmt.Errorf("tpm2: invalid key type for secret key generation, must be KeyTypeHMAC or KeyTypeSecret")
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Ensure TPM is open and SRK name is loaded
	if ks.tpm == nil {
		tpmDevice, err := ks.openTPM()
		if err != nil {
			return fmt.Errorf("tpm2: failed to open TPM: %w", err)
		}
		ks.tpm = tpmDevice
	}

	// Load SRK name if not already loaded
	if len(ks.srkName.Buffer) == 0 {
		if err := ks.loadSRKName(); err != nil {
			return fmt.Errorf("tpm2: failed to load SRK name: %w", err)
		}
	}

	// Create keyed hash template for HMAC/secret key
	template := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true, // For HMAC operations
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(
						tpm2.TPMAlgHMAC,
						&tpm2.TPMSSchemeHMAC{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
	}

	// Create the keyed hash object (TPM generates the key material)
	createResp, err := tpm2.Create{
		ParentHandle: &tpm2.NamedHandle{
			Handle: ks.srkHandle,
			Name:   ks.srkName,
		},
		InPublic: tpm2.New2B(template),
	}.Execute(ks.tpm)

	if err != nil {
		return fmt.Errorf("tpm2: failed to create secret key: %w", err)
	}

	// Marshal the key blob for storage
	privateBlob := tpm2.Marshal(createResp.OutPrivate)
	publicBlob := tpm2.Marshal(createResp.OutPublic)

	// Save private blob
	privateKeyID := attrs.ID() + string(kbackend.FSEXT_PRIVATE_BLOB)
	if err := storage.SaveKey(ks.keyStorage, privateKeyID, privateBlob); err != nil {
		return fmt.Errorf("tpm2: failed to save secret key private blob: %w", err)
	}

	// Save public blob
	publicKeyID := attrs.ID() + string(kbackend.FSEXT_PUBLIC_BLOB)
	if err := storage.SaveKey(ks.keyStorage, publicKeyID, publicBlob); err != nil {
		return fmt.Errorf("tpm2: failed to save secret key public blob: %w", err)
	}

	return nil
}

// RotateKey atomically replaces an existing key with a newly generated key.
//
// This method deletes the existing key blob and generates a new one with
// the same attributes. TPM keys are stored as blobs, so rotation is a
// delete-and-regenerate operation.
//
// Note: If deletion succeeds but generation fails, the key will be in a
// deleted state. Consider backup strategies for production use.
//
// Parameters:
//   - attrs: Key attributes identifying the key to rotate
//
// Returns an OpaqueKey for the new key, or an error if rotation fails.
func (ks *TPM2KeyStore) RotateKey(attrs *types.KeyAttributes) error {
	// Verify the key exists before attempting rotation
	_, err := ks.Find(attrs)
	if err != nil {
		return fmt.Errorf("tpm2: cannot rotate key that doesn't exist: %w", err)
	}

	// Delete the existing key blob
	if err := ks.DeleteKey(attrs); err != nil {
		return fmt.Errorf("tpm2: failed to delete existing key during rotation: %w", err)
	}

	// Generate new key with same attributes
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		_, err = ks.generateRSA(attrs)
	case x509.ECDSA:
		_, err = ks.generateECDSA(attrs)
	case x509.Ed25519:
		err = keychain.ErrUnsupportedKeyAlgorithm
	default:
		err = keychain.ErrInvalidKeyAlgorithm
	}
	return err
}

// Equal compares an opaque key with a native private key for equality.
//
// For TPM-backed keys, we can only compare the public key portions since
// the private key never leaves the TPM. This method extracts public keys
// from both parameters and performs a deep comparison.
//
// Parameters:
//   - opaque: The opaque key from the TPM
//   - x: The private key to compare against
//
// Returns true if the public keys match, indicating the same key pair.
func (ks *TPM2KeyStore) Equal(opaque crypto.PrivateKey, x crypto.PrivateKey) bool {
	if opaque == nil || x == nil {
		return false
	}

	// Get public key from opaque key - need to type assert to crypto.Signer
	signer, ok := opaque.(crypto.Signer)
	if !ok {
		return false
	}
	opaquePub := signer.Public()
	if opaquePub == nil {
		return false
	}

	// Extract public key from private key
	var xPub crypto.PublicKey
	switch pk := x.(type) {
	case *rsa.PrivateKey:
		xPub = &pk.PublicKey
	case *ecdsa.PrivateKey:
		xPub = &pk.PublicKey
	case ed25519.PrivateKey:
		xPub = pk.Public()
	default:
		return false
	}

	// Compare public keys based on type
	switch opaquePubKey := opaquePub.(type) {
	case *rsa.PublicKey:
		xPubKey, ok := xPub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		// Compare RSA modulus and exponent
		return opaquePubKey.N.Cmp(xPubKey.N) == 0 && opaquePubKey.E == xPubKey.E

	case *ecdsa.PublicKey:
		xPubKey, ok := xPub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		// Compare ECDSA curve and coordinates
		return opaquePubKey.Curve == xPubKey.Curve &&
			opaquePubKey.X.Cmp(xPubKey.X) == 0 &&
			opaquePubKey.Y.Cmp(xPubKey.Y) == 0

	case ed25519.PublicKey:
		xPubKey, ok := xPub.(ed25519.PublicKey)
		if !ok {
			return false
		}
		// Compare Ed25519 public key bytes
		if len(opaquePubKey) != len(xPubKey) {
			return false
		}
		for i := range opaquePubKey {
			if opaquePubKey[i] != xPubKey[i] {
				return false
			}
		}
		return true

	default:
		return false
	}
}

// GetKey retrieves an existing key from the keychain.
//
// The key blob is loaded from the backend and the public portion is returned.
// The private key remains sealed in the TPM blob.
//
// Parameters:
//   - attrs: Key attributes identifying the key to retrieve
//
// Returns:
//   - OpaqueKey for the requested key
//   - ErrKeyNotFound if key doesn't exist
//   - Other errors for load failures
func (ks *TPM2KeyStore) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Ensure TPM is open
	if ks.tpm == nil {
		ks.mu.RUnlock()
		ks.mu.Lock()
		if ks.tpm == nil {
			tpmDevice, err := ks.openTPM()
			if err != nil {
				ks.mu.Unlock()
				ks.mu.RLock()
				return nil, fmt.Errorf("tpm2: failed to open TPM: %w", err)
			}
			ks.tpm = tpmDevice
		}
		ks.mu.Unlock()
		ks.mu.RLock()
	}

	// Load public blob
	publicKeyID := attrs.ID() + string(kbackend.FSEXT_PUBLIC_BLOB)
	publicBlob, err := storage.GetKey(ks.keyStorage, publicKeyID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, keychain.ErrKeyNotFound
		}
		return nil, fmt.Errorf("tpm2: failed to load public blob: %w", err)
	}

	// Unmarshal public structure - FIXED API
	tpmPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unmarshal public blob: %w", err)
	}

	pub, err := tpmPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to get public contents: %w", err)
	}

	// Convert to Go crypto public key
	var publicKey crypto.PublicKey
	switch pub.Type {
	case tpm2.TPMAlgRSA:
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to get RSA details: %w", err)
		}
		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to get RSA unique: %w", err)
		}
		publicKey, err = tpm2.RSAPub(rsaDetail, rsaUnique)
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to create RSA public key: %w", err)
		}

	case tpm2.TPMAlgECC:
		eccDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to get ECC details: %w", err)
		}
		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to get ECC unique: %w", err)
		}
		curve, err := eccDetail.CurveID.Curve()
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to get curve: %w", err)
		}
		publicKey = &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}

	default:
		return nil, keychain.ErrUnsupportedKeyAlgorithm
	}

	opaqueKey, err := opaque.NewOpaqueKey(ks, attrs, publicKey)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create opaque key: %w", err)
	}
	return opaqueKey, nil
}

// Find checks if a key exists in the keychain without fully loading it.
//
// This is more efficient than GetKey() for existence checks.
//
// Parameters:
//   - attrs: Key attributes identifying the key
//
// Returns:
//   - OpaqueKey if found
//   - ErrKeyNotFound if not found
func (ks *TPM2KeyStore) Find(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	// For TPM backend, Find and GetKey are similar - we need to load the blob
	// to get the public key anyway
	return ks.GetKey(attrs)
}

// Signer returns a crypto.Signer for the specified key.
//
// The returned signer performs TPM-native signing operations without
// exposing the private key.
//
// Parameters:
//   - attrs: Key attributes identifying the signing key
//
// Returns:
//   - crypto.Signer for RSA or ECDSA keys
//   - Error if key not found or doesn't support signing
func (ks *TPM2KeyStore) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	// Get the public key first
	opaqueKey, err := ks.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	// Type assert to crypto.Signer to access Public() method
	signer, ok := opaqueKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tpm2: key does not implement crypto.Signer")
	}

	return &tpmSigner{
		ks:     ks,
		attrs:  attrs,
		public: signer.Public(),
	}, nil
}

// Decrypter returns a crypto.Decrypter for the specified key.
//
// Note: Decryption support depends on key attributes and TPM capabilities.
// Not all TPM keys support decryption operations.
//
// Parameters:
//   - attrs: Key attributes identifying the decryption key
//
// Returns:
//   - crypto.Decrypter for keys that support decryption
//   - Error if key doesn't support decryption
func (ks *TPM2KeyStore) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	// Get the public key first
	opaqueKey, err := ks.GetKey(attrs)
	if err != nil {
		return nil, err
	}

	// Type assert to crypto.Signer to access Public() method
	signer, ok := opaqueKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tpm2: key does not implement crypto.Signer")
	}

	// Only RSA keys support decryption in TPM
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("tpm2: decryption only supported for RSA keys")
	}

	return &tpmDecrypter{
		tpmSigner: tpmSigner{
			ks:     ks,
			attrs:  attrs,
			public: signer.Public(),
		},
	}, nil
}

// DeleteKey removes a key from the keychain.
//
// This deletes the TPM key blob from the backend.
//
// Note: No TPM handle cleanup is needed as transient handles are
// flushed immediately after each operation (signing, decryption, etc.).
//
// Parameters:
//   - attrs: Key attributes identifying the key to delete
//
// Returns:
//   - Error if deletion fails
//   - nil if successful or key doesn't exist (idempotent)
func (ks *TPM2KeyStore) DeleteKey(attrs *types.KeyAttributes) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Delete private and public blobs from key storage
	privateKeyID := attrs.ID() + string(kbackend.FSEXT_PRIVATE_BLOB)
	if err := storage.DeleteKey(ks.keyStorage, privateKeyID); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("tpm2: failed to delete private blob: %w", err)
	}

	publicKeyID := attrs.ID() + string(kbackend.FSEXT_PUBLIC_BLOB)
	if err := storage.DeleteKey(ks.keyStorage, publicKeyID); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("tpm2: failed to delete public blob: %w", err)
	}

	return nil
}

// ListKeys returns attributes for all keys managed by this keychain.
func (ks *TPM2KeyStore) ListKeys() ([]*types.KeyAttributes, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	if ks.closed {
		return nil, keychain.ErrStorageClosed
	}

	// List all key IDs from storage
	keyIDs, err := storage.ListKeys(ks.keyStorage)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to list keys: %w", err)
	}

	// Strip file extensions and deduplicate
	// Keys are stored as "composite-id.key.bin" and "composite-id.pub.bin"
	// where composite-id is like "tpm2:tls:keyname:rsa"
	uniqueKeys := make(map[string]bool)
	for _, id := range keyIDs {
		// Remove both possible extensions
		baseName := id
		baseName = strings.TrimSuffix(baseName, string(kbackend.FSEXT_PRIVATE_BLOB))
		baseName = strings.TrimSuffix(baseName, string(kbackend.FSEXT_PUBLIC_BLOB))
		uniqueKeys[baseName] = true
	}

	// Create KeyAttributes for each unique key
	// Parse the composite ID to extract components
	// Format: [partition:]storetype:keytype:cn:keyalgorithm
	attrs := make([]*types.KeyAttributes, 0, len(uniqueKeys))
	for compositeID := range uniqueKeys {
		parts := strings.Split(compositeID, ":")

		var attr *types.KeyAttributes
		if len(parts) == 4 {
			// Format: storetype:keytype:cn:keyalgorithm
			attr = &types.KeyAttributes{
				StoreType: types.StoreType(parts[0]),
				KeyType:   types.ParseKeyType(parts[1]),
				CN:        parts[2],
			}
			parseAlgorithm(attr, parts[3])
		} else if len(parts) == 5 {
			// Format: partition:storetype:keytype:cn:keyalgorithm
			attr = &types.KeyAttributes{
				Partition: types.Partition(parts[0]),
				StoreType: types.StoreType(parts[1]),
				KeyType:   types.ParseKeyType(parts[2]),
				CN:        parts[3],
			}
			parseAlgorithm(attr, parts[4])
		} else {
			// Fallback: treat the whole thing as CN
			attr = &types.KeyAttributes{
				CN:        compositeID,
				StoreType: kbackend.STORE_TPM2,
			}
		}
		attrs = append(attrs, attr)
	}

	return attrs, nil
}

// parseAlgorithm parses an algorithm string and sets the appropriate field in KeyAttributes
func parseAlgorithm(attrs *types.KeyAttributes, algStr string) {
	// Try to parse as x509.PublicKeyAlgorithm
	switch strings.ToLower(algStr) {
	case "rsa":
		attrs.KeyAlgorithm = x509.RSA
	case "ecdsa":
		attrs.KeyAlgorithm = x509.ECDSA
	case "ed25519":
		attrs.KeyAlgorithm = x509.Ed25519
	default:
		// Try to parse as SymmetricAlgorithm
		attrs.SymmetricAlgorithm = types.SymmetricAlgorithm(algStr)
	}
}

// openTPM opens a connection to the TPM device or simulator based on configuration.
func (ks *TPM2KeyStore) openTPM() (transport.TPMCloser, error) {
	var tpmConn transport.TPMCloser
	var err error

	if ks.config.UseSimulator {
		switch ks.config.SimulatorType {
		case "embedded":
			// Use embedded go-tpm-tools simulator (stateless, for testing)
			// This matches go-trusted-platform behavior
			sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
			if err != nil {
				return nil, fmt.Errorf("tpm2: failed to open embedded simulator: %w", err)
			}

			// Wrap simulator to provide proper Close behavior
			tpmConn = &simulatorCloser{
				sim:       sim,
				transport: transport.FromReadWriter(sim),
			}

		case "swtpm":
			// Use SWTPM over TCP (stateful, for production VMs)
			// SWTPM requires both command and platform (ctrl) ports
			cmdAddr := fmt.Sprintf("%s:%d", ks.config.SimulatorHost, ks.config.SimulatorPort)
			platAddr := fmt.Sprintf("%s:%d", ks.config.SimulatorHost, ks.config.SimulatorPort+1)
			tcpTPM, err := tcp.Open(tcp.Config{
				CommandAddress:  cmdAddr,
				PlatformAddress: platAddr,
			})
			if err != nil {
				return nil, fmt.Errorf("tpm2: failed to connect to SWTPM at %s (platform: %s): %w", cmdAddr, platAddr, err)
			}

			// SWTPM is started with --flags startup-clear, so TPM2_Startup is automatic
			// No need to send it manually
			tpmConn = tcpTPM

		default:
			return nil, fmt.Errorf("tpm2: invalid simulator type %q", ks.config.SimulatorType)
		}
	} else {
		// Open hardware TPM device
		tpmConn, err = transport.OpenTPM(ks.config.DevicePath)
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to open TPM device: %w", err)
		}
	}

	return tpmConn, nil
}

// simulatorCloser wraps the simulator to provide proper Close() behavior
type simulatorCloser struct {
	sim       *simulator.Simulator
	transport transport.TPM
}

func (sc *simulatorCloser) Send(input []byte) ([]byte, error) {
	return sc.transport.Send(input)
}

func (sc *simulatorCloser) Close() error {
	sc.sim.Close()
	return nil
}

// loadSRKName reads the SRK's cryptographic name from the TPM.
// This is needed to use the SRK as a parent handle in TPM operations.
func (ks *TPM2KeyStore) loadSRKName() error {
	readPubResp, err := tpm2.ReadPublic{
		ObjectHandle: ks.srkHandle,
	}.Execute(ks.tpm)

	if err != nil {
		return fmt.Errorf("tpm2: failed to read SRK public: %w", err)
	}

	ks.srkName = readPubResp.Name
	return nil
}

// createSRK creates and persists the Storage Root Key in the TPM.
func (ks *TPM2KeyStore) createSRK(soPIN, userPIN types.Password) error {
	// Build SRK template (RSA 2048-bit storage key)
	srkTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			Restricted:          true,
			Decrypt:             true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				KeyBits: 2048,
			},
		),
	}

	// Note: SRK is created WITHOUT a password for simplicity
	// The userPIN is sealed TO the SRK, not used to PROTECT the SRK
	// This is the standard approach for TPM key hierarchies
	//
	// For SWTPM simulator, the owner hierarchy is typically not password protected.
	// We use an empty password for maximum compatibility.

	// Create primary key (SRK)
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil), // No password for owner hierarchy
		},
		InPublic: tpm2.New2B(srkTemplate),
		// SRK created with empty password
	}

	rsp, err := createPrimary.Execute(ks.tpm)
	if err != nil {
		return fmt.Errorf("tpm2: failed to create primary key: %w", err)
	}

	// Persist the SRK
	evictControl := tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: rsp.ObjectHandle,
			Name:   rsp.Name,
		},
		PersistentHandle: ks.srkHandle,
	}

	_, err = evictControl.Execute(ks.tpm)
	if err != nil {
		// Flush transient handle before returning error
		tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(ks.tpm)
		return fmt.Errorf("tpm2: failed to persist SRK: %w", err)
	}

	// Flush transient handle (we now use the persistent handle)
	tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(ks.tpm)

	// Store the SRK name for future use
	ks.srkName = rsp.Name

	return nil
}

// sealPIN seals a password to the TPM using a keyed hash object.
func (ks *TPM2KeyStore) sealPIN(pin types.Password) error {
	pinBytes := pin.Bytes()

	// Create keyed hash template for sealing
	template := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		),
	}

	// Create the sealed object
	createResp, err := tpm2.Create{
		ParentHandle: &tpm2.NamedHandle{
			Handle: ks.srkHandle,
			Name:   ks.srkName,
		},
		InPublic: tpm2.New2B(template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(
					&tpm2.TPM2BSensitiveData{
						Buffer: pinBytes,
					},
				),
			},
		},
	}.Execute(ks.tpm)

	if err != nil {
		return fmt.Errorf("tpm2: failed to seal PIN: %w", err)
	}

	// Save sealed blob to backend
	privateBlob := tpm2.Marshal(createResp.OutPrivate)
	publicBlob := tpm2.Marshal(createResp.OutPublic)

	// Use a special key attributes for the PIN
	pinAttrs := &types.KeyAttributes{
		CN:        fmt.Sprintf("%s.pin", ks.config.CN),
		StoreType: kbackend.STORE_TPM2,
	}

	privateKeyID := pinAttrs.ID() + string(kbackend.FSEXT_PRIVATE_BLOB)
	if err := storage.SaveKey(ks.keyStorage, privateKeyID, privateBlob); err != nil {
		return fmt.Errorf("tpm2: failed to save sealed PIN private: %w", err)
	}

	publicKeyID := pinAttrs.ID() + string(kbackend.FSEXT_PUBLIC_BLOB)
	if err := storage.SaveKey(ks.keyStorage, publicKeyID, publicBlob); err != nil {
		return fmt.Errorf("tpm2: failed to save sealed PIN public: %w", err)
	}

	return nil
}

// unsealPIN retrieves a sealed password from the TPM.
func (ks *TPM2KeyStore) unsealPIN() ([]byte, error) {
	pinAttrs := &types.KeyAttributes{
		CN:        fmt.Sprintf("%s.pin", ks.config.CN),
		StoreType: kbackend.STORE_TPM2,
	}

	// Load blobs
	privateKeyID := pinAttrs.ID() + string(kbackend.FSEXT_PRIVATE_BLOB)
	privateBlob, err := storage.GetKey(ks.keyStorage, privateKeyID)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load sealed PIN private: %w", err)
	}

	publicKeyID := pinAttrs.ID() + string(kbackend.FSEXT_PUBLIC_BLOB)
	publicBlob, err := storage.GetKey(ks.keyStorage, publicKeyID)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load sealed PIN public: %w", err)
	}

	// Unmarshal blobs - FIXED API
	tpmPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privateBlob)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unmarshal sealed private: %w", err)
	}

	tpmPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unmarshal sealed public: %w", err)
	}

	// Load into TPM
	loadResp, err := tpm2.Load{
		ParentHandle: &tpm2.NamedHandle{
			Handle: ks.srkHandle,
			Name:   ks.srkName,
		},
		InPrivate: *tpmPrivate,
		InPublic:  *tpmPublic,
	}.Execute(ks.tpm)

	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load sealed object: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}.Execute(ks.tpm)

	// Unseal
	unsealResp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loadResp.ObjectHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
	}.Execute(ks.tpm)

	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unseal PIN: %w", err)
	}

	return unsealResp.OutData.Buffer, nil
}

// keyHandleInfo contains both handle and name for a loaded TPM key.
type keyHandleInfo struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
}

// loadKey loads a key into the TPM and returns its handle and name.
//
// IMPORTANT: The caller is responsible for:
// 1. Flushing the returned transient handle after use
// 2. Closing the returned session closer if not nil
//
// When encryption is enabled, this function creates an HMAC session that MUST be closed
// by calling the returned closer function immediately after the load completes.
//
// Returns:
//   - keyHandleInfo: Handle and name of the loaded key
//   - closer: Function to close the parent session (may be nil if PasswordAuth used)
//   - error: Any error that occurred
func (ks *TPM2KeyStore) loadKey(attrs *types.KeyAttributes) (*keyHandleInfo, func() error, error) {
	var session tpm2.Session
	var closer func() error
	var err error

	if ks.config.EncryptSession {
		// Create encrypted HMAC session - MUST be closed after use
		session, closer, err = ks.HMACSession(nil)
		if err != nil {
			return nil, nil, fmt.Errorf("tpm2: failed to create HMAC session: %w", err)
		}
	} else {
		// Use password auth - no session resources consumed
		session = tpm2.PasswordAuth(nil)
		closer = nil
	}

	keyInfo, err := ks.loadKeyWithSession(attrs, session)
	if err != nil {
		// Close session on error
		if closer != nil {
			closer()
		}
		return nil, nil, err
	}

	return keyInfo, closer, nil
}

// loadKeyWithSession loads a key into the TPM using the specified authorization session.
//
// IMPORTANT: The caller is responsible for flushing the returned transient handle
// after use to avoid TPM resource exhaustion (TPM_RC_RETRY errors).
func (ks *TPM2KeyStore) loadKeyWithSession(attrs *types.KeyAttributes, parentAuth tpm2.Session) (*keyHandleInfo, error) {
	// Load from backend
	privateKeyID := attrs.ID() + string(kbackend.FSEXT_PRIVATE_BLOB)
	privateBlob, err := storage.GetKey(ks.keyStorage, privateKeyID)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load private blob: %w", err)
	}

	publicKeyID := attrs.ID() + string(kbackend.FSEXT_PUBLIC_BLOB)
	publicBlob, err := storage.GetKey(ks.keyStorage, publicKeyID)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load public blob: %w", err)
	}

	// Unmarshal blobs - FIXED API
	tpmPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privateBlob)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unmarshal private blob: %w", err)
	}

	tpmPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unmarshal public blob: %w", err)
	}

	// Load into TPM - creates a NEW transient handle each time
	// Use AuthHandle with session for proper authorization
	loadResp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: ks.srkHandle,
			Name:   ks.srkName,
			Auth:   parentAuth,
		},
		InPrivate: *tpmPrivate,
		InPublic:  *tpmPublic,
	}.Execute(ks.tpm)

	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load key: %w", err)
	}

	// Return transient handle - caller MUST flush after use
	return &keyHandleInfo{
		handle: loadResp.ObjectHandle,
		name:   loadResp.Name,
	}, nil
}

// validateKeyAttributes checks key attributes for completeness and validity.
func validateKeyAttributes(attrs *types.KeyAttributes) error {
	if attrs == nil {
		return keychain.ErrInvalidKeyAttributes
	}

	if attrs.CN == "" {
		return errors.New("tpm2: CN (Common Name) is required in key attributes")
	}

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if attrs.RSAAttributes == nil {
			return keychain.ErrInvalidRSAAttributes
		}
		if attrs.RSAAttributes.KeySize < 2048 {
			return errors.New("tpm2: RSA key size must be at least 2048 bits")
		}
	case x509.ECDSA:
		if attrs.ECCAttributes == nil {
			return keychain.ErrInvalidECCAttributes
		}
		if attrs.ECCAttributes.Curve == nil {
			return keychain.ErrInvalidCurve
		}
	case x509.Ed25519:
		return keychain.ErrUnsupportedKeyAlgorithm
	default:
		return keychain.ErrInvalidKeyAlgorithm
	}

	return nil
}

// tpmSigner implements crypto.Signer for TPM-backed keys.
type tpmSigner struct {
	ks     *TPM2KeyStore
	attrs  *types.KeyAttributes
	public crypto.PublicKey
}

// Public returns the public key portion of the TPM key.
func (s *tpmSigner) Public() crypto.PublicKey {
	return s.public
}

// Sign performs a TPM-based signing operation.
//
// The signature is created by the TPM using the sealed private key.
// The private key never leaves the TPM.
//
// Parameters:
//   - rand: Ignored (TPM provides its own randomness)
//   - digest: The digest to sign
//   - opts: Signing options (hash algorithm, PSS parameters, etc.)
//
// Returns:
//   - signature bytes
//   - error if signing fails
func (s *tpmSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	_ = rand // TPM provides its own randomness

	s.ks.mu.Lock()
	defer s.ks.mu.Unlock()

	// Create parent session for loading the key
	// Use HMAC() which creates appropriate session type based on config
	parentSession := s.ks.HMAC(nil)

	// Load key into TPM using parent session
	keyInfo, err := s.ks.loadKeyWithSession(s.attrs, parentSession)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load key for signing: %w", err)
	}

	defer func() {
		if keyInfo != nil {
			_, _ = tpm2.FlushContext{FlushHandle: keyInfo.handle}.Execute(s.ks.tpm)
		}
	}()

	// Determine hash algorithm from opts
	hashAlg := tpm2.TPMAlgSHA256
	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA256:
			hashAlg = tpm2.TPMAlgSHA256
		case crypto.SHA384:
			hashAlg = tpm2.TPMAlgSHA384
		case crypto.SHA512:
			hashAlg = tpm2.TPMAlgSHA512
		}
	}

	// Use password auth for key authorization (no resources consumed)
	keyAuth := tpm2.PasswordAuth(nil)

	// Determine key type from public key and sign accordingly
	switch s.public.(type) {
	case *rsa.PublicKey:
		// Check if PSS options are provided
		_, isPSS := opts.(*rsa.PSSOptions)

		var signResp *tpm2.SignResponse
		var err error

		if isPSS {
			// RSA signing with RSAPSS scheme
			signResp, err = tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: keyInfo.handle,
					Name:   keyInfo.name,
					Auth:   keyAuth,
				},
				Digest: tpm2.TPM2BDigest{Buffer: digest},
				InScheme: tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSchemeHash{HashAlg: hashAlg},
					),
				},
				Validation: tpm2.TPMTTKHashCheck{
					Tag: tpm2.TPMSTHashCheck,
				},
			}.Execute(s.ks.tpm)
		} else {
			// RSA signing with RSASSA scheme (PKCS#1 v1.5)
			signResp, err = tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: keyInfo.handle,
					Name:   keyInfo.name,
					Auth:   keyAuth,
				},
				Digest: tpm2.TPM2BDigest{Buffer: digest},
				InScheme: tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSchemeHash{HashAlg: hashAlg},
					),
				},
				Validation: tpm2.TPMTTKHashCheck{
					Tag: tpm2.TPMSTHashCheck,
				},
			}.Execute(s.ks.tpm)
		}

		if err != nil {
			return nil, fmt.Errorf("tpm2: RSA signing failed: %w", err)
		}

		// Extract signature based on scheme used
		if isPSS {
			rsaSig, err := signResp.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, fmt.Errorf("tpm2: failed to extract RSA-PSS signature: %w", err)
			}
			return rsaSig.Sig.Buffer, nil
		} else {
			rsaSig, err := signResp.Signature.Signature.RSASSA()
			if err != nil {
				return nil, fmt.Errorf("tpm2: failed to extract RSA signature: %w", err)
			}
			return rsaSig.Sig.Buffer, nil
		}

	case *ecdsa.PublicKey:
		// ECDSA signing
		signResp, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{
				Handle: keyInfo.handle,
				Name:   keyInfo.name,
				Auth:   keyAuth,
			},
			Digest: tpm2.TPM2BDigest{Buffer: digest},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSchemeHash{HashAlg: hashAlg},
				),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}.Execute(s.ks.tpm)

		if err != nil {
			return nil, fmt.Errorf("tpm2: ECDSA signing failed: %w", err)
		}

		ecdsaSig, err := signResp.Signature.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to extract ECDSA signature: %w", err)
		}

		// Marshal R and S as ASN.1 (required for standard ECDSA signature format)
		r := big.NewInt(0).SetBytes(ecdsaSig.SignatureR.Buffer)
		sBigInt := big.NewInt(0).SetBytes(ecdsaSig.SignatureS.Buffer)
		asn1Struct := struct{ R, S *big.Int }{r, sBigInt}
		return asn1.Marshal(asn1Struct)

	default:
		return nil, keychain.ErrUnsupportedKeyAlgorithm
	}
}

// tpmDecrypter implements crypto.Decrypter for TPM-backed RSA keys.
type tpmDecrypter struct {
	tpmSigner
}

// Decrypt performs TPM-based decryption.
func (d *tpmDecrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	_ = rand // TPM provides its own randomness

	d.ks.mu.Lock()
	defer d.ks.mu.Unlock()

	// Load key into TPM - creates transient handle and possibly a session
	keyInfo, sessionCloser, err := d.ks.loadKey(d.attrs)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to load key for decryption: %w", err)
	}

	// Close parent session immediately after load completes
	if sessionCloser != nil {
		if err := sessionCloser(); err != nil {
			// Flush key handle on error
			tpm2.FlushContext{FlushHandle: keyInfo.handle}.Execute(d.ks.tpm)
			return nil, fmt.Errorf("tpm2: failed to close parent session: %w", err)
		}
	}

	// CRITICAL: Flush transient handle after decryption to prevent TPM_RC_RETRY errors
	defer func() {
		if keyInfo != nil {
			_, _ = tpm2.FlushContext{FlushHandle: keyInfo.handle}.Execute(d.ks.tpm)
		}
	}()

	// Use password auth for key authorization (no session resources needed)
	keySession := tpm2.PasswordAuth(nil)

	// Determine decryption scheme based on opts
	var scheme tpm2.TPMTRSADecrypt

	// Check if OAEP is requested
	if oaepOpts, ok := opts.(*rsa.OAEPOptions); ok {
		// Map crypto.Hash to TPM hash algorithm
		var hashAlg tpm2.TPMAlgID
		switch oaepOpts.Hash {
		case crypto.SHA256:
			hashAlg = tpm2.TPMAlgSHA256
		case crypto.SHA384:
			hashAlg = tpm2.TPMAlgSHA384
		case crypto.SHA512:
			hashAlg = tpm2.TPMAlgSHA512
		default:
			return nil, fmt.Errorf("tpm2: unsupported OAEP hash algorithm: %v", oaepOpts.Hash)
		}

		// Use OAEP scheme
		scheme = tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: hashAlg,
				},
			),
		}
	} else {
		// Default to PKCS#1 v1.5 (RSAES)
		scheme = tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgRSAES,
		}
	}

	decrypt := tpm2.RSADecrypt{
		KeyHandle: tpm2.AuthHandle{
			Handle: keyInfo.handle,
			Name:   keyInfo.name,
			Auth:   keySession,
		},
		CipherText: tpm2.TPM2BPublicKeyRSA{
			Buffer: ciphertext,
		},
		InScheme: scheme,
	}

	decryptResp, err := decrypt.Execute(d.ks.tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2: decryption failed: %w", err)
	}

	return decryptResp.Message.Buffer, nil
}

// Ensure interfaces are implemented at compile time
var _ types.Backend = (*TPM2KeyStore)(nil)
var _ crypto.Signer = (*tpmSigner)(nil)
var _ crypto.Decrypter = (*tpmDecrypter)(nil)

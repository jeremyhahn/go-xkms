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

//go:build pkcs11

package pkcs11

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/crypto11"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/miekg/pkcs11"
)

// Ensure Backend implements ImportExportBackend interface
var _ backend.ImportExportBackend = (*Backend)(nil)

// PKCS#11 wrapping key constants
const (
	// wrappingKeyLabel is the label for the HSM wrapping key used for import/export
	wrappingKeyLabel = "go-keychain-wrapping-key"

	// wrappingKeySize is the size of the RSA wrapping key in bits
	wrappingKeySize = 4096
)

// GetImportParameters retrieves the parameters needed to import a key into the PKCS#11 HSM.
// This method finds or creates a wrapping key in the HSM and returns its public key.
//
// PKCS#11 wrapping keys are stored permanently in the HSM token and reused for multiple imports.
// The wrapping key is an RSA 4096-bit key pair with the private key marked as non-extractable
// and sensitive, ensuring it never leaves the HSM.
//
// For PKCS#11, import tokens are not required since the wrapping key is permanently stored
// in the HSM and referenced by its label.
func (b *Backend) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Validate wrapping algorithm
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Supported algorithms
	default:
		return nil, fmt.Errorf("%w: %s for PKCS#11", backend.ErrInvalidAlgorithm, algorithm)
	}

	// Find or create wrapping key in HSM
	wrappingKeyID := []byte(wrappingKeyLabel)

	// Try to find existing wrapping key
	wrappingKeySigner, err := b.ctx.FindKeyPair(wrappingKeyID, nil)
	if err != nil || wrappingKeySigner == nil {
		// Wrapping key doesn't exist, create it with explicit wrap/unwrap capabilities
		wrappingKeySigner, err = b.generateWrappingKeyPair(wrappingKeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate wrapping key: %w", err)
		}
	}

	// Get the public key from the wrapping key
	wrappingPublicKey := wrappingKeySigner.Public()

	// Determine key spec from attributes
	keySpec := determineKeySpec(attrs)

	// For PKCS#11, wrapping keys don't expire as they're permanently stored in HSM
	// We return nil for ExpiresAt
	return &backend.ImportParameters{
		WrappingPublicKey: wrappingPublicKey,
		ImportToken:       wrappingKeyID, // Use wrapping key ID as token
		Algorithm:         algorithm,
		ExpiresAt:         nil, // No expiration for PKCS#11 wrapping keys
		KeySpec:           keySpec,
	}, nil
}

// WrapKey wraps key material for secure transport using the specified parameters.
// This uses the standard wrapping functions from pkg/crypto/wrapping.
//
// The actual wrapping is performed locally using the wrapping public key from ImportParameters.
// The wrapped key can then be securely transmitted and imported via ImportKey, which will
// unwrap it using the corresponding private key in the HSM.
func (b *Backend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if keyMaterial == nil || len(keyMaterial) == 0 {
		return nil, fmt.Errorf("%w: key material cannot be nil or empty", backend.ErrInvalidAttributes)
	}

	if params == nil {
		return nil, fmt.Errorf("%w: import parameters cannot be nil", backend.ErrInvalidAttributes)
	}

	// Ensure we have an RSA public key
	rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: wrapping public key must be RSA", backend.ErrInvalidKeyType)
	}

	var wrapped []byte
	var err error

	// Wrap based on algorithm
	switch params.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		// Direct RSA-OAEP wrapping (for small keys like symmetric keys)
		wrapped, err = wrapping.WrapRSAOAEP(keyMaterial, rsaPubKey, params.Algorithm)

	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Hybrid wrapping (for large keys like RSA private keys)
		wrapped, err = wrapping.WrapRSAAES(keyMaterial, rsaPubKey, params.Algorithm)

	default:
		return nil, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, params.Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to wrap key material: %w", err)
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrapped,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// UnwrapKey unwraps key material that was previously wrapped with WrapKey.
// For PKCS#11, unwrapping happens in the HSM during import via C_UnwrapKey, so this
// method returns ErrNotSupported. This method exists to satisfy the ImportExportBackend
// interface but is not used for PKCS#11 imports.
//
// The actual unwrapping is performed by the HSM's C_UnwrapKey function during ImportKey,
// ensuring the plaintext key material never leaves the HSM hardware boundary.
func (b *Backend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	return nil, fmt.Errorf("%w: unwrapping is performed by PKCS#11 HSM during import", backend.ErrNotSupported)
}

// ImportKey imports externally generated key material into the PKCS#11 HSM.
// The key material must be wrapped using parameters obtained from GetImportParameters.
//
// This method uses the PKCS#11 C_UnwrapKey function to securely import the wrapped key
// into the HSM. The unwrapping happens entirely within the HSM hardware, ensuring the
// plaintext key material never exists outside the secure boundary.
//
// The imported key is marked as:
//   - CKA_TOKEN: true (stored permanently in the token)
//   - CKA_PRIVATE: true (requires authentication to access - for private keys)
//   - CKA_SENSITIVE: true (cannot be extracted in plaintext - for private keys)
//   - CKA_EXTRACTABLE: false (can only be exported in wrapped form - for private keys)
//
// HSM Compatibility Note:
// While the PKCS#11 2.40 specification supports C_UnwrapKey with CKM_RSA_PKCS_OAEP for secret keys,
// some HSM implementations (including SoftHSM2) may return CKR_ARGUMENTS_BAD when attempting this
// operation. This is a known limitation of certain HSM implementations. Production hardware HSMs
// with complete PKCS#11 2.40 support should work correctly.
func (b *Backend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ctx == nil {
		return ErrNotInitialized
	}

	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	if wrapped == nil {
		return fmt.Errorf("%w: wrapped key material cannot be nil", backend.ErrInvalidAttributes)
	}

	// Initialize low-level PKCS#11 context if not already done
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return fmt.Errorf("failed to load PKCS#11 library: %s", b.config.Library)
		}

		if err := p.Initialize(); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				return fmt.Errorf("failed to initialize PKCS#11: %w", err)
			}
		}

		b.p11ctx = p
	}

	// Get token slot
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return ErrTokenNotFound
	}

	slot := slots[0]
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("failed to open session: %w", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Login as user (only logout if we performed the login)
	var didLogin bool
	if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return fmt.Errorf("failed to login: %w", err)
		}
		// Already logged in, don't logout later
		didLogin = false
	} else {
		// We logged in successfully, logout when done
		didLogin = true
	}
	if didLogin {
		defer b.p11ctx.Logout(session)
	}

	// Find the wrapping key (private key handle)
	wrappingKeyID := wrapped.ImportToken // This is the wrapping key label
	wrappingKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, wrappingKeyID),
	}

	if err := b.p11ctx.FindObjectsInit(session, wrappingKeyTemplate); err != nil {
		return fmt.Errorf("failed to init wrapping key search: %w", err)
	}
	defer b.p11ctx.FindObjectsFinal(session)

	wrappingKeyHandles, _, err := b.p11ctx.FindObjects(session, 1)
	if err != nil {
		return fmt.Errorf("failed to find wrapping key: %w", err)
	}

	if len(wrappingKeyHandles) == 0 {
		return fmt.Errorf("%w: wrapping key not found in HSM", backend.ErrKeyNotFound)
	}

	wrappingKeyHandle := wrappingKeyHandles[0]

	// Create key ID and label
	keyID := []byte(createKeyID(attrs))
	keyLabel := []byte(attrs.CN)

	// Build the key template based on key type
	keyTemplate, err := b.buildImportKeyTemplate(attrs, keyID, keyLabel)
	if err != nil {
		return fmt.Errorf("failed to build key template: %w", err)
	}

	var keyHandle pkcs11.ObjectHandle

	// Determine the unwrapping mechanism based on the wrapping algorithm
	switch wrapped.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		// Direct RSA-OAEP unwrapping (for small keys)
		// Note: This doesn't work with SoftHSM2 for secret keys - use hybrid wrapping instead
		unwrapMechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(
			pkcs11.CKM_SHA256,
			pkcs11.CKG_MGF1_SHA256,
			pkcs11.CKZ_DATA_SPECIFIED,
			[]byte{}, // Empty label to match wrapping.WrapRSAOAEP which uses nil label
		))

		keyHandle, err = b.p11ctx.UnwrapKey(session, []*pkcs11.Mechanism{unwrapMechanism}, wrappingKeyHandle, wrapped.WrappedKey, keyTemplate)
		if err != nil {
			return fmt.Errorf("failed to unwrap key with RSA-OAEP: %w", err)
		}

	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Hybrid unwrapping using two-step process (works with SoftHSM2):
		// 1. Unwrap the AES key using RSA-OAEP
		// 2. Unwrap the target key using the AES key
		keyHandle, err = b.importKeyHybrid(session, attrs, wrapped, wrappingKeyHandle, keyID, keyLabel, keyTemplate)
		if err != nil {
			return fmt.Errorf("failed to import key with hybrid unwrapping: %w", err)
		}

	default:
		return fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, wrapped.Algorithm)
	}

	// Store metadata about the imported key
	metadata := map[string]interface{}{
		"key_handle":    keyHandle,
		"cn":            attrs.CN,
		"key_type":      attrs.KeyType,
		"key_algorithm": attrs.KeyAlgorithm,
		"store_type":    backend.STORE_PKCS11,
		"imported":      true,
	}

	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if b.config.KeyStorage != nil {
		if err := storage.SaveKey(b.config.KeyStorage, attrs.ID(), metadataBytes); err != nil {
			return fmt.Errorf("failed to save metadata: %w", err)
		}
	}

	return nil
}

// importKeyHybrid implements the two-step hybrid unwrapping process for PKCS#11.
// This follows the pattern used by smallstep/pkcs11-key-wrap:
//  1. Parse the wrapped key material to extract wrapped AES key and wrapped target key
//  2. Use C_UnwrapKey with CKM_RSA_PKCS_OAEP to unwrap the AES key into the HSM
//  3. Use C_UnwrapKey with CKM_AES_KEY_WRAP_PAD to unwrap the target key using the AES key
//  4. Destroy the temporary AES key
func (b *Backend) importKeyHybrid(session pkcs11.SessionHandle, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial, wrappingKeyHandle pkcs11.ObjectHandle, keyID, keyLabel []byte, keyTemplate []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	// Parse the hybrid wrapped format: [4-byte length][wrapped AES key][wrapped key material]
	if len(wrapped.WrappedKey) < 4 {
		return 0, fmt.Errorf("wrapped key too short for hybrid format")
	}

	// Extract wrapped AES key length
	wrappedAESKeyLen := uint32(wrapped.WrappedKey[0])<<24 | uint32(wrapped.WrappedKey[1])<<16 | uint32(wrapped.WrappedKey[2])<<8 | uint32(wrapped.WrappedKey[3])

	if len(wrapped.WrappedKey) < int(4+wrappedAESKeyLen) {
		return 0, fmt.Errorf("wrapped key corrupted: insufficient data")
	}

	wrappedAESKey := wrapped.WrappedKey[4 : 4+wrappedAESKeyLen]
	wrappedTargetKey := wrapped.WrappedKey[4+wrappedAESKeyLen:]

	// Step 1: Unwrap the AES key using RSA-OAEP with SHA-256
	// Must match the hash used in wrapping.WrapRSAAES
	var hashMech, mgfMech uint
	switch wrapped.Algorithm {
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		hashMech = pkcs11.CKM_SHA256
		mgfMech = pkcs11.CKG_MGF1_SHA256
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1:
		hashMech = pkcs11.CKM_SHA_1
		mgfMech = pkcs11.CKG_MGF1_SHA1
	default:
		return 0, fmt.Errorf("%w: %s", backend.ErrInvalidAlgorithm, wrapped.Algorithm)
	}

	aesUnwrapMech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(
		hashMech,
		mgfMech,
		pkcs11.CKZ_DATA_SPECIFIED,
		[]byte{},
	))

	aesKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false), // Temporary key
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32), // 256-bit AES key
	}

	aesKeyHandle, err := b.p11ctx.UnwrapKey(session, []*pkcs11.Mechanism{aesUnwrapMech}, wrappingKeyHandle, wrappedAESKey, aesKeyTemplate)
	if err != nil {
		return 0, fmt.Errorf("failed to unwrap AES key: %w", err)
	}

	// Ensure we destroy the temporary AES key when done
	defer b.p11ctx.DestroyObject(session, aesKeyHandle)

	// Step 2: Unwrap the target key using the AES key with AES-KWP
	targetUnwrapMech := pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)

	targetKeyHandle, err := b.p11ctx.UnwrapKey(session, []*pkcs11.Mechanism{targetUnwrapMech}, aesKeyHandle, wrappedTargetKey, keyTemplate)
	if err != nil {
		return 0, fmt.Errorf("failed to unwrap target key with AES-KWP: %w", err)
	}

	return targetKeyHandle, nil
}

// buildImportKeyTemplate builds the PKCS#11 attribute template for importing a key.
func (b *Backend) buildImportKeyTemplate(attrs *types.KeyAttributes, keyID, keyLabel []byte) ([]*pkcs11.Attribute, error) {
	var template []*pkcs11.Attribute

	// Add key-type-specific attributes
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		}

	case x509.ECDSA:
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_ECDSA),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		}

	default:
		// Check for symmetric algorithms
		switch attrs.SymmetricAlgorithm {
		case types.SymmetricAES128GCM, types.SymmetricAES192GCM, types.SymmetricAES256GCM:
			// Determine key length in bytes
			var keyLen int
			switch attrs.SymmetricAlgorithm {
			case types.SymmetricAES128GCM:
				keyLen = 16 // 128 bits
			case types.SymmetricAES192GCM:
				keyLen = 24 // 192 bits
			case types.SymmetricAES256GCM:
				keyLen = 32 // 256 bits
			}

			// For secret keys being unwrapped, use minimal required attributes
			// Some HSMs are strict about which attributes can be set during C_UnwrapKey
			template = []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, keyLen), // Required for C_UnwrapKey
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
				pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
				pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
				pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			}
		default:
			return nil, fmt.Errorf("%w: unsupported key algorithm for import: %v (symmetric: %v)", backend.ErrInvalidAlgorithm, attrs.KeyAlgorithm, attrs.SymmetricAlgorithm)
		}
	}

	return template, nil
}

// ExportKey exports a key in wrapped form for secure transport.
// This method checks if the key has the CKA_EXTRACTABLE attribute set to true.
// If the key is extractable, it uses the PKCS#11 C_WrapKey function to export it
// using the HSM's wrapping key.
//
// Security considerations:
//   - Only keys marked as exportable (attrs.Exportable=true) can be exported
//   - The exported key is wrapped using the HSM's wrapping key
//   - Keys imported with CKA_EXTRACTABLE=false cannot be exported
//   - The export operation happens entirely within the HSM for maximum security
func (b *Backend) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Check if backend supports export
	if !b.Capabilities().Export {
		return nil, backend.ErrExportNotSupported
	}

	// Check if key is marked as exportable
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ctx == nil {
		return nil, ErrNotInitialized
	}

	// Initialize low-level PKCS#11 context if not already done
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return nil, fmt.Errorf("failed to load PKCS#11 library: %s", b.config.Library)
		}

		if err := p.Initialize(); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
			}
		}

		b.p11ctx = p
	}

	// Get token slot
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return nil, ErrTokenNotFound
	}

	slot := slots[0]
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Login as user (only logout if we performed the login)
	var didLogin bool
	if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return nil, fmt.Errorf("failed to login: %w", err)
		}
		// Already logged in, don't logout later
		didLogin = false
	} else {
		// We logged in successfully, logout when done
		didLogin = true
	}
	if didLogin {
		defer b.p11ctx.Logout(session)
	}

	// Find the key to export
	keyID := []byte(createKeyID(attrs))
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(attrs.CN)),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	}

	if err := b.p11ctx.FindObjectsInit(session, keyTemplate); err != nil {
		return nil, fmt.Errorf("failed to init key search: %w", err)
	}
	defer b.p11ctx.FindObjectsFinal(session)

	keyHandles, _, err := b.p11ctx.FindObjects(session, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	if len(keyHandles) == 0 {
		return nil, fmt.Errorf("%w: %s", backend.ErrKeyNotFound, attrs.CN)
	}

	keyHandle := keyHandles[0]

	// Check if key is extractable (CKA_EXTRACTABLE attribute in HSM)
	// This provides defense-in-depth: we check attrs.Exportable above (policy),
	// and CKA_EXTRACTABLE here (actual HSM capability)
	extractableAttr, err := b.p11ctx.GetAttributeValue(session, keyHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get extractable attribute: %w", err)
	}

	if len(extractableAttr) == 0 || len(extractableAttr[0].Value) == 0 {
		return nil, fmt.Errorf("failed to determine if key is extractable")
	}

	isExtractable := extractableAttr[0].Value[0] != 0
	if !isExtractable {
		return nil, backend.ErrKeyNotExportable
	}

	// Find the wrapping key
	wrappingKeyID := []byte(wrappingKeyLabel)
	wrappingKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, wrappingKeyID),
	}

	if err := b.p11ctx.FindObjectsInit(session, wrappingKeyTemplate); err != nil {
		return nil, fmt.Errorf("failed to init wrapping key search: %w", err)
	}
	defer b.p11ctx.FindObjectsFinal(session)

	wrappingKeyHandles, _, err := b.p11ctx.FindObjects(session, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to find wrapping key: %w", err)
	}

	if len(wrappingKeyHandles) == 0 {
		return nil, fmt.Errorf("%w: wrapping key not found in HSM", backend.ErrKeyNotFound)
	}

	wrappingKeyHandle := wrappingKeyHandles[0]

	// Determine the wrapping mechanism
	var wrapMechanism *pkcs11.Mechanism
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		wrapMechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(
			pkcs11.CKM_SHA256,
			pkcs11.CKG_MGF1_SHA256,
			pkcs11.CKZ_DATA_SPECIFIED,
			[]byte{}, // Empty label for consistency
		))

	default:
		return nil, fmt.Errorf("%w: %s for export", backend.ErrInvalidAlgorithm, algorithm)
	}

	// Wrap the key using C_WrapKey
	wrappedKey, err := b.p11ctx.WrapKey(session, []*pkcs11.Mechanism{wrapMechanism}, wrappingKeyHandle, keyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap key: %w", err)
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrappedKey,
		Algorithm:   algorithm,
		ImportToken: wrappingKeyID,
		Metadata:    make(map[string]string),
	}, nil
}

// generateWrappingKeyPair generates an RSA key pair with wrap/unwrap/encrypt/decrypt capabilities.
// This is used for import/export operations and needs specific attributes that crypto11 doesn't set by default.
//
// This function uses the low-level PKCS#11 C_GenerateKeyPair API to set all required attributes:
// - CKA_WRAP, CKA_UNWRAP: For key wrapping operations
// - CKA_ENCRYPT, CKA_DECRYPT: For encryption/decryption
// - CKA_TOKEN: To store the key permanently in the HSM
// - CKA_PRIVATE, CKA_SENSITIVE: For private key security
// - CKA_EXTRACTABLE: Set to false to prevent key extraction
//
// After generating the key with proper attributes, we retrieve it using crypto11's FindKeyPair
// to get a proper crypto11.Signer that can be used with the rest of the system.
func (b *Backend) generateWrappingKeyPair(keyID []byte) (crypto11.Signer, error) {
	// Initialize low-level PKCS#11 context if not already done
	if b.p11ctx == nil {
		p := pkcs11.New(b.config.Library)
		if p == nil {
			return nil, fmt.Errorf("failed to load PKCS#11 library: %s", b.config.Library)
		}

		if err := p.Initialize(); err != nil {
			if err != pkcs11.Error(pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				return nil, fmt.Errorf("failed to initialize PKCS#11: %w", err)
			}
		}

		b.p11ctx = p
	}

	// Get token slot
	slots, err := b.p11ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}

	if len(slots) == 0 {
		return nil, ErrTokenNotFound
	}

	slot := slots[0]
	if b.config.Slot != nil {
		slot = uint(*b.config.Slot)
	}

	// Open session
	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}
	defer b.p11ctx.CloseSession(session)

	// Login as user (only logout if we performed the login)
	var didLogin bool
	if err := b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN); err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return nil, fmt.Errorf("failed to login: %w", err)
		}
		// Already logged in, don't logout later
		didLogin = false
	} else {
		// We logged in successfully, logout when done
		didLogin = true
	}
	if didLogin {
		defer b.p11ctx.Logout(session)
	}

	// Build public key template with wrap/verify capabilities
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, wrappingKeySize),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}), // 65537
	}

	// Build private key template with wrap/unwrap capabilities
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	}

	// RSA key generation mechanism
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)

	// Generate the key pair using low-level C_GenerateKeyPair
	_, _, err = b.p11ctx.GenerateKeyPair(session, []*pkcs11.Mechanism{mechanism}, publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair with C_GenerateKeyPair: %w", err)
	}

	// Now retrieve the generated key using crypto11's FindKeyPair
	// This returns a proper crypto11.Signer that can be used throughout the system
	signer, err := b.ctx.FindKeyPair(keyID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to find generated wrapping key: %w", err)
	}

	if signer == nil {
		return nil, fmt.Errorf("wrapping key not found after generation")
	}

	return signer, nil
}

// determineKeySpec determines the key spec string from key attributes.
func determineKeySpec(attrs *types.KeyAttributes) string {
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if attrs.RSAAttributes != nil && attrs.RSAAttributes.KeySize > 0 {
			return fmt.Sprintf("RSA_%d", attrs.RSAAttributes.KeySize)
		}
		return "RSA_2048" // Default
	case x509.ECDSA:
		if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
			// Convert curve to string representation
			curveName := attrs.ECCAttributes.Curve.Params().Name
			return fmt.Sprintf("EC_%s", curveName)
		}
		return "EC_P256" // Default
	default:
		// Check symmetric algorithms
		switch attrs.SymmetricAlgorithm {
		case types.SymmetricAES128GCM:
			return "AES_128"
		case types.SymmetricAES192GCM:
			return "AES_192"
		case types.SymmetricAES256GCM:
			return "AES_256"
		default:
			return "UNKNOWN"
		}
	}
}

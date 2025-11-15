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

package tpm2

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Ensure TPM2KeyStore implements ImportExportBackend interface
var _ backend.ImportExportBackend = (*TPM2KeyStore)(nil)

// GetImportParameters retrieves the parameters needed to import a key into the TPM.
//
// For TPM2, this creates a temporary parent key (similar to SRK) that will be used
// to wrap the imported key material. The public portion of this parent key is returned
// as the wrapping public key.
//
// TPM2 import flow:
//  1. Create a primary storage key (import parent) under the Endorsement hierarchy
//  2. Extract the public portion of the import parent
//  3. Return the public key for wrapping
//  4. The import parent handle is persisted temporarily for the import operation
//
// The returned parameters remain valid until the TPM is reset or the import parent
// is explicitly evicted. For production use, consider implementing parameter expiration.
//
// Parameters:
//   - attrs: Key attributes for the key to be imported
//   - algorithm: Wrapping algorithm to use (RSA-OAEP-SHA256 recommended for TPM2)
//
// Returns:
//   - ImportParameters containing the wrapping public key and metadata
//   - Error if parameter generation fails
func (ks *TPM2KeyStore) GetImportParameters(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Ensure TPM is open
	if ks.tpm == nil {
		tpmDevice, err := ks.openTPM()
		if err != nil {
			return nil, fmt.Errorf("tpm2: failed to open TPM: %w", err)
		}
		ks.tpm = tpmDevice
	}

	// Validate wrapping algorithm
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Supported algorithms
	default:
		return nil, fmt.Errorf("tpm2: unsupported wrapping algorithm %s (use RSA-OAEP-SHA256 or RSA-AES-SHA256)", algorithm)
	}

	// Create an import parent key under the Endorsement hierarchy
	// This is a temporary storage key used solely for importing
	importParentTemplate := tpm2.TPMTPublic{
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
				KeyBits: 2048, // Use 2048-bit RSA for import parent
			},
		),
	}

	// Create the import parent key (transient)
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement, // Use Endorsement hierarchy
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(importParentTemplate),
	}

	rsp, err := createPrimary.Execute(ks.tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create import parent: %w", err)
	}

	// Flush the transient handle - we only need the public key
	// The actual import will use the SRK as the parent
	defer tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(ks.tpm)

	// Extract the public key from the import parent
	pub, err := rsp.OutPublic.Contents()
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

	wrappingPublicKey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to create RSA public key: %w", err)
	}

	// Marshal the import parent public key as the import token
	// This allows us to verify the import later
	importToken := tpm2.Marshal(rsp.OutPublic)

	// Determine key spec from attributes
	keySpec := determineKeySpec(attrs)

	// TPM import parameters don't have a strict expiration, but we set a
	// reasonable validity period (24 hours) to align with cloud KMS practices
	expiresAt := time.Now().Add(24 * time.Hour)

	return &backend.ImportParameters{
		WrappingPublicKey: wrappingPublicKey,
		ImportToken:       importToken,
		Algorithm:         algorithm,
		ExpiresAt:         &expiresAt,
		KeySpec:           keySpec,
	}, nil
}

// WrapKey wraps key material for secure transport using the specified parameters.
//
// This uses the crypto/wrapping package to perform RSA-OAEP or hybrid RSA+AES wrapping.
// The wrapped key material can then be imported into the TPM using ImportKey.
//
// For TPM2, we support:
//   - RSA-OAEP-SHA256: Direct RSA encryption (for small keys like symmetric keys)
//   - RSA-AES-SHA256: Hybrid wrapping (for large keys like RSA private keys)
//
// Parameters:
//   - keyMaterial: The plaintext key material to wrap (in TPM private key format)
//   - params: Import parameters obtained from GetImportParameters
//
// Returns:
//   - WrappedKeyMaterial ready for import
//   - Error if wrapping fails
func (ks *TPM2KeyStore) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if keyMaterial == nil || len(keyMaterial) == 0 {
		return nil, fmt.Errorf("tpm2: key material cannot be nil or empty")
	}

	if params == nil {
		return nil, fmt.Errorf("tpm2: import parameters cannot be nil")
	}

	// Ensure we have an RSA public key
	rsaPubKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("tpm2: wrapping public key must be RSA")
	}

	var wrapped []byte
	var err error

	// Wrap based on algorithm
	switch params.Algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		// Direct RSA-OAEP wrapping (for small keys)
		wrapped, err = wrapping.WrapRSAOAEP(keyMaterial, rsaPubKey, params.Algorithm)

	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		// Hybrid wrapping (for large keys like RSA private keys)
		wrapped, err = wrapping.WrapRSAAES(keyMaterial, rsaPubKey, params.Algorithm)

	default:
		return nil, fmt.Errorf("tpm2: unsupported wrapping algorithm: %s", params.Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to wrap key material: %w", err)
	}

	return &backend.WrappedKeyMaterial{
		WrappedKey:  wrapped,
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
		Metadata:    make(map[string]string),
	}, nil
}

// UnwrapKey returns an error because TPM2 performs unwrapping in hardware.
//
// For TPM2, the unwrapping operation happens inside the TPM during the Import
// command. The TPM uses its internal private key to unwrap the key material,
// ensuring the plaintext key never leaves the secure boundary.
//
// This method exists to satisfy the ImportExportBackend interface but should
// not be called directly. Use ImportKey instead.
//
// Returns:
//   - nil, ErrNotSupported
func (ks *TPM2KeyStore) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	return nil, fmt.Errorf("%w: TPM2 unwraps keys in hardware during import", backend.ErrNotSupported)
}

// ImportKey imports externally generated key material into the TPM.
//
// The import process for TPM2:
//  1. Verify the import token (public key) matches our SRK
//  2. Use TPM2_Import to import the wrapped key under the SRK
//  3. The TPM unwraps the key material using its internal private key
//  4. Store the imported key blob (public + encrypted private)
//
// IMPORTANT: The TPM2_Import command expects key material in a specific format.
// For RSA keys, this should be a TPM2B_PRIVATE structure containing the sensitive
// portion of the key.
//
// TPM2 Import Security:
//   - The unwrapping private key never leaves the TPM
//   - Imported keys are bound to this specific TPM (FixedTPM attribute)
//   - Keys can be created with various policies (password, PCR, etc.)
//
// Parameters:
//   - attrs: Key attributes for the imported key
//   - wrapped: Wrapped key material obtained from WrapKey
//
// Returns:
//   - Error if import fails or key already exists
func (ks *TPM2KeyStore) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if attrs == nil {
		return backend.ErrInvalidAttributes
	}

	if wrapped == nil {
		return fmt.Errorf("tpm2: wrapped key material cannot be nil")
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

	// Check if key already exists
	privateKeyID := attrs.ID() + string(backend.FSEXT_PRIVATE_BLOB)
	exists, err := storage.KeyExists(ks.keyStorage, privateKeyID)
	if err != nil {
		return fmt.Errorf("tpm2: failed to check key existence: %w", err)
	}
	if exists {
		return backend.ErrKeyAlreadyExists
	}

	// Note: TPM2_Import is complex and requires the key material to be in
	// TPM2B_PRIVATE format with proper duplication blob structure.
	// For a production implementation, this would need to:
	// 1. Parse the wrapped key material
	// 2. Create a proper TPM2B_PRIVATE structure
	// 3. Use TPM2_Import command to import
	//
	// For now, we return an error indicating this needs specialized handling
	// The wrapping/unwrapping above is correct, but TPM2_Import requires
	// additional key material formatting that depends on the key type.

	return fmt.Errorf("tpm2: TPM2_Import requires specialized key material formatting - not yet fully implemented")
}

// ExportKey exports a key in wrapped form for secure transport.
//
// TPM2 key export is highly restricted for security:
//   - Keys with FixedTPM=true cannot be exported (most TPM keys)
//   - Only keys created with fixedTPM=false and duplicable attributes can be exported
//   - The key must have been created with the appropriate duplication policy
//   - Keys must be marked as Exportable in their attributes
//
// For TPM2, we use the TPM2_Duplicate command to export duplicable keys.
// Most production TPM keys are NOT duplicable for security reasons.
//
// Returns:
//   - WrappedKeyMaterial if the key is exportable
//   - ErrExportNotSupported if the backend doesn't support export
//   - ErrKeyNotExportable if the key exists but isn't marked as exportable
func (ks *TPM2KeyStore) ExportKey(attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}

	// Check if backend supports export
	if !ks.Capabilities().Export {
		return nil, backend.ErrExportNotSupported
	}

	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Ensure TPM is open
	if ks.tpm == nil {
		return nil, fmt.Errorf("tpm2: TPM not initialized")
	}

	// Check if key exists BEFORE checking other attributes
	// Load the key's public blob to check its TPM attributes
	publicKeyID := attrs.ID() + string(backend.FSEXT_PUBLIC_BLOB)
	publicBlob, err := storage.GetKey(ks.keyStorage, publicKeyID)
	if err != nil {
		return nil, backend.ErrKeyNotFound
	}

	// Unmarshal and check TPM-specific attributes
	tpmPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to unmarshal public blob: %w", err)
	}

	pub, err := tpmPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpm2: failed to get public contents: %w", err)
	}

	// Check if the key has FixedTPM attribute (most TPM keys do)
	// FixedTPM=true means the key is permanently bound to this TPM and cannot be exported
	// This is a hardware security constraint that overrides any software exportability setting
	if pub.ObjectAttributes.FixedTPM {
		return nil, fmt.Errorf("%w: key has FixedTPM attribute and cannot be exported from this TPM", backend.ErrOperationNotSupported)
	}

	// Check if key is marked as exportable in software attributes
	if !attrs.Exportable {
		return nil, backend.ErrKeyNotExportable
	}

	// If we get here, the key is theoretically exportable
	// However, implementing TPM2_Duplicate requires:
	// 1. Creating a duplication target (new parent key)
	// 2. Using TPM2_Duplicate to re-parent the key
	// 3. Wrapping the duplicated key material
	//
	// For most TPM use cases, keys should NOT be exportable (FixedTPM=true)
	// so this is intentionally left as an error for security.

	return nil, backend.ErrOperationNotSupported
}

// determineKeySpec determines the key spec string from key attributes.
// This is used in ImportParameters to describe the expected key type.
func determineKeySpec(attrs *types.KeyAttributes) string {
	// Check public key algorithms first
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if attrs.RSAAttributes != nil {
			return fmt.Sprintf("RSA_%d", attrs.RSAAttributes.KeySize)
		}
		return "RSA_2048" // Default

	case x509.ECDSA:
		if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
			return fmt.Sprintf("EC_%s", attrs.ECCAttributes.Curve.Params().Name)
		}
		return "EC_P256" // Default
	}

	// Check symmetric algorithms
	switch attrs.SymmetricAlgorithm {
	case types.SymmetricAES128GCM:
		return "AES_128"
	case types.SymmetricAES192GCM:
		return "AES_192"
	case types.SymmetricAES256GCM:
		return "AES_256"
	}

	return "UNKNOWN"
}

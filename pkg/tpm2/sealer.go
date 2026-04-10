package tpm2

import (
	"context"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// KeyBackend is an alias for store.KeyBackend for cleaner internal use
type KeyBackend = store.KeyBackend

// Ensure TPM2 implements types.Sealer interface
var _ types.Sealer = (*TPM2)(nil)

// CanSeal returns true if this TPM backend supports sealing operations.
// TPM2 always supports sealing when properly initialized.
func (tpm *TPM2) CanSeal() bool {
	return tpm.transport != nil
}

// defaultSealKeyAttributes returns sensible default KeyAttributes for sealing
// when the caller does not provide explicit KeyAttributes. It uses the Platform
// Storage Root Key (Platform SRK) as the parent with a deterministic CN so the
// same sealing key is reused across operations instead of creating a new key
// per seal.
func (tpm *TPM2) defaultSealKeyAttributes() (*types.KeyAttributes, error) {
	srkAttrs, err := tpm.PlatformSRKAttributes()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPlatformSRKConfiguration, err)
	}
	return &types.KeyAttributes{
		CN:     "platform-sealing-key",
		Parent: srkAttrs,
	}, nil
}

// defaultUnsealKeyAttributes returns sensible default KeyAttributes for unsealing
// when the caller does not provide explicit KeyAttributes. It uses the Platform
// Storage Root Key (Platform SRK) as the parent and sets the CN from the sealed
// data's KeyID (which was assigned during the original Seal operation).
func (tpm *TPM2) defaultUnsealKeyAttributes(keyID string) (*types.KeyAttributes, error) {
	srkAttrs, err := tpm.PlatformSRKAttributes()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPlatformSRKConfiguration, err)
	}
	return &types.KeyAttributes{
		CN:     keyID,
		Parent: srkAttrs,
	}, nil
}

// Seal encrypts/protects data using the TPM's sealing mechanism.
// The data is sealed to the current PCR state (if PlatformPolicy is enabled)
// and can only be unsealed when the same PCR values are present.
//
// When opts is nil or opts.KeyAttributes is nil, sensible defaults are provided
// using the Platform Storage Root Key (Platform SRK) as the parent hierarchy.
// This allows callers such as the barrier's TPM2Strategy to seal data without
// needing to know TPM-specific key hierarchy details.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - data: The plaintext data to seal
//   - opts: Sealing options (optional; defaults provided if nil)
//
// Returns SealedData containing the TPM public/private areas, or error.
func (tpm *TPM2) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if opts == nil {
		opts = &types.SealOptions{}
	}

	if opts.KeyAttributes == nil {
		defaultAttrs, err := tpm.defaultSealKeyAttributes()
		if err != nil {
			return nil, err
		}
		opts.KeyAttributes = defaultAttrs
	}

	keyAttrs := opts.KeyAttributes

	// Set the seal data on the key attributes
	if data != nil {
		keyAttrs.SealData = types.NewSealData(data)
	}

	// Apply TPM policy if provided
	if opts.TPMPolicy != nil {
		if keyAttrs.TPMAttributes == nil {
			keyAttrs.TPMAttributes = &types.TPMAttributes{}
		}
		keyAttrs.TPMAttributes.PCRSelection = opts.TPMPolicy.PCRSelection
		keyAttrs.TPMAttributes.HashAlg = opts.TPMPolicy.HashAlg

		// Set auth policy if provided
		if len(opts.TPMPolicy.AuthPolicy) > 0 {
			template := KeyedHashTemplate
			template.AuthPolicy = tpm2.TPM2BDigest{Buffer: opts.TPMPolicy.AuthPolicy}
			keyAttrs.TPMAttributes.Template = template
		}
	}

	// Get the backend - use opts.Backend if provided, otherwise use TPM instance backend
	backend := tpm.backend
	if opts.Backend != nil {
		if kb, ok := opts.Backend.(store.KeyBackend); ok {
			backend = kb
		} else {
			return nil, ErrInvalidSealBackend
		}
	}
	if backend == nil {
		return nil, ErrNoStorageBackend
	}

	// Call the internal seal operation
	sealResponse, err := tpm.SealKey(keyAttrs, backend, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSealFailed, err)
	}

	// Marshal the TPM public area
	publicBytes := sealResponse.OutPublic.Bytes()

	// Build the sealed data result
	sealed := &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		Ciphertext: nil, // TPM sealing doesn't produce traditional ciphertext
		TPMPublic:  publicBytes,
		TPMPrivate: sealResponse.OutPrivate.Buffer,
		KeyID:      keyAttrs.CN,
		Metadata:   make(map[string][]byte),
	}

	// Store additional metadata
	if keyAttrs.TPMAttributes != nil && keyAttrs.TPMAttributes.Handle != 0 {
		sealed.Metadata["tpm:handle"] = []byte(fmt.Sprintf("0x%x", keyAttrs.TPMAttributes.Handle))
	}

	return sealed, nil
}

// Unseal decrypts/recovers data using the TPM's unsealing mechanism.
// For TPM backends, this requires the same PCR state as when the data was sealed.
//
// When opts is nil or opts.KeyAttributes is nil, sensible defaults are provided
// using the Platform Storage Root Key (Platform SRK) as the parent hierarchy and
// the sealed data's KeyID as the CN. This allows callers such as the barrier's
// TPM2Strategy to unseal data without needing to know TPM-specific details.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - sealed: The sealed data from a previous Seal operation (TPMPublic/TPMPrivate used if set)
//   - opts: Unsealing options (optional; defaults provided if nil)
//
// Returns the original plaintext data, or error if unsealing fails.
//
// If sealed.TPMPublic and sealed.TPMPrivate are provided, they will be used directly
// instead of reading from backend storage. This allows unsealing from in-memory blobs
// without requiring prior storage of the sealed data.
func (tpm *TPM2) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, ErrNilSealedData
	}

	if sealed.Backend != types.BackendTypeTPM2 {
		return nil, fmt.Errorf("%w: got %s", ErrSealedDataBackendMismatch, sealed.Backend)
	}

	if opts == nil {
		opts = &types.UnsealOptions{}
	}

	if opts.KeyAttributes == nil {
		defaultAttrs, err := tpm.defaultUnsealKeyAttributes(sealed.KeyID)
		if err != nil {
			return nil, err
		}
		opts.KeyAttributes = defaultAttrs
	}

	keyAttrs := opts.KeyAttributes

	// Ensure Parent (SRK) is set when caller provides KeyAttributes without it.
	// This happens when KeyAttributes are parsed from a stored KeyID string
	// which doesn't include the TPM key hierarchy.
	if keyAttrs.Parent == nil {
		srkAttrs, err := tpm.PlatformSRKAttributes()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidPlatformSRKConfiguration, err)
		}
		keyAttrs.Parent = srkAttrs
	}

	// Apply password if provided
	if opts.Password != nil {
		keyAttrs.Password = opts.Password
	}

	// If TPMPublic and TPMPrivate blobs are provided in sealed data, use them directly
	// instead of reading from backend storage. This enables unsealing from in-memory
	// blobs (e.g., loaded from EFI partition files during boot).
	if len(sealed.TPMPublic) > 0 && len(sealed.TPMPrivate) > 0 {
		tpm.logger.Debug("unseal: using provided TPMPublic/TPMPrivate blobs directly")
		return tpm.unsealFromBlobs(keyAttrs, sealed.TPMPublic, sealed.TPMPrivate)
	}

	// Fall back to reading from backend storage
	backend := tpm.backend
	if opts.Backend != nil {
		if kb, ok := opts.Backend.(store.KeyBackend); ok {
			backend = kb
		} else {
			return nil, ErrInvalidSealBackend
		}
	}
	if backend == nil {
		return nil, ErrNoStorageBackend
	}

	// Call the internal unseal operation
	plaintext, err := tpm.UnsealKey(keyAttrs, backend)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsealFailed, err)
	}

	return plaintext, nil
}

// SealKey is the internal method that creates a sealed keyed hash key.
// This is the original Seal() implementation renamed for clarity.
// It creates a new key under the provided Storage Root Key (SRK),
// optionally sealing a provided secret to the current Platform
// Golden Integrity Measurements.
func (tpm *TPM2) SealKey(
	keyAttrs *types.KeyAttributes,
	backend KeyBackend,
	overwrite bool) (*tpm2.CreateResponse, error) {

	// Delegate to the existing implementation in seal.go
	return tpm.sealKeyInternal(keyAttrs, backend, overwrite)
}

// UnsealKey is the internal method that returns sealed data for a keyed hash.
// This is the original Unseal() implementation renamed for clarity.
// It uses the platform PCR Policy Session to satisfy the TPM to release the secret.
func (tpm *TPM2) UnsealKey(
	keyAttrs *types.KeyAttributes,
	backend KeyBackend) ([]byte, error) {

	// Delegate to the existing implementation in seal.go
	return tpm.unsealKeyInternal(keyAttrs, backend)
}

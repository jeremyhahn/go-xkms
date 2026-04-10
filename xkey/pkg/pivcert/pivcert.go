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

// Package pivcert provides PIV (Personal Identity Verification) certificate storage abstraction.
//
// The package implements a pluggable certificate storage layer that operates independently
// from key backend infrastructure while maintaining seamless integration. It supports
// multiple storage backends including file system, TPM2 NV storage, and PKCS#11 tokens.
//
// Key features:
//   - Clean separation between key operations and certificate storage
//   - Support for PIV standard slots (9a, 9c, 9d, 9e) and retired key slots
//   - Thread-safe implementations with comprehensive error handling
//   - PEM and DER certificate format support
//   - Consistent with go-xkms architecture patterns
//
// Example usage:
//
//	backend := storage.NewMemory() // or file.New("/var/lib/xkey/piv")
//	config := &pivcert.PIVConfig{
//	    StorageType: pivcert.StorageTypeFile,
//	    FileConfig: &pivcert.FileStorageConfig{
//	        Backend:    backend,
//	        DEREnabled: true,
//	        PEMEnabled: true,
//	    },
//	}
//
//	storage, err := pivcert.NewPIVCertificateStorage(config)
//	if err != nil {
//	    return err
//	}
//	defer storage.Close()
//
//	err = storage.Store(pivcert.PIVSlotAuthentication, cert)
package pivcert

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// PIVStorageType identifies the certificate storage backend type.
type PIVStorageType string

const (
	// StorageTypeFile stores certificates on the file system.
	StorageTypeFile PIVStorageType = "file"

	// StorageTypeTPM2 stores certificates in TPM2 NV (Non-Volatile) storage.
	StorageTypeTPM2 PIVStorageType = "tpm2"

	// StorageTypePKCS11 stores certificates in PKCS#11 token storage.
	StorageTypePKCS11 PIVStorageType = "pkcs11"
)

// String returns the string representation of the storage type.
func (t PIVStorageType) String() string {
	return string(t)
}

// IsValid checks if the storage type is a recognized value.
func (t PIVStorageType) IsValid() bool {
	switch t {
	case StorageTypeFile, StorageTypeTPM2, StorageTypePKCS11:
		return true
	default:
		return false
	}
}

// PIVSlot represents a PIV certificate slot identifier.
// PIV slots are defined by NIST SP 800-73-4 and identify specific certificate purposes.
type PIVSlot string

const (
	// PIVSlotAuthentication is the PIV Authentication slot (9a).
	// Used for PIV card and cardholder authentication.
	PIVSlotAuthentication PIVSlot = "9a"

	// PIVSlotDigitalSignature is the Digital Signature slot (9c).
	// Used for document signing and non-repudiation.
	PIVSlotDigitalSignature PIVSlot = "9c"

	// PIVSlotKeyManagement is the Key Management slot (9d).
	// Used for key establishment and key transport.
	PIVSlotKeyManagement PIVSlot = "9d"

	// PIVSlotCardAuthentication is the Card Authentication slot (9e).
	// Used for card authentication without cardholder interaction.
	PIVSlotCardAuthentication PIVSlot = "9e"

	// PIVSlotAttestation is the Attestation Certificate slot (f9).
	// Used for device attestation certificates proving key origin (YubiKey-compatible).
	PIVSlotAttestation PIVSlot = "f9"

	// Retired Key Management slots (82-95)
	// These slots store historical key management certificates for decryption of old data.

	// PIVSlotRetired1 is Retired Key Management slot 1 (82).
	PIVSlotRetired1 PIVSlot = "82"

	// PIVSlotRetired2 is Retired Key Management slot 2 (83).
	PIVSlotRetired2 PIVSlot = "83"

	// PIVSlotRetired3 is Retired Key Management slot 3 (84).
	PIVSlotRetired3 PIVSlot = "84"

	// PIVSlotRetired4 is Retired Key Management slot 4 (85).
	PIVSlotRetired4 PIVSlot = "85"

	// PIVSlotRetired5 is Retired Key Management slot 5 (86).
	PIVSlotRetired5 PIVSlot = "86"

	// PIVSlotRetired6 is Retired Key Management slot 6 (87).
	PIVSlotRetired6 PIVSlot = "87"

	// PIVSlotRetired7 is Retired Key Management slot 7 (88).
	PIVSlotRetired7 PIVSlot = "88"

	// PIVSlotRetired8 is Retired Key Management slot 8 (89).
	PIVSlotRetired8 PIVSlot = "89"

	// PIVSlotRetired9 is Retired Key Management slot 9 (8a).
	PIVSlotRetired9 PIVSlot = "8a"

	// PIVSlotRetired10 is Retired Key Management slot 10 (8b).
	PIVSlotRetired10 PIVSlot = "8b"

	// PIVSlotRetired11 is Retired Key Management slot 11 (8c).
	PIVSlotRetired11 PIVSlot = "8c"

	// PIVSlotRetired12 is Retired Key Management slot 12 (8d).
	PIVSlotRetired12 PIVSlot = "8d"

	// PIVSlotRetired13 is Retired Key Management slot 13 (8e).
	PIVSlotRetired13 PIVSlot = "8e"

	// PIVSlotRetired14 is Retired Key Management slot 14 (8f).
	PIVSlotRetired14 PIVSlot = "8f"

	// PIVSlotRetired15 is Retired Key Management slot 15 (90).
	PIVSlotRetired15 PIVSlot = "90"

	// PIVSlotRetired16 is Retired Key Management slot 16 (91).
	PIVSlotRetired16 PIVSlot = "91"

	// PIVSlotRetired17 is Retired Key Management slot 17 (92).
	PIVSlotRetired17 PIVSlot = "92"

	// PIVSlotRetired18 is Retired Key Management slot 18 (93).
	PIVSlotRetired18 PIVSlot = "93"

	// PIVSlotRetired19 is Retired Key Management slot 19 (94).
	PIVSlotRetired19 PIVSlot = "94"

	// PIVSlotRetired20 is Retired Key Management slot 20 (95).
	PIVSlotRetired20 PIVSlot = "95"
)

// String returns the string representation of the slot.
func (s PIVSlot) String() string {
	return string(s)
}

// validSlots is the set of all valid PIV slot identifiers.
var validSlots = map[PIVSlot]struct{}{
	PIVSlotAuthentication:     {},
	PIVSlotDigitalSignature:   {},
	PIVSlotKeyManagement:      {},
	PIVSlotCardAuthentication: {},
	PIVSlotAttestation:        {},
	PIVSlotRetired1:           {},
	PIVSlotRetired2:           {},
	PIVSlotRetired3:           {},
	PIVSlotRetired4:           {},
	PIVSlotRetired5:           {},
	PIVSlotRetired6:           {},
	PIVSlotRetired7:           {},
	PIVSlotRetired8:           {},
	PIVSlotRetired9:           {},
	PIVSlotRetired10:          {},
	PIVSlotRetired11:          {},
	PIVSlotRetired12:          {},
	PIVSlotRetired13:          {},
	PIVSlotRetired14:          {},
	PIVSlotRetired15:          {},
	PIVSlotRetired16:          {},
	PIVSlotRetired17:          {},
	PIVSlotRetired18:          {},
	PIVSlotRetired19:          {},
	PIVSlotRetired20:          {},
}

// IsValid checks if the slot identifier is a recognized PIV slot.
func (s PIVSlot) IsValid() bool {
	_, ok := validSlots[s]
	return ok
}

// IsPrimarySlot returns true if this is one of the four primary PIV slots (9a, 9c, 9d, 9e).
func (s PIVSlot) IsPrimarySlot() bool {
	switch s {
	case PIVSlotAuthentication, PIVSlotDigitalSignature, PIVSlotKeyManagement, PIVSlotCardAuthentication:
		return true
	default:
		return false
	}
}

// IsRetiredSlot returns true if this is a retired key management slot (82-95).
func (s PIVSlot) IsRetiredSlot() bool {
	return s.IsValid() && !s.IsPrimarySlot() && !s.IsAttestationSlot()
}

// IsAttestationSlot returns true if this is the attestation certificate slot (f9).
func (s PIVSlot) IsAttestationSlot() bool {
	return s == PIVSlotAttestation
}

// ValidateSlot checks if a slot identifier is valid.
// Returns ErrInvalidSlot if the slot is not recognized.
func ValidateSlot(slot PIVSlot) error {
	if !slot.IsValid() {
		return ErrInvalidSlot
	}
	return nil
}

// CertFormat specifies the certificate encoding format.
type CertFormat int

const (
	// FormatDER is the DER (Distinguished Encoding Rules) binary format.
	FormatDER CertFormat = iota

	// FormatPEM is the PEM (Privacy-Enhanced Mail) text format with base64 encoding.
	FormatPEM
)

// String returns the string representation of the certificate format.
func (f CertFormat) String() string {
	switch f {
	case FormatDER:
		return "DER"
	case FormatPEM:
		return "PEM"
	default:
		return "unknown"
	}
}

// IsValid checks if the format is a recognized certificate format.
func (f CertFormat) IsValid() bool {
	switch f {
	case FormatDER, FormatPEM:
		return true
	default:
		return false
	}
}

// PIVSlotInfo contains metadata about a certificate stored in a PIV slot.
type PIVSlotInfo struct {
	// Slot is the PIV slot identifier.
	Slot PIVSlot

	// Subject is the certificate subject common name or distinguished name.
	Subject string

	// Issuer is the certificate issuer common name or distinguished name.
	Issuer string

	// SerialNumber is the certificate serial number in hexadecimal format.
	SerialNumber string

	// NotBefore is the certificate validity start time formatted as RFC3339.
	NotBefore string

	// NotAfter is the certificate validity end time formatted as RFC3339.
	NotAfter string

	// Algorithm is the public key algorithm (e.g., "RSA", "ECDSA", "Ed25519").
	Algorithm string

	// KeySize is the key size in bits (e.g., 2048 for RSA, 256 for ECDSA P-256).
	KeySize int

	// Fingerprint is the SHA-256 fingerprint of the certificate in hexadecimal.
	Fingerprint string

	// StoredAt is the timestamp when the certificate was stored.
	StoredAt time.Time
}

// SlotMetadata contains static information about a PIV slot.
type SlotMetadata struct {
	// Slot is the PIV slot identifier.
	Slot PIVSlot

	// Name is the human-readable slot name.
	Name string

	// Description provides a detailed description of the slot's purpose.
	Description string

	// KeyUsage specifies the allowed key usage for certificates in this slot.
	KeyUsage x509.KeyUsage

	// ExtKeyUsage specifies the allowed extended key usage for certificates in this slot.
	ExtKeyUsage []x509.ExtKeyUsage

	// MaxCertSize is the maximum certificate size in bytes for this slot.
	MaxCertSize int

	// RequiresPIN indicates whether access to this slot requires PIN entry.
	RequiresPIN bool

	// TouchPolicy indicates the touch policy for this slot (if applicable).
	TouchPolicy string
}

// PIVConfig contains configuration for PIV certificate storage.
type PIVConfig struct {
	// StorageType specifies the backend storage type.
	// If empty, defaults to the key backend type.
	StorageType PIVStorageType

	// FileConfig is used when StorageType is StorageTypeFile.
	FileConfig *FileStorageConfig

	// TPM2Config is used when StorageType is StorageTypeTPM2.
	TPM2Config *TPM2StorageConfig

	// PKCS11Config is used when StorageType is StorageTypePKCS11.
	PKCS11Config *PKCS11StorageConfig
}

// Validate checks if the configuration is valid.
func (c *PIVConfig) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	if !c.StorageType.IsValid() {
		return &PIVStorageError{
			Op:  "validate",
			Err: ErrInvalidStorageType,
		}
	}

	switch c.StorageType {
	case StorageTypeFile:
		if c.FileConfig == nil {
			return &PIVStorageError{
				Op:  "validate",
				Err: ErrMissingConfig,
			}
		}
		if err := c.FileConfig.Validate(); err != nil {
			return err
		}
	case StorageTypeTPM2:
		if c.TPM2Config == nil {
			return &PIVStorageError{
				Op:  "validate",
				Err: ErrMissingConfig,
			}
		}
		if err := c.TPM2Config.Validate(); err != nil {
			return err
		}
	case StorageTypePKCS11:
		if c.PKCS11Config == nil {
			return &PIVStorageError{
				Op:  "validate",
				Err: ErrMissingConfig,
			}
		}
		if err := c.PKCS11Config.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// FileStorageConfig contains file backend configuration.
type FileStorageConfig struct {
	// Backend is the storage backend for certificate persistence.
	// This can be any storage.Backend implementation (memory, file, etc.).
	Backend storage.Backend

	// DEREnabled controls whether DER files are written.
	// When true, certificates are stored in binary DER format.
	DEREnabled bool

	// PEMEnabled controls whether PEM files are written.
	// When true, certificates are stored in base64 PEM format.
	PEMEnabled bool
}

// Validate checks if the file storage configuration is valid.
func (c *FileStorageConfig) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	if c.Backend == nil {
		return &PIVStorageError{
			Op:  "validate",
			Err: ErrMissingBackend,
		}
	}

	if !c.DEREnabled && !c.PEMEnabled {
		return &PIVStorageError{
			Op:  "validate",
			Err: ErrNoFormatEnabled,
		}
	}

	return nil
}

// TPM2StorageConfig contains TPM2 NV storage configuration.
type TPM2StorageConfig struct {
	// DevicePath is the path to the TPM device.
	// Common values: /dev/tpmrm0 (resource manager), /dev/tpm0 (direct).
	DevicePath string

	// BaseIndex is the starting NV index for certificates.
	// Default: 0x01C00100 (within the NV_INDEX_FIRST range).
	BaseIndex uint32

	// OwnerAuth is the TPM owner authorization value.
	// This is required for NV operations on most TPM configurations.
	OwnerAuth string

	// UseResourceManager indicates whether to use the TPM resource manager.
	UseResourceManager bool
}

// DefaultTPM2BaseIndex is the default starting NV index for PIV certificates.
const DefaultTPM2BaseIndex uint32 = 0x01C00100

// Validate checks if the TPM2 storage configuration is valid.
func (c *TPM2StorageConfig) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	if c.DevicePath == "" {
		return &PIVStorageError{
			Op:  "validate",
			Err: ErrMissingDevicePath,
		}
	}

	return nil
}

// PKCS11StorageConfig contains PKCS#11 storage configuration.
type PKCS11StorageConfig struct {
	// LibraryPath is the path to the PKCS#11 library (.so or .dylib).
	LibraryPath string

	// TokenLabel is the label of the token to use.
	// If empty, the first available token will be used.
	TokenLabel string

	// SlotID is the PKCS#11 slot ID. If set, takes precedence over TokenLabel.
	// Use -1 to indicate that TokenLabel should be used instead.
	SlotID int

	// PIN is the user PIN for the token.
	// Required for storing and retrieving certificates.
	PIN string

	// ReadOnly opens the session in read-only mode when true.
	ReadOnly bool
}

// Validate checks if the PKCS#11 storage configuration is valid.
func (c *PKCS11StorageConfig) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	if c.LibraryPath == "" {
		return &PIVStorageError{
			Op:  "validate",
			Err: ErrMissingLibraryPath,
		}
	}

	return nil
}

// PIVCertificateStorage defines the interface for PIV certificate storage backends.
// All implementations must be safe for concurrent use.
type PIVCertificateStorage interface {
	// Store stores a certificate for the given slot.
	//
	// Parameters:
	//   - slot: PIV slot identifier (e.g., "9a", "9c")
	//   - cert: X.509 certificate to store
	//
	// Returns:
	//   - error: ErrInvalidSlot, ErrStorageFull, ErrPermissionDenied, ErrStorageClosed
	Store(slot PIVSlot, cert *x509.Certificate) error

	// Retrieve retrieves the certificate for the given slot.
	//
	// Parameters:
	//   - slot: PIV slot identifier
	//
	// Returns:
	//   - *x509.Certificate: The stored certificate
	//   - error: ErrCertificateNotFound, ErrInvalidSlot, ErrStorageClosed
	Retrieve(slot PIVSlot) (*x509.Certificate, error)

	// Delete removes the certificate from the given slot.
	//
	// Parameters:
	//   - slot: PIV slot identifier
	//
	// Returns:
	//   - error: ErrCertificateNotFound, ErrInvalidSlot, ErrPermissionDenied, ErrStorageClosed
	Delete(slot PIVSlot) error

	// List returns all slots that contain certificates.
	//
	// Returns:
	//   - []PIVSlotInfo: Slice of slot information for populated slots
	//   - error: Any storage access error
	List() ([]PIVSlotInfo, error)

	// Import imports a certificate from external encoding.
	//
	// Parameters:
	//   - slot: PIV slot identifier
	//   - data: Certificate data (PEM or DER encoded)
	//   - format: Import format (FormatPEM or FormatDER)
	//
	// Returns:
	//   - error: ErrInvalidFormat, ErrInvalidSlot, ErrStorageFull, ErrStorageClosed
	Import(slot PIVSlot, data []byte, format CertFormat) error

	// Export exports a certificate in the specified format.
	//
	// Parameters:
	//   - slot: PIV slot identifier
	//   - format: Export format (FormatPEM or FormatDER)
	//
	// Returns:
	//   - []byte: Encoded certificate data
	//   - error: ErrCertificateNotFound, ErrInvalidFormat, ErrInvalidSlot, ErrStorageClosed
	Export(slot PIVSlot, format CertFormat) ([]byte, error)

	// Close releases any resources held by the storage.
	// After Close is called, all other methods will return ErrStorageClosed.
	Close() error

	// Type returns the storage type identifier.
	Type() PIVStorageType
}

// PIVSlotRegistry provides slot metadata and validation.
// It maintains information about all valid PIV slots and their properties.
type PIVSlotRegistry interface {
	// ValidateSlot checks if a slot identifier is valid.
	//
	// Parameters:
	//   - slot: PIV slot identifier to validate
	//
	// Returns:
	//   - error: ErrInvalidSlot if the slot is not recognized
	ValidateSlot(slot PIVSlot) error

	// GetSlotInfo returns metadata about a slot.
	//
	// Parameters:
	//   - slot: PIV slot identifier
	//
	// Returns:
	//   - *SlotMetadata: Static slot information
	//   - error: ErrInvalidSlot if the slot is not recognized
	GetSlotInfo(slot PIVSlot) (*SlotMetadata, error)

	// ListSlots returns all valid slot identifiers.
	//
	// Returns:
	//   - []PIVSlot: All recognized PIV slot identifiers
	ListSlots() []PIVSlot

	// ListPrimarySlots returns the four primary PIV slots (9a, 9c, 9d, 9e).
	//
	// Returns:
	//   - []PIVSlot: Primary PIV slot identifiers
	ListPrimarySlots() []PIVSlot

	// ListRetiredSlots returns all retired key management slots (82-95).
	//
	// Returns:
	//   - []PIVSlot: Retired key management slot identifiers
	ListRetiredSlots() []PIVSlot
}

// Sentinel errors for PIV certificate storage operations.
// These errors can be checked using errors.Is().
var (
	// ErrInvalidSlot indicates an invalid slot identifier.
	ErrInvalidSlot = errors.New("pivcert: invalid slot identifier")

	// ErrCertificateNotFound indicates no certificate exists in the slot.
	ErrCertificateNotFound = errors.New("pivcert: certificate not found")

	// ErrStorageFull indicates the storage backend is full.
	ErrStorageFull = errors.New("pivcert: storage full")

	// ErrPermissionDenied indicates insufficient permissions for operation.
	ErrPermissionDenied = errors.New("pivcert: permission denied")

	// ErrInvalidFormat indicates an invalid certificate format.
	ErrInvalidFormat = errors.New("pivcert: invalid certificate format")

	// ErrStorageClosed indicates the storage has been closed.
	ErrStorageClosed = errors.New("pivcert: storage closed")

	// ErrInvalidCertificate indicates the certificate is invalid or malformed.
	ErrInvalidCertificate = errors.New("pivcert: invalid certificate")

	// ErrCertificateExpired indicates the certificate has expired.
	ErrCertificateExpired = errors.New("pivcert: certificate expired")

	// ErrCertificateTooLarge indicates the certificate exceeds the maximum size.
	ErrCertificateTooLarge = errors.New("pivcert: certificate too large")

	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("pivcert: invalid configuration")

	// ErrInvalidStorageType indicates an unrecognized storage type.
	ErrInvalidStorageType = errors.New("pivcert: invalid storage type")

	// ErrMissingConfig indicates a required configuration section is missing.
	ErrMissingConfig = errors.New("pivcert: missing configuration")

	// ErrMissingBackend indicates the storage backend is not set.
	ErrMissingBackend = errors.New("pivcert: missing storage backend")

	// ErrMissingDevicePath indicates the TPM device path is not set.
	ErrMissingDevicePath = errors.New("pivcert: missing device path")

	// ErrMissingLibraryPath indicates the PKCS#11 library path is not set.
	ErrMissingLibraryPath = errors.New("pivcert: missing library path")

	// ErrNoFormatEnabled indicates neither DER nor PEM format is enabled.
	ErrNoFormatEnabled = errors.New("pivcert: no format enabled")

	// ErrTPMNotAvailable indicates the TPM device is not available.
	ErrTPMNotAvailable = errors.New("pivcert: TPM not available")

	// ErrPKCS11NotAvailable indicates the PKCS#11 token is not available.
	ErrPKCS11NotAvailable = errors.New("pivcert: PKCS#11 token not available")

	// ErrNVIndexExists indicates the TPM NV index already exists.
	ErrNVIndexExists = errors.New("pivcert: NV index already exists")

	// ErrNVIndexNotFound indicates the TPM NV index does not exist.
	ErrNVIndexNotFound = errors.New("pivcert: NV index not found")

	// ErrTokenNotFound indicates the PKCS#11 token was not found.
	ErrTokenNotFound = errors.New("pivcert: token not found")

	// ErrSessionError indicates a PKCS#11 session error.
	ErrSessionError = errors.New("pivcert: session error")
)

// PIVStorageError wraps errors with operation context.
// It provides detailed information about the operation that failed
// and supports error unwrapping with errors.Is() and errors.As().
type PIVStorageError struct {
	// Op is the operation being performed (e.g., "store", "retrieve", "delete").
	Op string

	// Slot is the PIV slot involved in the operation, if applicable.
	Slot PIVSlot

	// StorageType is the storage backend type, if applicable.
	StorageType PIVStorageType

	// Err is the underlying error.
	Err error
}

// Error returns the formatted error message.
func (e *PIVStorageError) Error() string {
	if e.Slot != "" {
		return fmt.Sprintf("pivcert: %s slot %s: %v", e.Op, e.Slot, e.Err)
	}
	if e.StorageType != "" {
		return fmt.Sprintf("pivcert: %s [%s]: %v", e.Op, e.StorageType, e.Err)
	}
	return fmt.Sprintf("pivcert: %s: %v", e.Op, e.Err)
}

// Unwrap returns the underlying error for use with errors.Is() and errors.As().
func (e *PIVStorageError) Unwrap() error {
	return e.Err
}

// Is reports whether target matches this error.
func (e *PIVStorageError) Is(target error) bool {
	if target == nil {
		return false
	}
	return errors.Is(e.Err, target)
}

// NewStorageError creates a new PIVStorageError with the given parameters.
func NewStorageError(op string, slot PIVSlot, err error) *PIVStorageError {
	return &PIVStorageError{
		Op:   op,
		Slot: slot,
		Err:  err,
	}
}

// NewStorageTypeError creates a new PIVStorageError with storage type context.
func NewStorageTypeError(op string, storageType PIVStorageType, err error) *PIVStorageError {
	return &PIVStorageError{
		Op:          op,
		StorageType: storageType,
		Err:         err,
	}
}

// Viper configuration keys for CLI integration.
const (
	// ConfigKeyPIVStorage is the configuration key for PIV storage type.
	ConfigKeyPIVStorage = "piv.storage"

	// ConfigKeyPIVStoragePath is the configuration key for file storage base path.
	ConfigKeyPIVStoragePath = "piv.storage_path"

	// ConfigKeyPIVTPMDevice is the configuration key for TPM device path.
	ConfigKeyPIVTPMDevice = "piv.tpm_device"

	// ConfigKeyPIVTPMBaseIndex is the configuration key for TPM NV base index.
	ConfigKeyPIVTPMBaseIndex = "piv.tpm_base_index"

	// ConfigKeyPIVTPMOwnerAuth is the configuration key for TPM owner authorization.
	ConfigKeyPIVTPMOwnerAuth = "piv.tpm_owner_auth"

	// ConfigKeyPIVPKCS11Lib is the configuration key for PKCS#11 library path.
	ConfigKeyPIVPKCS11Lib = "piv.pkcs11_library"

	// ConfigKeyPIVPKCS11Token is the configuration key for PKCS#11 token label.
	ConfigKeyPIVPKCS11Token = "piv.pkcs11_token"

	// ConfigKeyPIVPKCS11SlotID is the configuration key for PKCS#11 slot ID.
	ConfigKeyPIVPKCS11SlotID = "piv.pkcs11_slot_id"

	// ConfigKeyPIVPKCS11PIN is the configuration key for PKCS#11 PIN.
	ConfigKeyPIVPKCS11PIN = "piv.pkcs11_pin"
)

// Maximum certificate sizes for storage backends.
const (
	// MaxCertSizeFile is the maximum certificate size for file storage (16KB).
	MaxCertSizeFile = 16 * 1024

	// MaxCertSizeTPM2 is the maximum certificate size for TPM2 NV storage (4KB).
	// This is limited by typical TPM NV index size constraints.
	MaxCertSizeTPM2 = 4 * 1024

	// MaxCertSizePKCS11 is the maximum certificate size for PKCS#11 storage (8KB).
	// This may vary by token implementation.
	MaxCertSizePKCS11 = 8 * 1024
)

// TPM2 NV index constants.
const (
	// TPM2NVIndexFirst is the first available NV index for user space.
	TPM2NVIndexFirst uint32 = 0x01000000

	// TPM2NVMagic is the magic number for PIV certificate NV entries.
	TPM2NVMagic uint32 = 0x50495643 // "PIVC" in ASCII

	// TPM2NVVersion is the current version of the NV storage format.
	TPM2NVVersion uint16 = 1

	// TPM2NVHeaderSize is the size of the NV entry header in bytes.
	TPM2NVHeaderSize = 16
)

// slotNVIndexOffset maps PIV slots to their TPM2 NV index offsets.
var slotNVIndexOffset = map[PIVSlot]uint32{
	PIVSlotAuthentication:     0x00,
	PIVSlotDigitalSignature:   0x01,
	PIVSlotKeyManagement:      0x02,
	PIVSlotCardAuthentication: 0x03,
	PIVSlotAttestation:        0x04,
	PIVSlotRetired1:           0x10,
	PIVSlotRetired2:           0x11,
	PIVSlotRetired3:           0x12,
	PIVSlotRetired4:           0x13,
	PIVSlotRetired5:           0x14,
	PIVSlotRetired6:           0x15,
	PIVSlotRetired7:           0x16,
	PIVSlotRetired8:           0x17,
	PIVSlotRetired9:           0x18,
	PIVSlotRetired10:          0x19,
	PIVSlotRetired11:          0x1A,
	PIVSlotRetired12:          0x1B,
	PIVSlotRetired13:          0x1C,
	PIVSlotRetired14:          0x1D,
	PIVSlotRetired15:          0x1E,
	PIVSlotRetired16:          0x1F,
	PIVSlotRetired17:          0x20,
	PIVSlotRetired18:          0x21,
	PIVSlotRetired19:          0x22,
	PIVSlotRetired20:          0x23,
}

// GetNVIndex returns the TPM2 NV index for a given slot and base index.
func GetNVIndex(slot PIVSlot, baseIndex uint32) (uint32, error) {
	offset, ok := slotNVIndexOffset[slot]
	if !ok {
		return 0, ErrInvalidSlot
	}
	return baseIndex + offset, nil
}

// AllSlots returns a slice of all valid PIV slot identifiers.
// This includes primary slots (9a, 9c, 9d, 9e), the attestation slot (f9),
// and retired slots (82-95).
func AllSlots() []PIVSlot {
	return []PIVSlot{
		PIVSlotAuthentication,
		PIVSlotDigitalSignature,
		PIVSlotKeyManagement,
		PIVSlotCardAuthentication,
		PIVSlotAttestation,
		PIVSlotRetired1,
		PIVSlotRetired2,
		PIVSlotRetired3,
		PIVSlotRetired4,
		PIVSlotRetired5,
		PIVSlotRetired6,
		PIVSlotRetired7,
		PIVSlotRetired8,
		PIVSlotRetired9,
		PIVSlotRetired10,
		PIVSlotRetired11,
		PIVSlotRetired12,
		PIVSlotRetired13,
		PIVSlotRetired14,
		PIVSlotRetired15,
		PIVSlotRetired16,
		PIVSlotRetired17,
		PIVSlotRetired18,
		PIVSlotRetired19,
		PIVSlotRetired20,
	}
}

// PrimarySlots returns a slice of the four primary PIV slot identifiers.
func PrimarySlots() []PIVSlot {
	return []PIVSlot{
		PIVSlotAuthentication,
		PIVSlotDigitalSignature,
		PIVSlotKeyManagement,
		PIVSlotCardAuthentication,
	}
}

// RetiredSlots returns a slice of all retired key management slot identifiers.
func RetiredSlots() []PIVSlot {
	return []PIVSlot{
		PIVSlotRetired1,
		PIVSlotRetired2,
		PIVSlotRetired3,
		PIVSlotRetired4,
		PIVSlotRetired5,
		PIVSlotRetired6,
		PIVSlotRetired7,
		PIVSlotRetired8,
		PIVSlotRetired9,
		PIVSlotRetired10,
		PIVSlotRetired11,
		PIVSlotRetired12,
		PIVSlotRetired13,
		PIVSlotRetired14,
		PIVSlotRetired15,
		PIVSlotRetired16,
		PIVSlotRetired17,
		PIVSlotRetired18,
		PIVSlotRetired19,
		PIVSlotRetired20,
	}
}

// ParseSlot parses a string into a PIVSlot.
// Returns ErrInvalidSlot if the string is not a valid slot identifier.
func ParseSlot(s string) (PIVSlot, error) {
	slot := PIVSlot(s)
	if err := ValidateSlot(slot); err != nil {
		return "", err
	}
	return slot, nil
}

// SlotName returns the human-readable name for a PIV slot.
func SlotName(slot PIVSlot) string {
	switch slot {
	case PIVSlotAuthentication:
		return "PIV Authentication"
	case PIVSlotDigitalSignature:
		return "Digital Signature"
	case PIVSlotKeyManagement:
		return "Key Management"
	case PIVSlotCardAuthentication:
		return "Card Authentication"
	case PIVSlotAttestation:
		return "Attestation"
	case PIVSlotRetired1:
		return "Retired Key 1"
	case PIVSlotRetired2:
		return "Retired Key 2"
	case PIVSlotRetired3:
		return "Retired Key 3"
	case PIVSlotRetired4:
		return "Retired Key 4"
	case PIVSlotRetired5:
		return "Retired Key 5"
	case PIVSlotRetired6:
		return "Retired Key 6"
	case PIVSlotRetired7:
		return "Retired Key 7"
	case PIVSlotRetired8:
		return "Retired Key 8"
	case PIVSlotRetired9:
		return "Retired Key 9"
	case PIVSlotRetired10:
		return "Retired Key 10"
	case PIVSlotRetired11:
		return "Retired Key 11"
	case PIVSlotRetired12:
		return "Retired Key 12"
	case PIVSlotRetired13:
		return "Retired Key 13"
	case PIVSlotRetired14:
		return "Retired Key 14"
	case PIVSlotRetired15:
		return "Retired Key 15"
	case PIVSlotRetired16:
		return "Retired Key 16"
	case PIVSlotRetired17:
		return "Retired Key 17"
	case PIVSlotRetired18:
		return "Retired Key 18"
	case PIVSlotRetired19:
		return "Retired Key 19"
	case PIVSlotRetired20:
		return "Retired Key 20"
	default:
		return "Unknown"
	}
}

// SlotDescription returns a description of the PIV slot's purpose.
func SlotDescription(slot PIVSlot) string {
	switch slot {
	case PIVSlotAuthentication:
		return "Used for PIV card and cardholder authentication to systems and applications"
	case PIVSlotDigitalSignature:
		return "Used for document signing and non-repudiation"
	case PIVSlotKeyManagement:
		return "Used for key establishment and secure key transport"
	case PIVSlotCardAuthentication:
		return "Used for card authentication without cardholder interaction"
	case PIVSlotAttestation:
		return "Device attestation certificate for proving key origin"
	default:
		if slot.IsRetiredSlot() {
			return "Historical key management certificate for decryption of archived data"
		}
		return "Unknown slot"
	}
}

// DefaultSlotMetadata returns the default metadata for a PIV slot.
func DefaultSlotMetadata(slot PIVSlot) (*SlotMetadata, error) {
	if err := ValidateSlot(slot); err != nil {
		return nil, err
	}

	meta := &SlotMetadata{
		Slot:        slot,
		Name:        SlotName(slot),
		Description: SlotDescription(slot),
		MaxCertSize: MaxCertSizeFile,
	}

	switch slot {
	case PIVSlotAuthentication:
		meta.KeyUsage = x509.KeyUsageDigitalSignature
		meta.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		meta.RequiresPIN = true
	case PIVSlotDigitalSignature:
		meta.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment
		meta.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		meta.RequiresPIN = true
	case PIVSlotKeyManagement:
		meta.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
		meta.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		meta.RequiresPIN = true
	case PIVSlotCardAuthentication:
		meta.KeyUsage = x509.KeyUsageDigitalSignature
		meta.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		meta.RequiresPIN = false
	case PIVSlotAttestation:
		meta.KeyUsage = x509.KeyUsageDigitalSignature
		meta.RequiresPIN = false
	default:
		// Retired slots
		meta.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
		meta.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		meta.RequiresPIN = true
	}

	return meta, nil
}

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

package hardware

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash/fnv"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	storagepkg "github.com/jeremyhahn/go-keychain/pkg/storage"
)

// TPM2CertStorage implements HardwareCertStorage for TPM 2.0 devices.
// Certificates are stored in TPM NV (Non-Volatile) RAM.
//
// Thread Safety:
// All operations are protected by a read-write mutex for concurrent access.
//
// Certificate Storage:
//   - Each certificate is stored in a dedicated NV index
//   - NV indices are derived from a base index + hash(ID)
//   - Certificates are stored as PEM-encoded data
//   - NV index attributes provide access control
//
// NV Index Layout:
//
//	Base Index: 0x01800000 (TPM_NV_INDEX_FIRST)
//	Cert Index: Base + (FNV-1a hash of ID % 0x003FFFFF)
//
// Limitations:
//   - Limited NV RAM capacity (typically 2KB-8KB total)
//   - Each certificate consumes ~2KB (including overhead)
//   - Practical limit: 2-4 certificates per TPM
//   - No built-in chain support (stored as single blob)
type TPM2CertStorage struct {
	tpm       transport.TPMCloser // TPM device connection
	baseIndex uint32              // Base NV index for certificates
	maxSize   int                 // Maximum certificate size (bytes)
	ownerAuth []byte              // Owner hierarchy password
	mu        sync.RWMutex        // Protects concurrent access
	closed    bool                // Tracks if storage is closed
}

// TPM2CertStorageConfig configures TPM2 certificate storage
type TPM2CertStorageConfig struct {
	// BaseIndex is the starting NV index for certificate storage
	// Default: 0x01800000 (TPM_NV_INDEX_FIRST)
	BaseIndex uint32

	// MaxCertSize is the maximum certificate size in bytes
	// Default: 2048 bytes
	MaxCertSize int

	// OwnerAuth is the owner hierarchy password
	// Required for creating/deleting NV indices
	OwnerAuth []byte
}

// DefaultTPM2CertStorageConfig returns safe defaults for TPM2 certificate storage
func DefaultTPM2CertStorageConfig() *TPM2CertStorageConfig {
	return &TPM2CertStorageConfig{
		BaseIndex:   0x01800000, // TPM_NV_INDEX_FIRST
		MaxCertSize: 2048,
		OwnerAuth:   nil, // No password by default
	}
}

// NewTPM2CertStorage creates a new TPM2 certificate storage instance.
//
// Parameters:
//   - tpm: Open TPM device connection
//   - config: Storage configuration
//
// Returns an error if NV RAM is inaccessible or config is invalid.
func NewTPM2CertStorage(
	tpm transport.TPMCloser,
	config *TPM2CertStorageConfig,
) (HardwareCertStorage, error) {
	if tpm == nil {
		return nil, ErrNilTPM
	}

	if config == nil {
		config = DefaultTPM2CertStorageConfig()
	}

	// Validate base index is in NV RAM range
	if config.BaseIndex < 0x01000000 || config.BaseIndex > 0x01BFFFFF {
		return nil, fmt.Errorf("%w: got %#x", ErrInvalidBaseIndex, config.BaseIndex)
	}

	if config.MaxCertSize < 512 || config.MaxCertSize > 4096 {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidCertSize, config.MaxCertSize)
	}

	return &TPM2CertStorage{
		tpm:       tpm,
		baseIndex: config.BaseIndex,
		maxSize:   config.MaxCertSize,
		ownerAuth: config.OwnerAuth,
	}, nil
}

// SaveCert stores a certificate in TPM NV RAM.
// The certificate is PEM-encoded and written to a dedicated NV index.
//
// NV Index Attributes:
//   - TPMA_NV_AUTHWRITE: Requires authorization to write
//   - TPMA_NV_AUTHREAD: Requires authorization to read
//   - TPMA_NV_NO_DA: Not subject to dictionary attack protection
//   - TPMA_NV_OWNERWRITE: Owner hierarchy can write
//   - TPMA_NV_OWNERREAD: Owner hierarchy can read
func (t *TPM2CertStorage) SaveCert(id string, cert *x509.Certificate) error {
	if id == "" {
		return storage.ErrInvalidID
	}
	if cert == nil {
		return storage.ErrInvalidData
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrStorageClosed
	}

	// PEM encode certificate
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if len(pemData) > t.maxSize {
		return ErrCertificateTooLarge
	}

	// Compute NV index for this certificate
	nvIndex := t.certIndexFromID(id)

	// Write to NV RAM (creates if doesn't exist)
	if err := t.writeNVIndex(nvIndex, pemData); err != nil {
		return NewOperationError("write certificate to NV RAM", err)
	}

	return nil
}

// GetCert retrieves a certificate from TPM NV RAM.
func (t *TPM2CertStorage) GetCert(id string) (*x509.Certificate, error) {
	if id == "" {
		return nil, storage.ErrInvalidID
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return nil, ErrStorageClosed
	}

	// Compute NV index
	nvIndex := t.certIndexFromID(id)

	// Read from NV RAM
	pemData, err := t.readNVIndex(nvIndex)
	if err != nil {
		return nil, NewOperationError("read certificate from NV RAM", err)
	}

	// Decode PEM
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidCertificate
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, NewOperationError("parse certificate", err)
	}

	return cert, nil
}

// DeleteCert removes a certificate by undefining its NV index.
func (t *TPM2CertStorage) DeleteCert(id string) error {
	if id == "" {
		return storage.ErrInvalidID
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrStorageClosed
	}

	// Compute NV index
	nvIndex := t.certIndexFromID(id)

	// Delete NV index
	if err := t.deleteNVIndex(nvIndex); err != nil {
		return NewOperationError("delete certificate from NV RAM", err)
	}

	return nil
}

// SaveCertChain stores a certificate chain as a PEM-encoded bundle.
// All certificates are concatenated and stored in a single NV index.
func (t *TPM2CertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	if id == "" {
		return storage.ErrInvalidID
	}
	if len(chain) == 0 {
		return storage.ErrInvalidData
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrStorageClosed
	}

	// Concatenate PEM-encoded certificates
	var pemData []byte
	for _, cert := range chain {
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		pemData = append(pemData, pemBlock...)
	}

	if len(pemData) > t.maxSize {
		return ErrCertificateTooLarge
	}

	// Compute NV index
	nvIndex := t.certIndexFromID(id)

	// Write to NV RAM
	if err := t.writeNVIndex(nvIndex, pemData); err != nil {
		return NewOperationError("write certificate chain to NV RAM", err)
	}

	return nil
}

// GetCertChain retrieves and parses a certificate chain bundle.
func (t *TPM2CertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	if id == "" {
		return nil, storage.ErrInvalidID
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return nil, ErrStorageClosed
	}

	// Compute NV index
	nvIndex := t.certIndexFromID(id)

	// Read from NV RAM
	pemData, err := t.readNVIndex(nvIndex)
	if err != nil {
		return nil, NewOperationError("read certificate chain from NV RAM", err)
	}

	// Parse all PEM blocks
	var chain []*x509.Certificate
	remaining := pemData
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, NewOperationError("parse certificate in chain", err)
		}

		chain = append(chain, cert)
		remaining = rest
	}

	if len(chain) == 0 {
		return nil, ErrInvalidCertificate
	}

	return chain, nil
}

// ListCerts returns certificate IDs by scanning defined NV indices.
// Note: This is expensive as it requires querying TPM capabilities.
func (t *TPM2CertStorage) ListCerts() ([]string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return nil, ErrStorageClosed
	}

	// Query TPM for NV indices in our range
	// TPM2_GetCapability with TPM_CAP_HANDLES
	capResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      t.baseIndex,
		PropertyCount: 256, // Max indices to query
	}.Execute(t.tpm)

	if err != nil {
		return nil, NewOperationError("query NV indices", err)
	}

	handles, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return nil, NewOperationError("get NV handles", err)
	}

	// Note: We cannot reverse the hash to get original IDs
	// This is a limitation of the hash-based index scheme
	// Return indices as hex strings for now
	var certIDs []string
	for _, handle := range handles.Handle {
		// Only include indices in our range
		if handle >= tpm2.TPMHandle(t.baseIndex) && handle < tpm2.TPMHandle(t.baseIndex+0x00400000) {
			certIDs = append(certIDs, fmt.Sprintf("0x%08x", handle))
		}
	}

	return certIDs, nil
}

// CertExists checks if an NV index exists for the certificate.
func (t *TPM2CertStorage) CertExists(id string) (bool, error) {
	if id == "" {
		return false, storage.ErrInvalidID
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return false, ErrStorageClosed
	}

	// Compute NV index
	nvIndex := t.certIndexFromID(id)

	// Try to read NV public to check existence
	_, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(nvIndex),
	}.Execute(t.tpm)

	if err != nil {
		// Index doesn't exist
		return false, nil
	}

	return true, nil
}

// Close releases TPM resources (NV handles are persistent, no cleanup needed).
func (t *TPM2CertStorage) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrStorageClosed
	}

	t.closed = true
	return nil
}

// GetCapacity queries TPM NV RAM capacity and usage.
// Note: This is an approximation based on max cert size and available space.
func (t *TPM2CertStorage) GetCapacity() (total int, available int, err error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return 0, 0, ErrStorageClosed
	}

	// Typical TPM NV RAM: 2KB-8KB total
	// Conservative estimate: 8KB total, each cert ~2KB = 4 certs max
	// This is a simplified implementation - real TPMs vary widely
	estimatedTotal := 4

	// Count existing certificates
	certIDs, err := t.listCertsUnlocked()
	if err != nil {
		return 0, 0, NewOperationError("count certificates", err)
	}

	used := len(certIDs)
	available = estimatedTotal - used
	if available < 0 {
		available = 0
	}

	return estimatedTotal, available, nil
}

// SupportsChains returns true (chains stored as concatenated PEM).
func (t *TPM2CertStorage) SupportsChains() bool {
	return true
}

// IsHardwareBacked returns true.
func (t *TPM2CertStorage) IsHardwareBacked() bool {
	return true
}

// Compact defragments TPM NV RAM if supported (TPM 2.0 spec optional).
// Most TPMs don't support this, so we return ErrNotSupported.
func (t *TPM2CertStorage) Compact() error {
	return ErrNotSupported
}

// certIndexFromID computes the NV index for a certificate ID
// using FNV-1a hash to distribute IDs across index space.
func (t *TPM2CertStorage) certIndexFromID(id string) uint32 {
	// Use FNV-1a hash for consistent distribution
	h := fnv.New32a()
	h.Write([]byte(id))
	hash := h.Sum32()

	// Map to NV index range (0x01800000 - 0x01BFFFFF)
	// Use modulo to wrap into 0x00400000 range
	offset := hash % 0x00400000
	return t.baseIndex + offset
}

// readNVIndex reads data from an NV index with authorization.
func (t *TPM2CertStorage) readNVIndex(index uint32) ([]byte, error) {
	// Read NV public to get size
	readPubResp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}.Execute(t.tpm)

	if err != nil {
		return nil, storagepkg.ErrNotFound
	}

	nvPublic, err := readPubResp.NVPublic.Contents()
	if err != nil {
		return nil, NewOperationError("get NV public contents", err)
	}

	// Read data in chunks (TPM has max read size limits)
	const maxChunkSize = 1024
	totalSize := int(nvPublic.DataSize)
	result := make([]byte, 0, totalSize)
	offset := uint16(0)

	for offset < uint16(totalSize) {
		chunkSize := uint16(maxChunkSize)
		if int(offset)+int(chunkSize) > totalSize {
			chunkSize = uint16(totalSize) - offset
		}

		readResp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(t.ownerAuth),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(index),
				Name:   readPubResp.NVName,
			},
			Size:   chunkSize,
			Offset: offset,
		}.Execute(t.tpm)

		if err != nil {
			return nil, NewOperationError(fmt.Sprintf("NV read at offset %d", offset), err)
		}

		result = append(result, readResp.Data.Buffer...)
		offset += chunkSize
	}

	return result, nil
}

// writeNVIndex writes data to an NV index, creating if necessary.
func (t *TPM2CertStorage) writeNVIndex(index uint32, data []byte) error {
	// Check if index exists
	readPubResp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}.Execute(t.tpm)

	if err != nil {
		// Index doesn't exist, create it
		if err := t.defineNVIndex(index, len(data)); err != nil {
			return NewOperationError("define NV index", err)
		}

		// Re-read public to get name
		readPubResp, err = tpm2.NVReadPublic{
			NVIndex: tpm2.TPMHandle(index),
		}.Execute(t.tpm)

		if err != nil {
			return NewOperationError("read NV public after define", err)
		}
	} else {
		// Index exists - check if size matches
		nvPublic, err := readPubResp.NVPublic.Contents()
		if err != nil {
			return NewOperationError("get NV public contents", err)
		}

		if int(nvPublic.DataSize) != len(data) {
			// Size mismatch - delete and recreate
			if err := t.deleteNVIndex(index); err != nil {
				return NewOperationError("delete existing NV index", err)
			}

			if err := t.defineNVIndex(index, len(data)); err != nil {
				return NewOperationError("redefine NV index", err)
			}

			// Re-read public to get name
			readPubResp, err = tpm2.NVReadPublic{
				NVIndex: tpm2.TPMHandle(index),
			}.Execute(t.tpm)

			if err != nil {
				return NewOperationError("read NV public after redefine", err)
			}
		}
	}

	// Write data in chunks (TPM has max write size limits)
	// Typical max: 1024 bytes per write
	const maxChunkSize = 1024
	offset := uint16(0)

	for offset < uint16(len(data)) {
		chunkEnd := int(offset) + maxChunkSize
		if chunkEnd > len(data) {
			chunkEnd = len(data)
		}

		chunk := data[offset:chunkEnd]

		_, err = tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(t.ownerAuth),
			},
			NVIndex: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(index),
				Name:   readPubResp.NVName,
			},
			Data: tpm2.TPM2BMaxNVBuffer{
				Buffer: chunk,
			},
			Offset: offset,
		}.Execute(t.tpm)

		if err != nil {
			return NewOperationError(fmt.Sprintf("NV write at offset %d", offset), err)
		}

		offset += uint16(len(chunk))
	}

	return nil
}

// defineNVIndex creates a new NV index with the specified size.
func (t *TPM2CertStorage) defineNVIndex(index uint32, size int) error {
	// Define NV index with appropriate attributes
	nvPublic := tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMHandle(index),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			AuthWrite:  true,
			AuthRead:   true,
			NoDA:       true,
			OwnerWrite: true,
			OwnerRead:  true,
			// Note: WriteDefine not set to allow updates
		},
		DataSize: uint16(size),
	}

	_, err := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(t.ownerAuth),
		},
		PublicInfo: tpm2.New2B(nvPublic),
	}.Execute(t.tpm)

	if err != nil {
		return NewOperationError("NV define", err)
	}

	return nil
}

// deleteNVIndex undefines an NV index to free NV RAM.
func (t *TPM2CertStorage) deleteNVIndex(index uint32) error {
	// Read public to get name
	readPubResp, err := tpm2.NVReadPublic{
		NVIndex: tpm2.TPMHandle(index),
	}.Execute(t.tpm)

	if err != nil {
		// Index doesn't exist, treat as success (idempotent)
		return nil
	}

	// Undefine the index
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(t.ownerAuth),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(index),
			Name:   readPubResp.NVName,
		},
	}.Execute(t.tpm)

	if err != nil {
		return NewOperationError("NV undefine", err)
	}

	return nil
}

// listCertsUnlocked is the unlocked version of ListCerts for internal use
func (t *TPM2CertStorage) listCertsUnlocked() ([]string, error) {
	if t.closed {
		return nil, ErrStorageClosed
	}

	capResp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      t.baseIndex,
		PropertyCount: 256,
	}.Execute(t.tpm)

	if err != nil {
		return nil, NewOperationError("query NV indices", err)
	}

	handles, err := capResp.CapabilityData.Data.Handles()
	if err != nil {
		return nil, NewOperationError("get NV handles", err)
	}

	var certIDs []string
	for _, handle := range handles.Handle {
		if handle >= tpm2.TPMHandle(t.baseIndex) && handle < tpm2.TPMHandle(t.baseIndex+0x00400000) {
			certIDs = append(certIDs, fmt.Sprintf("0x%08x", handle))
		}
	}

	return certIDs, nil
}

// Ensure interface compliance at compile time
var _ HardwareCertStorage = (*TPM2CertStorage)(nil)

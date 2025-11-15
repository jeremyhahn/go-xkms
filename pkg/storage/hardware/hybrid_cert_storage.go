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

//go:build tpm2 || pkcs11

package hardware

import (
	"crypto/x509"
	"fmt"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// BackendCertStorageAdapter wraps a storage.Backend to implement HardwareCertStorage interface.
// This adapter converts between the Backend's []byte interface and HardwareCertStorage's
// *x509.Certificate interface by encoding/decoding certificates as DER.
type BackendCertStorageAdapter struct {
	backend storage.Backend
	mu      sync.RWMutex
	closed  bool
}

// NewBackendCertStorageAdapter creates a new adapter that wraps a storage.Backend.
func NewBackendCertStorageAdapter(backend storage.Backend) HardwareCertStorage {
	return &BackendCertStorageAdapter{
		backend: backend,
		closed:  false,
	}
}

// SaveCert stores a certificate by encoding it as DER and saving to the backend.
func (a *BackendCertStorageAdapter) SaveCert(id string, cert *x509.Certificate) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}
	if cert == nil {
		return storage.ErrInvalidData
	}

	return storage.SaveCert(a.backend, id, cert.Raw)
}

// GetCert retrieves and parses a certificate from the backend.
func (a *BackendCertStorageAdapter) GetCert(id string) (*x509.Certificate, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.closed {
		return nil, ErrStorageClosed
	}

	if id == "" {
		return nil, storage.ErrInvalidID
	}

	certData, err := storage.GetCert(a.backend, id)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, NewOperationError("parse certificate", err)
	}

	return cert, nil
}

// DeleteCert removes a certificate from the backend.
func (a *BackendCertStorageAdapter) DeleteCert(id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}

	return storage.DeleteCert(a.backend, id)
}

// SaveCertChain stores a certificate chain by concatenating DER-encoded certificates.
func (a *BackendCertStorageAdapter) SaveCertChain(id string, chain []*x509.Certificate) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}
	if len(chain) == 0 {
		return storage.ErrInvalidData
	}

	// Concatenate all certificate DER data
	var chainData []byte
	for i, cert := range chain {
		if cert == nil {
			return fmt.Errorf("certificate at index %d is nil: %w", i, storage.ErrInvalidData)
		}
		chainData = append(chainData, cert.Raw...)
	}

	return storage.SaveCertChain(a.backend, id, chainData)
}

// GetCertChain retrieves and parses a certificate chain from the backend.
func (a *BackendCertStorageAdapter) GetCertChain(id string) ([]*x509.Certificate, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.closed {
		return nil, ErrStorageClosed
	}

	if id == "" {
		return nil, storage.ErrInvalidID
	}

	chainData, err := storage.GetCertChain(a.backend, id)
	if err != nil {
		return nil, err
	}

	// Parse concatenated DER data
	// Note: x509.ParseCertificates expects PEM or a slice of DER blocks
	// For now, we'll try to parse as a single cert chain
	chain, err := x509.ParseCertificates(chainData)
	if err != nil {
		return nil, NewOperationError("parse certificate chain", err)
	}

	if len(chain) == 0 {
		return nil, ErrInvalidCertificate
	}

	return chain, nil
}

// ListCerts returns all certificate IDs from the backend.
func (a *BackendCertStorageAdapter) ListCerts() ([]string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.closed {
		return nil, ErrStorageClosed
	}

	// List all keys with "certs/" prefix
	keys, err := a.backend.List("certs/")
	if err != nil {
		return nil, err
	}

	// Extract IDs from paths (certs/ID.pem -> ID)
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		// Remove "certs/" prefix and ".pem" suffix
		if strings.HasPrefix(key, "certs/") && strings.HasSuffix(key, ".pem") {
			id := key[6 : len(key)-4] // Strip "certs/" and ".pem"
			ids = append(ids, id)
		}
	}

	return ids, nil
}

// CertExists checks if a certificate exists in the backend.
func (a *BackendCertStorageAdapter) CertExists(id string) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.closed {
		return false, ErrStorageClosed
	}

	if id == "" {
		return false, storage.ErrInvalidID
	}

	return storage.CertExists(a.backend, id)
}

// Close closes the underlying backend.
func (a *BackendCertStorageAdapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return nil
	}

	a.closed = true
	return a.backend.Close()
}

// GetCapacity returns ErrNotSupported (external storage has no capacity limits).
func (a *BackendCertStorageAdapter) GetCapacity() (total int, available int, err error) {
	return 0, 0, ErrNotSupported
}

// SupportsChains returns true (external storage supports chains).
func (a *BackendCertStorageAdapter) SupportsChains() bool {
	return true
}

// IsHardwareBacked returns false (this is external storage).
func (a *BackendCertStorageAdapter) IsHardwareBacked() bool {
	return false
}

// Compact returns ErrNotSupported (external storage doesn't need compaction).
func (a *BackendCertStorageAdapter) Compact() error {
	return ErrNotSupported
}

// HybridCertStorage provides a hybrid storage strategy combining
// hardware and external storage for maximum flexibility and reliability.
//
// Storage Strategy:
//   - SaveCert: Always tries hardware first, falls back to external on capacity/error
//   - GetCert: Tries hardware first, falls back to external if not found
//   - DeleteCert: Deletes from both hardware and external (idempotent)
//   - ListCerts: Merges IDs from both storages (deduplicated)
//
// Use Cases:
//   - Migration from external to hardware storage
//   - Overflow handling when hardware capacity is exhausted
//   - High-availability with redundant storage
//   - Gradual rollout of hardware certificate storage
//
// Thread Safety:
// This implementation is thread-safe. All operations are protected by a
// read-write mutex. The underlying hardware and external storage backends
// are also expected to be thread-safe.
type HybridCertStorage struct {
	hardware HardwareCertStorage // Hardware-backed storage
	external HardwareCertStorage // External storage (wrapped Backend)
	mu       sync.RWMutex        // Protects storage state
	closed   bool                // Tracks if storage is closed
}

// NewHybridCertStorage creates a new hybrid certificate storage that combines
// hardware and external storage backends.
//
// The hybrid storage provides automatic failover:
//   - Writes prioritize hardware storage but fall back to external on capacity errors
//   - Reads check hardware first, then external
//   - Deletes remove from both backends
//
// Parameters:
//   - hardware: Hardware certificate storage implementation (PKCS#11, TPM2)
//   - external: External certificate storage implementation (file, memory, etc.)
//
// Returns an error if either storage is nil.
func NewHybridCertStorage(
	hardware HardwareCertStorage,
	external HardwareCertStorage,
) (HardwareCertStorage, error) {
	if hardware == nil {
		return nil, ErrNilStorage
	}
	if external == nil {
		return nil, ErrNilStorage
	}

	return &HybridCertStorage{
		hardware: hardware,
		external: external,
		closed:   false,
	}, nil
}

// NewHybridCertStorageFromBackend creates a hybrid storage using a storage.Backend
// for external storage. The backend is automatically wrapped with an adapter.
func NewHybridCertStorageFromBackend(
	hardware HardwareCertStorage,
	externalBackend storage.Backend,
) (HardwareCertStorage, error) {
	if hardware == nil {
		return nil, ErrNilStorage
	}
	if externalBackend == nil {
		return nil, ErrNilStorage
	}

	external := NewBackendCertStorageAdapter(externalBackend)
	return NewHybridCertStorage(hardware, external)
}

// SaveCert attempts to save the certificate to hardware storage first.
// If hardware storage fails due to capacity or availability issues, it
// automatically falls back to external storage.
//
// This provides transparent overflow handling and ensures certificates
// are never lost due to hardware limitations.
//
// Returns:
//   - nil if saved to either storage
//   - error if both storage backends fail
func (h *HybridCertStorage) SaveCert(id string, cert *x509.Certificate) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}

	if cert == nil {
		return storage.ErrInvalidData
	}

	// Try hardware storage first
	hwErr := h.hardware.SaveCert(id, cert)
	if hwErr == nil {
		// Success on hardware storage
		return nil
	}

	// Check if the error is capacity-related or hardware unavailable
	if IsCapacityError(hwErr) || IsHardwareError(hwErr) {
		// Fall back to external storage
		extErr := h.external.SaveCert(id, cert)
		if extErr == nil {
			// Successfully saved to external storage
			return nil
		}
		// Both failed - return combined error
		return fmt.Errorf("hardware storage failed: %w; external storage failed: %v", hwErr, extErr)
	}

	// Hardware error is not capacity-related, return it
	return fmt.Errorf("hardware storage failed: %w", hwErr)
}

// GetCert retrieves a certificate by trying hardware storage first,
// then falling back to external storage if not found.
//
// This allows transparent migration where certificates can exist in
// either storage backend.
//
// Returns:
//   - Certificate if found in either storage
//   - ErrNotFound if not in either storage
//   - Other errors if retrieval fails
func (h *HybridCertStorage) GetCert(id string) (*x509.Certificate, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return nil, ErrStorageClosed
	}

	if id == "" {
		return nil, storage.ErrInvalidID
	}

	// Try hardware storage first
	cert, hwErr := h.hardware.GetCert(id)
	if hwErr == nil {
		return cert, nil
	}

	// If not found in hardware, try external
	if hwErr == storage.ErrNotFound || IsHardwareError(hwErr) {
		cert, extErr := h.external.GetCert(id)
		if extErr == nil {
			return cert, nil
		}
		// If external also returns not found, use that error
		if extErr == storage.ErrNotFound {
			return nil, storage.ErrNotFound
		}
		// Return external error
		return nil, fmt.Errorf("external storage failed: %w", extErr)
	}

	// Return hardware error
	return nil, fmt.Errorf("hardware storage failed: %w", hwErr)
}

// DeleteCert removes a certificate from both hardware and external storage.
// This is idempotent - it succeeds if the certificate is removed from at
// least one storage backend or doesn't exist in either.
//
// Returns:
//   - nil if deleted from at least one storage or not found in both
//   - error if both storages fail with non-NotFound errors
func (h *HybridCertStorage) DeleteCert(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}

	// Try to delete from both storages
	hwErr := h.hardware.DeleteCert(id)
	extErr := h.external.DeleteCert(id)

	// Check if both report not found
	hwNotFound := hwErr == storage.ErrNotFound
	extNotFound := extErr == storage.ErrNotFound

	if hwNotFound && extNotFound {
		return storage.ErrNotFound
	}

	// At least one succeeded or reported not found
	if hwErr == nil || hwNotFound || extErr == nil || extNotFound {
		return nil
	}

	// Both failed with real errors
	return fmt.Errorf("hardware delete failed: %w; external delete failed: %v", hwErr, extErr)
}

// SaveCertChain saves a certificate chain by trying hardware storage first,
// then falling back to external storage on capacity or availability issues.
//
// This follows the same strategy as SaveCert for transparent overflow handling.
//
// Returns:
//   - nil if saved to either storage
//   - error if both storage backends fail
func (h *HybridCertStorage) SaveCertChain(id string, chain []*x509.Certificate) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return ErrStorageClosed
	}

	if id == "" {
		return storage.ErrInvalidID
	}

	if len(chain) == 0 {
		return storage.ErrInvalidData
	}

	// Validate all certs in chain are non-nil
	for i, cert := range chain {
		if cert == nil {
			return fmt.Errorf("certificate at index %d is nil: %w", i, storage.ErrInvalidData)
		}
	}

	// Try hardware storage first
	hwErr := h.hardware.SaveCertChain(id, chain)
	if hwErr == nil {
		return nil
	}

	// Check if the error is capacity-related or hardware unavailable
	if IsCapacityError(hwErr) || IsHardwareError(hwErr) {
		// Fall back to external storage
		extErr := h.external.SaveCertChain(id, chain)
		if extErr == nil {
			return nil
		}
		// Both failed
		return fmt.Errorf("hardware storage failed: %w; external storage failed: %v", hwErr, extErr)
	}

	// Hardware error is not capacity-related
	return fmt.Errorf("hardware storage failed: %w", hwErr)
}

// GetCertChain retrieves a certificate chain by trying hardware storage first,
// then falling back to external storage if not found.
//
// Returns:
//   - Certificate chain if found in either storage
//   - ErrNotFound if not in either storage
//   - Other errors if retrieval fails
func (h *HybridCertStorage) GetCertChain(id string) ([]*x509.Certificate, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return nil, ErrStorageClosed
	}

	if id == "" {
		return nil, storage.ErrInvalidID
	}

	// Try hardware storage first
	chain, hwErr := h.hardware.GetCertChain(id)
	if hwErr == nil {
		return chain, nil
	}

	// If not found in hardware, try external
	if hwErr == storage.ErrNotFound || IsHardwareError(hwErr) {
		chain, extErr := h.external.GetCertChain(id)
		if extErr == nil {
			return chain, nil
		}
		// If external also returns not found, use that error
		if extErr == storage.ErrNotFound {
			return nil, storage.ErrNotFound
		}
		return nil, fmt.Errorf("external storage failed: %w", extErr)
	}

	return nil, fmt.Errorf("hardware storage failed: %w", hwErr)
}

// ListCerts returns a deduplicated list of all certificate IDs from both
// hardware and external storage.
//
// This provides a unified view of all available certificates regardless
// of which storage backend they're in.
//
// Returns:
//   - Merged list of certificate IDs (deduplicated)
//   - error if both storages fail to list certificates
func (h *HybridCertStorage) ListCerts() ([]string, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return nil, ErrStorageClosed
	}

	// Get lists from both storages
	hwList, hwErr := h.hardware.ListCerts()
	extList, extErr := h.external.ListCerts()

	// If both fail, return error
	if hwErr != nil && extErr != nil {
		return nil, fmt.Errorf("hardware list failed: %w; external list failed: %v", hwErr, extErr)
	}

	// Use a map to deduplicate
	idMap := make(map[string]bool)

	// Add hardware IDs if available
	if hwErr == nil {
		for _, id := range hwList {
			idMap[id] = true
		}
	}

	// Add external IDs if available
	if extErr == nil {
		for _, id := range extList {
			idMap[id] = true
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(idMap))
	for id := range idMap {
		result = append(result, id)
	}

	return result, nil
}

// CertExists checks if a certificate exists in either hardware or external storage.
//
// Returns:
//   - true if the certificate exists in at least one storage backend
//   - false if not found in either storage
//   - error if both storages fail to check existence
func (h *HybridCertStorage) CertExists(id string) (bool, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return false, ErrStorageClosed
	}

	if id == "" {
		return false, storage.ErrInvalidID
	}

	// Check hardware storage
	hwExists, hwErr := h.hardware.CertExists(id)
	if hwErr == nil && hwExists {
		return true, nil
	}

	// Check external storage
	extExists, extErr := h.external.CertExists(id)
	if extErr == nil && extExists {
		return true, nil
	}

	// If both had errors, return combined error
	if hwErr != nil && extErr != nil {
		return false, fmt.Errorf("hardware check failed: %w; external check failed: %v", hwErr, extErr)
	}

	// Neither exists and no errors
	return false, nil
}

// Close closes both hardware and external storage backends.
// After calling Close, all operations will return ErrStorageClosed.
//
// This is idempotent - calling Close multiple times is safe.
//
// Returns:
//   - nil if both storages close successfully
//   - error if either storage fails to close
func (h *HybridCertStorage) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil // Already closed
	}

	// Close both storages
	hwErr := h.hardware.Close()
	extErr := h.external.Close()

	// Mark as closed regardless of errors
	h.closed = true

	// Return combined error if both failed
	if hwErr != nil && extErr != nil {
		return fmt.Errorf("hardware close failed: %w; external close failed: %v", hwErr, extErr)
	}

	// Return whichever error occurred
	if hwErr != nil {
		return fmt.Errorf("hardware close failed: %w", hwErr)
	}
	if extErr != nil {
		return fmt.Errorf("external close failed: %w", extErr)
	}

	return nil
}

// GetCapacity returns the hardware storage capacity.
// It only reports on the hardware backend capacity.
func (h *HybridCertStorage) GetCapacity() (total int, available int, err error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return 0, 0, ErrStorageClosed
	}

	return h.hardware.GetCapacity()
}

// SupportsChains returns true if hardware storage supports chains.
func (h *HybridCertStorage) SupportsChains() bool {
	return h.hardware.SupportsChains()
}

// IsHardwareBacked returns true (hybrid includes hardware backing).
func (h *HybridCertStorage) IsHardwareBacked() bool {
	return true
}

// Compact performs compaction on the hardware storage backend.
func (h *HybridCertStorage) Compact() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return ErrStorageClosed
	}

	return h.hardware.Compact()
}

// Verify interface compliance at compile time
var _ HardwareCertStorage = (*HybridCertStorage)(nil)
var _ HardwareCertStorage = (*BackendCertStorageAdapter)(nil)

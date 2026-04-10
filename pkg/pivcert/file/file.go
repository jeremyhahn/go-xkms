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

// Package file provides a file system-based PIV certificate storage backend.
//
// The FileBackend stores PIV certificates as DER and optionally PEM-encoded data
// using a storage.Backend for persistence. Keys are organized as:
//
//	certificates/{slot}.der   # DER-encoded certificate
//	certificates/{slot}.pem   # PEM-encoded certificate (optional)
//	metadata/slots.json       # Slot metadata index
//
// All operations are thread-safe as the underlying storage.Backend is
// thread-safe per interface contract.
package file

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

const (
	// Key prefixes for storage
	keyPrefixCertificates = "certificates/"
	keyPrefixMetadata     = "metadata/"

	// File names
	keySlotMetadata = "metadata/slots.json"

	// File extensions
	extDER = ".der"
	extPEM = ".pem"

	// Metadata schema version
	metadataVersion = "1.0"
)

// Compile-time interface compliance check.
var _ pivcert.PIVCertificateStorage = (*FileBackend)(nil)

// FileBackend implements PIVCertificateStorage using a storage.Backend.
// All operations are thread-safe via the underlying storage backend.
type FileBackend struct {
	backend    storage.Backend
	derEnabled bool
	pemEnabled bool
	closed     bool
	mu         sync.RWMutex
}

// slotMetadataFile represents the on-disk metadata structure.
type slotMetadataFile struct {
	Version string                  `json:"version"`
	Slots   map[string]slotMetadata `json:"slots"`
}

// slotMetadata represents metadata for a single certificate slot.
type slotMetadata struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serial_number"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	Algorithm    string `json:"algorithm"`
	KeySize      int    `json:"key_size"`
	Fingerprint  string `json:"fingerprint"`
	StoredAt     string `json:"stored_at"`
}

// NewFileBackend creates a new storage.Backend-based PIV certificate storage backend.
//
// The backend uses the provided storage.Backend for persistence. By default,
// both DER and PEM formats are enabled unless explicitly disabled in the configuration.
//
// Returns an error if the configuration is nil or the backend is nil.
func NewFileBackend(config *pivcert.FileStorageConfig) (*FileBackend, error) {
	if config == nil {
		return nil, pivcert.NewStorageTypeError("NewFileBackend", pivcert.StorageTypeFile, pivcert.ErrInvalidConfig)
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	fb := &FileBackend{
		backend:    config.Backend,
		derEnabled: config.DEREnabled,
		pemEnabled: config.PEMEnabled,
	}

	// Initialize metadata file if it doesn't exist
	if err := fb.ensureMetadataInitialized(); err != nil {
		return nil, pivcert.NewStorageTypeError("NewFileBackend", pivcert.StorageTypeFile, err)
	}

	return fb, nil
}

// Store stores a certificate for the given slot.
//
// The certificate is written in DER format by default, and optionally
// in PEM format if enabled.
//
// Returns an error if the slot is invalid, the storage is closed,
// or storage operations fail.
func (fb *FileBackend) Store(slot pivcert.PIVSlot, cert *x509.Certificate) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	if fb.closed {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrStorageClosed)
	}

	if !slot.IsValid() {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrInvalidSlot)
	}

	if cert == nil {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrInvalidCertificate)
	}

	// Check certificate size
	if len(cert.Raw) > pivcert.MaxCertSizeFile {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrCertificateTooLarge)
	}

	// Write DER data
	if fb.derEnabled {
		derKey := certKey(slot, extDER)
		if err := fb.backend.Put(context.Background(), derKey, cert.Raw); err != nil {
			return pivcert.NewStorageError("Store", slot, err)
		}
	}

	// Write PEM data
	if fb.pemEnabled {
		pemKey := certKey(slot, extPEM)
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err := fb.backend.Put(context.Background(), pemKey, pemData); err != nil {
			return pivcert.NewStorageError("Store", slot, err)
		}
	}

	// Update metadata
	if err := fb.updateMetadata(slot, cert); err != nil {
		return pivcert.NewStorageError("Store", slot, err)
	}

	return nil
}

// Retrieve retrieves the certificate for the given slot.
//
// The certificate is read from the DER data if available, otherwise
// from the PEM data. Returns ErrCertificateNotFound if no certificate
// exists in the slot.
func (fb *FileBackend) Retrieve(slot pivcert.PIVSlot) (*x509.Certificate, error) {
	fb.mu.RLock()
	defer fb.mu.RUnlock()

	if fb.closed {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrStorageClosed)
	}

	if !slot.IsValid() {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrInvalidSlot)
	}

	// Try DER first
	derKey := certKey(slot, extDER)
	data, err := fb.backend.Get(context.Background(), derKey)
	if err == nil {
		cert, parseErr := x509.ParseCertificate(data)
		if parseErr != nil {
			return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrInvalidCertificate)
		}
		return cert, nil
	}

	// Fall back to PEM
	pemKey := certKey(slot, extPEM)
	data, err = fb.backend.Get(context.Background(), pemKey)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrCertificateNotFound)
		}
		return nil, pivcert.NewStorageError("Retrieve", slot, err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrInvalidFormat)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrInvalidCertificate)
	}

	return cert, nil
}

// Delete removes the certificate from the given slot.
//
// Both DER and PEM data are removed if they exist. Returns
// ErrCertificateNotFound if no certificate exists in the slot.
func (fb *FileBackend) Delete(slot pivcert.PIVSlot) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	if fb.closed {
		return pivcert.NewStorageError("Delete", slot, pivcert.ErrStorageClosed)
	}

	if !slot.IsValid() {
		return pivcert.NewStorageError("Delete", slot, pivcert.ErrInvalidSlot)
	}

	// Check if certificate exists
	derKey := certKey(slot, extDER)
	pemKey := certKey(slot, extPEM)

	derExists, _ := fb.backend.Exists(context.Background(), derKey)
	pemExists, _ := fb.backend.Exists(context.Background(), pemKey)

	if !derExists && !pemExists {
		return pivcert.NewStorageError("Delete", slot, pivcert.ErrCertificateNotFound)
	}

	// Remove DER data
	if derExists {
		if err := fb.backend.Delete(context.Background(), derKey); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return pivcert.NewStorageError("Delete", slot, err)
		}
	}

	// Remove PEM data
	if pemExists {
		if err := fb.backend.Delete(context.Background(), pemKey); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return pivcert.NewStorageError("Delete", slot, err)
		}
	}

	// Update metadata
	if err := fb.removeMetadata(slot); err != nil {
		return pivcert.NewStorageError("Delete", slot, err)
	}

	return nil
}

// List returns all slots that contain certificates.
//
// The slot information is read from the metadata and includes
// certificate subject, issuer, validity period, and key algorithm.
func (fb *FileBackend) List() ([]pivcert.PIVSlotInfo, error) {
	fb.mu.RLock()
	defer fb.mu.RUnlock()

	if fb.closed {
		return nil, pivcert.NewStorageTypeError("List", pivcert.StorageTypeFile, pivcert.ErrStorageClosed)
	}

	metadata, err := fb.loadMetadata()
	if err != nil {
		return nil, pivcert.NewStorageTypeError("List", pivcert.StorageTypeFile, err)
	}

	result := make([]pivcert.PIVSlotInfo, 0, len(metadata.Slots))
	for slotID, meta := range metadata.Slots {
		storedAt, _ := time.Parse(time.RFC3339, meta.StoredAt)
		result = append(result, pivcert.PIVSlotInfo{
			Slot:         pivcert.PIVSlot(slotID),
			Subject:      meta.Subject,
			Issuer:       meta.Issuer,
			SerialNumber: meta.SerialNumber,
			NotBefore:    meta.NotBefore,
			NotAfter:     meta.NotAfter,
			Algorithm:    meta.Algorithm,
			KeySize:      meta.KeySize,
			Fingerprint:  meta.Fingerprint,
			StoredAt:     storedAt,
		})
	}

	return result, nil
}

// Import imports a certificate from external encoding.
//
// The data is parsed according to the specified format (DER or PEM)
// and stored in the given slot. This is a convenience method that
// combines parsing and storing.
func (fb *FileBackend) Import(slot pivcert.PIVSlot, data []byte, format pivcert.CertFormat) error {
	if len(data) == 0 {
		return pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidCertificate)
	}

	var cert *x509.Certificate
	var err error

	switch format {
	case pivcert.FormatDER:
		cert, err = x509.ParseCertificate(data)
		if err != nil {
			return pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidCertificate)
		}

	case pivcert.FormatPEM:
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidFormat)
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidCertificate)
		}

	default:
		return pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidFormat)
	}

	return fb.Store(slot, cert)
}

// Export exports a certificate in the specified format.
//
// Returns the certificate encoded in DER or PEM format.
// Returns ErrCertificateNotFound if no certificate exists in the slot.
func (fb *FileBackend) Export(slot pivcert.PIVSlot, format pivcert.CertFormat) ([]byte, error) {
	cert, err := fb.Retrieve(slot)
	if err != nil {
		return nil, err
	}

	switch format {
	case pivcert.FormatDER:
		return cert.Raw, nil

	case pivcert.FormatPEM:
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		return pemData, nil

	default:
		return nil, pivcert.NewStorageError("Export", slot, pivcert.ErrInvalidFormat)
	}
}

// Close releases any resources held by the storage.
//
// After Close is called, all other methods will return ErrStorageClosed.
func (fb *FileBackend) Close() error {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	fb.closed = true
	return fb.backend.Close()
}

// Type returns the storage type identifier.
func (fb *FileBackend) Type() pivcert.PIVStorageType {
	return pivcert.StorageTypeFile
}

// ensureMetadataInitialized creates the metadata file if it doesn't exist.
func (fb *FileBackend) ensureMetadataInitialized() error {
	exists, err := fb.backend.Exists(context.Background(), keySlotMetadata)
	if err != nil {
		return err
	}

	if !exists {
		metadata := &slotMetadataFile{
			Version: metadataVersion,
			Slots:   make(map[string]slotMetadata),
		}
		data, err := json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			return err
		}
		return fb.backend.Put(context.Background(), keySlotMetadata, data)
	}

	return nil
}

// loadMetadata loads the slot metadata from storage.
func (fb *FileBackend) loadMetadata() (*slotMetadataFile, error) {
	data, err := fb.backend.Get(context.Background(), keySlotMetadata)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return &slotMetadataFile{
				Version: metadataVersion,
				Slots:   make(map[string]slotMetadata),
			}, nil
		}
		return nil, err
	}

	var metadata slotMetadataFile
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}

	if metadata.Slots == nil {
		metadata.Slots = make(map[string]slotMetadata)
	}

	return &metadata, nil
}

// saveMetadata saves the slot metadata to storage.
func (fb *FileBackend) saveMetadata(metadata *slotMetadataFile) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return fb.backend.Put(context.Background(), keySlotMetadata, data)
}

// updateMetadata updates the metadata for a slot.
func (fb *FileBackend) updateMetadata(slot pivcert.PIVSlot, cert *x509.Certificate) error {
	metadata, err := fb.loadMetadata()
	if err != nil {
		return err
	}

	// Calculate fingerprint
	fingerprint := sha256.Sum256(cert.Raw)

	metadata.Slots[string(slot)] = slotMetadata{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.Text(16),
		NotBefore:    cert.NotBefore.Format(time.RFC3339),
		NotAfter:     cert.NotAfter.Format(time.RFC3339),
		Algorithm:    keyAlgorithmName(cert),
		KeySize:      keySize(cert),
		Fingerprint:  hex.EncodeToString(fingerprint[:]),
		StoredAt:     time.Now().UTC().Format(time.RFC3339),
	}

	return fb.saveMetadata(metadata)
}

// removeMetadata removes the metadata for a slot.
func (fb *FileBackend) removeMetadata(slot pivcert.PIVSlot) error {
	metadata, err := fb.loadMetadata()
	if err != nil {
		return err
	}

	delete(metadata.Slots, string(slot))
	return fb.saveMetadata(metadata)
}

// certKey returns the storage key for a certificate slot.
func certKey(slot pivcert.PIVSlot, ext string) string {
	return keyPrefixCertificates + string(slot) + ext
}

// keyAlgorithmName returns a human-readable name for the certificate's public key algorithm.
func keyAlgorithmName(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	case x509.DSA:
		return "DSA"
	default:
		return "Unknown"
	}
}

// keySize returns the key size in bits for the certificate's public key.
func keySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		// RSA keys have a Size() method that returns bytes
		return pub.Size() * 8
	case interface {
		Params() interface{ BitSize() int }
	}:
		// ECDSA keys have Params().BitSize()
		if params := pub.Params(); params != nil {
			return params.BitSize()
		}
		return 0
	default:
		// Ed25519 is always 256 bits
		if cert.PublicKeyAlgorithm == x509.Ed25519 {
			return 256
		}
		return 0
	}
}

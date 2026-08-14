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

// Package tpm2 provides a TPM 2.0 NV-backed PIV certificate storage adapter.
//
// The adapter delegates certificate storage to hardware.TPM2CertStorage,
// binding each PIV slot to an immutable NV certificate ID. See slotmodel.go for
// the slot to NV index mapping and why it is stable across process restarts.
//
// Example:
//
//	store, err := tpm2.New(&tpm2.Config{TPM: tpm})
//	if err != nil {
//	    return err
//	}
//	defer store.Close()
//
//	err = store.Store(pivcert.PIVSlotAuthentication, cert)
package tpm2

import (
	"crypto/x509"
	"encoding/pem"
	"sync/atomic"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
)

// Compile-time interface check.
var _ pivcert.PIVCertificateStorage = (*TPM2CertStorage)(nil)

const (
	// DefaultBaseIndex is the first NV index of the range PIV certificates are
	// stored in. It matches hardware.DefaultTPM2CertStorageConfig so a PIV
	// store and the general-purpose certificate store address NV RAM the same
	// way; records carry their own ID, so the two never overwrite each other.
	DefaultBaseIndex uint32 = 0x01800000

	// DefaultMaxCertSize is the maximum size of a single NV certificate record
	// in bytes, covering the PEM-encoded certificate and its ID header.
	DefaultMaxCertSize = 2048
)

// Config configures TPM2-backed PIV certificate storage.
type Config struct {
	// TPM is an open TPM 2.0 connection. Required.
	//
	// The connection stays owned by the caller: Close releases the PIV store
	// without closing the TPM, so a single TPM connection can back a PIV store
	// alongside the rest of the platform's TPM use.
	TPM transport.TPM

	// BaseIndex is the first NV index of the range certificates are stored in.
	// Zero selects DefaultBaseIndex. Must be a valid NV index
	// (0x01000000-0x01BFFFFF).
	BaseIndex uint32

	// MaxCertSize is the maximum NV record size in bytes. Zero selects
	// DefaultMaxCertSize. Must be between 512 and pivcert.MaxCertSizeTPM2.
	MaxCertSize int

	// OwnerAuth is the TPM owner hierarchy authorization value. NV indices are
	// defined, written and read under the owner hierarchy, so this must match
	// the TPM's owner authorization.
	OwnerAuth []byte
}

// Validate reports whether the configuration can back a PIV certificate store.
func (c *Config) Validate() error {
	if c == nil {
		return pivcert.NewStorageTypeError("validate", pivcert.StorageTypeTPM2, pivcert.ErrInvalidConfig)
	}

	if c.TPM == nil {
		return pivcert.NewStorageTypeError("validate", pivcert.StorageTypeTPM2, pivcert.ErrTPMNotAvailable)
	}

	if c.MaxCertSize > pivcert.MaxCertSizeTPM2 {
		return pivcert.NewStorageTypeError("validate", pivcert.StorageTypeTPM2, pivcert.ErrCertificateTooLarge)
	}

	return nil
}

// hardwareConfig renders the configuration as a hardware storage config,
// applying the PIV defaults for unset fields.
func (c *Config) hardwareConfig() *hardware.TPM2CertStorageConfig {
	config := &hardware.TPM2CertStorageConfig{
		BaseIndex:   c.BaseIndex,
		MaxCertSize: c.MaxCertSize,
		OwnerAuth:   c.OwnerAuth,
	}
	if config.BaseIndex == 0 {
		config.BaseIndex = DefaultBaseIndex
	}
	if config.MaxCertSize == 0 {
		config.MaxCertSize = DefaultMaxCertSize
	}
	return config
}

// retainedTPM adapts a caller-owned TPM connection to the transport.TPMCloser
// the hardware storage takes, without handing over its lifecycle: closing the
// PIV store must not close a TPM the rest of the platform is still using.
type retainedTPM struct {
	tpm transport.TPM
}

// Send forwards a command to the underlying TPM connection.
func (r *retainedTPM) Send(input []byte) ([]byte, error) {
	return r.tpm.Send(input)
}

// Close is a no-op: the TPM connection belongs to the caller.
func (r *retainedTPM) Close() error {
	return nil
}

// TPM2CertStorage implements pivcert.PIVCertificateStorage over TPM 2.0 NV RAM.
//
// It is safe for concurrent use: the underlying hardware storage serializes TPM
// access, and the closed flag is read and written atomically.
type TPM2CertStorage struct {
	hw     hardware.HardwareCertStorage
	closed atomic.Bool
}

// New creates TPM2-backed PIV certificate storage over an open TPM connection.
func New(config *Config) (*TPM2CertStorage, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	hw, err := hardware.NewTPM2CertStorage(&retainedTPM{tpm: config.TPM}, config.hardwareConfig())
	if err != nil {
		return nil, storageTypeError("New", err)
	}

	return &TPM2CertStorage{hw: hw}, nil
}

// NewFromCertStorage creates PIV certificate storage over an existing hardware
// certificate store, for callers that already built one for the TPM.
func NewFromCertStorage(hw hardware.HardwareCertStorage) (*TPM2CertStorage, error) {
	if hw == nil {
		return nil, pivcert.NewStorageTypeError("NewFromCertStorage", pivcert.StorageTypeTPM2, pivcert.ErrInvalidConfig)
	}
	return &TPM2CertStorage{hw: hw}, nil
}

// CertStorage returns the underlying hardware certificate store, so a caller
// can build the slot model over the same NV records this store writes.
func (s *TPM2CertStorage) CertStorage() hardware.HardwareCertStorage {
	return s.hw
}

// Store writes a certificate to the NV index bound to the given PIV slot.
//
// Storing over a populated slot replaces its certificate.
func (s *TPM2CertStorage) Store(slot pivcert.PIVSlot, cert *x509.Certificate) error {
	if s.closed.Load() {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrStorageClosed)
	}

	id, err := certIDFor(slot)
	if err != nil {
		return pivcert.NewStorageError("Store", slot, err)
	}

	if cert == nil {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrInvalidCertificate)
	}
	if len(cert.Raw) > pivcert.MaxCertSizeTPM2 {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrCertificateTooLarge)
	}

	if err := s.hw.SaveCert(id, cert); err != nil {
		return storageError("Store", slot, err)
	}

	return nil
}

// Retrieve reads the certificate stored for the given PIV slot.
func (s *TPM2CertStorage) Retrieve(slot pivcert.PIVSlot) (*x509.Certificate, error) {
	if s.closed.Load() {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrStorageClosed)
	}

	id, err := certIDFor(slot)
	if err != nil {
		return nil, pivcert.NewStorageError("Retrieve", slot, err)
	}

	cert, err := s.hw.GetCert(id)
	if err != nil {
		return nil, storageError("Retrieve", slot, err)
	}

	return cert, nil
}

// Delete undefines the NV index holding the given slot's certificate.
//
// Returns pivcert.ErrCertificateNotFound when the slot holds no certificate.
func (s *TPM2CertStorage) Delete(slot pivcert.PIVSlot) error {
	if s.closed.Load() {
		return pivcert.NewStorageError("Delete", slot, pivcert.ErrStorageClosed)
	}

	id, err := certIDFor(slot)
	if err != nil {
		return pivcert.NewStorageError("Delete", slot, err)
	}

	// The hardware layer deletes idempotently; the PIV contract reports an
	// empty slot instead.
	exists, err := s.hw.CertExists(id)
	if err != nil {
		return storageError("Delete", slot, err)
	}
	if !exists {
		return pivcert.NewStorageError("Delete", slot, pivcert.ErrCertificateNotFound)
	}

	if err := s.hw.DeleteCert(id); err != nil {
		return storageError("Delete", slot, err)
	}

	return nil
}

// List returns information about every PIV slot holding a certificate.
//
// NV records written by other subsystems into the same index range are ignored.
// The reported StoredAt is the time of the listing: NV RAM records no write
// timestamp.
func (s *TPM2CertStorage) List() ([]pivcert.PIVSlotInfo, error) {
	if s.closed.Load() {
		return nil, pivcert.NewStorageTypeError("List", pivcert.StorageTypeTPM2, pivcert.ErrStorageClosed)
	}

	ids, err := s.hw.ListCerts()
	if err != nil {
		return nil, storageTypeError("List", err)
	}

	listedAt := time.Now().UTC()
	result := make([]pivcert.PIVSlotInfo, 0, len(ids))
	for _, id := range ids {
		slot, ok := certIDToPIVSlotMap[id]
		if !ok {
			continue
		}

		cert, err := s.hw.GetCert(id)
		if err != nil {
			return nil, storageError("List", slot, err)
		}

		result = append(result, pivcert.NewSlotInfo(slot, cert, listedAt))
	}

	return result, nil
}

// Import parses a DER- or PEM-encoded certificate and stores it in the slot.
func (s *TPM2CertStorage) Import(slot pivcert.PIVSlot, data []byte, format pivcert.CertFormat) error {
	if len(data) == 0 {
		return pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidCertificate)
	}

	cert, err := parseCertificate(slot, data, format)
	if err != nil {
		return err
	}

	return s.Store(slot, cert)
}

// Export returns the slot's certificate encoded in the requested format.
func (s *TPM2CertStorage) Export(slot pivcert.PIVSlot, format pivcert.CertFormat) ([]byte, error) {
	if !format.IsValid() {
		return nil, pivcert.NewStorageError("Export", slot, pivcert.ErrInvalidFormat)
	}

	cert, err := s.Retrieve(slot)
	if err != nil {
		return nil, err
	}

	if format == pivcert.FormatPEM {
		return pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: cert.Raw}), nil
	}

	return cert.Raw, nil
}

// Close releases the PIV store. The TPM connection supplied by the caller stays
// open. After Close every other method reports pivcert.ErrStorageClosed.
func (s *TPM2CertStorage) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return pivcert.NewStorageTypeError("Close", pivcert.StorageTypeTPM2, pivcert.ErrStorageClosed)
	}

	if err := s.hw.Close(); err != nil {
		return storageTypeError("Close", err)
	}

	return nil
}

// Type returns the storage type identifier.
func (s *TPM2CertStorage) Type() pivcert.PIVStorageType {
	return pivcert.StorageTypeTPM2
}

// certificatePEMType is the PEM block type of an X.509 certificate.
const certificatePEMType = "CERTIFICATE"

// parseCertificate decodes certificate data in the given format.
func parseCertificate(slot pivcert.PIVSlot, data []byte, format pivcert.CertFormat) (*x509.Certificate, error) {
	der := data

	switch format {
	case pivcert.FormatDER:
	case pivcert.FormatPEM:
		block, _ := pem.Decode(data)
		if block == nil || block.Type != certificatePEMType {
			return nil, pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidFormat)
		}
		der = block.Bytes
	default:
		return nil, pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidFormat)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, pivcert.NewStorageError("Import", slot, pivcert.ErrInvalidCertificate)
	}

	return cert, nil
}

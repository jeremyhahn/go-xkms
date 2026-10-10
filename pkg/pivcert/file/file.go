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

// Package file provides the software PIV certificate store.
//
// The FileBackend persists each slot's certificate as one go-qrdb DAO record
// in the DatabaseName database, keyed by the slot identifier. The record
// holds the DER encoding and the time it was stored; PEM is produced on
// export and slot metadata is derived from the certificate on List.
//
// All operations are safe for concurrent use.
package file

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"sort"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

const (
	// DatabaseName is the go-qrdb database the slot records live in.
	DatabaseName = "pivcert"

	// certEntityType is the entity type of a slot record.
	certEntityType = "piv_certificates"
)

// Compile-time interface compliance check.
var _ pivcert.PIVCertificateStorage = (*FileBackend)(nil)

// certEntity is the certificate stored in one PIV slot.
type certEntity struct {
	ID uint64 `json:"id"`

	// Slot is the natural key: the PIV slot identifier.
	Slot string `json:"slot"`

	// DER is the certificate's DER encoding.
	DER []byte `json:"der"`

	// StoredAt is when the certificate was stored.
	StoredAt time.Time `json:"stored_at"`
}

// EntityID returns the entity's ID.
func (e *certEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the entity's ID.
func (e *certEntity) SetEntityID(id uint64) { e.ID = id }

// FileBackend implements PIVCertificateStorage over go-qrdb DAOs.
type FileBackend struct {
	certs  qrdbsdk.GenericDAO[*certEntity]
	closed atomic.Bool
}

// NewFileBackend returns the PIV certificate store over the DAO factory in
// config. The composition root owns the factory; Close does not release it.
//
// Returns an error if the configuration is invalid or the factory cannot
// open DatabaseName.
func NewFileBackend(config *pivcert.FileStorageConfig) (*FileBackend, error) {
	if config == nil {
		return nil, pivcert.NewStorageTypeError("NewFileBackend", pivcert.StorageTypeFile, pivcert.ErrInvalidConfig)
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	certs, err := dao.New(config.DAOs, DatabaseName, certEntityType,
		func() *certEntity { return &certEntity{} },
		qrdbsdk.WithIDGenerator(qrdbsdk.NewCryptoFieldHashGenerator("Slot")))
	if err != nil {
		return nil, pivcert.NewStorageTypeError("NewFileBackend", pivcert.StorageTypeFile, err)
	}

	return &FileBackend{certs: certs}, nil
}

// Store stores a certificate for the given slot, replacing any certificate
// already there.
//
// Returns an error if the slot is invalid, the storage is closed,
// or the write fails.
func (fb *FileBackend) Store(slot pivcert.PIVSlot, cert *x509.Certificate) error {
	if fb.closed.Load() {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrStorageClosed)
	}

	if !slot.IsValid() {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrInvalidSlot)
	}

	if cert == nil {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrInvalidCertificate)
	}

	if len(cert.Raw) > pivcert.MaxCertSizeFile {
		return pivcert.NewStorageError("Store", slot, pivcert.ErrCertificateTooLarge)
	}

	entity := &certEntity{
		Slot:     string(slot),
		DER:      cert.Raw,
		StoredAt: time.Now().UTC(),
	}
	if err := fb.certs.Save(context.Background(), entity); err != nil {
		return pivcert.NewStorageError("Store", slot, err)
	}

	return nil
}

// Retrieve retrieves the certificate for the given slot.
//
// Returns ErrCertificateNotFound if no certificate exists in the slot.
func (fb *FileBackend) Retrieve(slot pivcert.PIVSlot) (*x509.Certificate, error) {
	if fb.closed.Load() {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrStorageClosed)
	}

	if !slot.IsValid() {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrInvalidSlot)
	}

	entity, err := fb.load(slot)
	if err != nil {
		return nil, pivcert.NewStorageError("Retrieve", slot, err)
	}

	cert, err := x509.ParseCertificate(entity.DER)
	if err != nil {
		return nil, pivcert.NewStorageError("Retrieve", slot, pivcert.ErrInvalidCertificate)
	}

	return cert, nil
}

// Delete removes the certificate from the given slot.
//
// Returns ErrCertificateNotFound if no certificate exists in the slot, and
// ErrConflict if the slot was replaced between reading and deleting it.
func (fb *FileBackend) Delete(slot pivcert.PIVSlot) error {
	if fb.closed.Load() {
		return pivcert.NewStorageError("Delete", slot, pivcert.ErrStorageClosed)
	}

	if !slot.IsValid() {
		return pivcert.NewStorageError("Delete", slot, pivcert.ErrInvalidSlot)
	}

	entity, err := fb.load(slot)
	if err != nil {
		return pivcert.NewStorageError("Delete", slot, err)
	}

	deleted, err := fb.certs.DeleteIfMatch(context.Background(), entity)
	if err != nil {
		return pivcert.NewStorageError("Delete", slot, err)
	}
	if !deleted {
		return pivcert.NewStorageError("Delete", slot, pivcert.ErrConflict)
	}

	return nil
}

// List returns all slots that contain certificates, sorted by slot.
//
// The slot information is derived from each stored certificate and
// includes its subject, issuer, validity period, and key algorithm.
func (fb *FileBackend) List() ([]pivcert.PIVSlotInfo, error) {
	if fb.closed.Load() {
		return nil, pivcert.NewStorageTypeError("List", pivcert.StorageTypeFile, pivcert.ErrStorageClosed)
	}

	entities, err := fb.certs.Find(context.Background()).Execute()
	if err != nil {
		return nil, pivcert.NewStorageTypeError("List", pivcert.StorageTypeFile, err)
	}

	result := make([]pivcert.PIVSlotInfo, 0, len(entities))
	for _, entity := range entities {
		slot := pivcert.PIVSlot(entity.Slot)
		cert, err := x509.ParseCertificate(entity.DER)
		if err != nil {
			return nil, pivcert.NewStorageError("List", slot, pivcert.ErrInvalidCertificate)
		}
		result = append(result, pivcert.NewSlotInfo(slot, cert, entity.StoredAt))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Slot < result[j].Slot })

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

// Close marks the storage closed. After Close is called, all other methods
// return ErrStorageClosed. The DAO factory stays open: its owner releases
// it.
func (fb *FileBackend) Close() error {
	fb.closed.Store(true)
	return nil
}

// Type returns the storage type identifier.
func (fb *FileBackend) Type() pivcert.PIVStorageType {
	return pivcert.StorageTypeFile
}

// load returns the record of slot, or ErrCertificateNotFound when there is
// none.
func (fb *FileBackend) load(slot pivcert.PIVSlot) (*certEntity, error) {
	entity, err := fb.certs.GetByNaturalKey(context.Background(), string(slot))
	if qrdbsdk.IsDAONotFound(err) {
		return nil, pivcert.ErrCertificateNotFound
	}
	if err != nil {
		return nil, err
	}
	return entity, nil
}

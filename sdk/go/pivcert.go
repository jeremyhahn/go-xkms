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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/pivcert"

// PIV certificate-storage surface re-exported so the xkey GUI/CLI reach the
// canonical pkg/pivcert slot model and storage backends through the SDK. The
// generic format/config identifiers carry a PIV prefix to stay unambiguous in
// the flat SDK namespace; the PIVSlot* identifiers are already prefixed.

// --- Storage interface and configs ---

// PIVCertificateStorage is the slot-addressable certificate storage interface.
type PIVCertificateStorage = pivcert.PIVCertificateStorage

// PIVFileStorageConfig configures the file-backed PIV certificate store.
type PIVFileStorageConfig = pivcert.FileStorageConfig

// PIVPKCS11StorageConfig configures the PKCS#11-backed PIV certificate store.
type PIVPKCS11StorageConfig = pivcert.PKCS11StorageConfig

// PIVStorageType identifies a PIV certificate storage backend kind.
type PIVStorageType = pivcert.PIVStorageType

// --- Slot model ---

// PIVSlot identifies a PIV slot.
type PIVSlot = pivcert.PIVSlot

// PIVSlotInfo describes a PIV slot's purpose.
type PIVSlotInfo = pivcert.PIVSlotInfo

// PIVSlotModel models the standard PIV slot layout.
type PIVSlotModel = pivcert.SlotModel

// PIVSlotOccupancyInfo reports whether a slot is populated.
type PIVSlotOccupancyInfo = pivcert.SlotOccupancyInfo

// --- Certificate format ---

// PIVCertFormat identifies a certificate encoding.
type PIVCertFormat = pivcert.CertFormat

const (
	// PIVFormatDER is the DER certificate encoding.
	PIVFormatDER = pivcert.FormatDER
	// PIVFormatPEM is the PEM certificate encoding.
	PIVFormatPEM = pivcert.FormatPEM
)

// PIVMaxCertSizeFile is the maximum stored certificate size for the file backend.
const PIVMaxCertSizeFile = pivcert.MaxCertSizeFile

// --- Storage type constants ---

const (
	// PIVStorageTypeFile selects the file-backed PIV store.
	PIVStorageTypeFile = pivcert.StorageTypeFile
	// PIVStorageTypePKCS11 selects the PKCS#11-backed PIV store.
	PIVStorageTypePKCS11 = pivcert.StorageTypePKCS11
)

// --- Slot constants ---

const (
	// PIVSlotAuthentication is the PIV authentication slot (9A).
	PIVSlotAuthentication = pivcert.PIVSlotAuthentication
	// PIVSlotDigitalSignature is the PIV digital-signature slot (9C).
	PIVSlotDigitalSignature = pivcert.PIVSlotDigitalSignature
	// PIVSlotKeyManagement is the PIV key-management slot (9D).
	PIVSlotKeyManagement = pivcert.PIVSlotKeyManagement
	// PIVSlotCardAuthentication is the PIV card-authentication slot (9E).
	PIVSlotCardAuthentication = pivcert.PIVSlotCardAuthentication
	// PIVSlotRetired1 is retired key-management slot 82.
	PIVSlotRetired1 = pivcert.PIVSlotRetired1
	// PIVSlotRetired2 is retired key-management slot 83.
	PIVSlotRetired2 = pivcert.PIVSlotRetired2
	// PIVSlotRetired3 is retired key-management slot 84.
	PIVSlotRetired3 = pivcert.PIVSlotRetired3
)

// --- Helpers ---

// PIVPrimarySlots returns the primary (non-retired) PIV slots.
var PIVPrimarySlots = pivcert.PrimarySlots

// PIVSlotName returns the human-readable name for a PIV slot.
var PIVSlotName = pivcert.SlotName

// ValidatePIVSlot validates a PIV slot value.
var ValidatePIVSlot = pivcert.ValidateSlot

// NewPIVStorageError constructs a slot-scoped PIV storage error.
var NewPIVStorageError = pivcert.NewStorageError

// NewPIVStorageTypeError constructs a storage-type-scoped PIV storage error.
var NewPIVStorageTypeError = pivcert.NewStorageTypeError

// --- Sentinel errors ---
//
// ErrPIVCertificateNotFound and ErrPIVStorageClosed carry a PIV prefix because
// the bare ErrCertificateNotFound (xkms.go) and ErrStorageClosed (storage.go,
// = storage.ErrClosed) SDK names already alias different error values.

var (
	// ErrPIVCertificateNotFound is returned when a PIV certificate is missing.
	ErrPIVCertificateNotFound = pivcert.ErrCertificateNotFound
	// ErrPIVStorageClosed is returned when operating on a closed PIV store.
	ErrPIVStorageClosed = pivcert.ErrStorageClosed
	// ErrPIVCertificateTooLarge is returned when a certificate exceeds the store limit.
	ErrPIVCertificateTooLarge = pivcert.ErrCertificateTooLarge
	// ErrPIVInvalidCertificate is returned for a malformed certificate.
	ErrPIVInvalidCertificate = pivcert.ErrInvalidCertificate
	// ErrPIVInvalidConfig is returned for an invalid storage configuration.
	ErrPIVInvalidConfig = pivcert.ErrInvalidConfig
	// ErrPIVInvalidFormat is returned for an unsupported certificate format.
	ErrPIVInvalidFormat = pivcert.ErrInvalidFormat
	// ErrPIVInvalidSlot is returned for an invalid slot value.
	ErrPIVInvalidSlot = pivcert.ErrInvalidSlot
	// ErrPIVMissingBackend is returned when no storage backend is configured.
	ErrPIVMissingBackend = pivcert.ErrMissingBackend
	// ErrPIVNoAvailableSlot is returned when no slot is free.
	ErrPIVNoAvailableSlot = pivcert.ErrNoAvailableSlot
	// ErrPIVNoFormatEnabled is returned when no certificate format is enabled.
	ErrPIVNoFormatEnabled = pivcert.ErrNoFormatEnabled
	// ErrPIVPKCS11NotAvailable is returned when the PKCS#11 backend is unavailable.
	ErrPIVPKCS11NotAvailable = pivcert.ErrPKCS11NotAvailable
)

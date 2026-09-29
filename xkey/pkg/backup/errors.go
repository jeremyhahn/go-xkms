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

package backup

import (
	"errors"
	"fmt"
)

var (
	// ErrNilConfig is returned when a nil config is passed to NewService.
	ErrNilConfig = errors.New("backup: nil config")

	// ErrNilTrustStore is returned when a nil trust store reader is
	// required but not provided.
	ErrNilTrustStore = errors.New("backup: nil trust store")

	// ErrEmptyBackup is returned when no data sources produced any data
	// to back up.
	ErrEmptyBackup = errors.New("backup: no data to backup")

	// ErrInvalidBackup is returned when backup data fails structural
	// validation (wrong magic bytes, etc.).
	ErrInvalidBackup = errors.New("backup: invalid backup data")

	// ErrCorruptedBackup is returned when the checksum in the manifest
	// does not match the computed checksum of the payload.
	ErrCorruptedBackup = errors.New("backup: checksum mismatch")

	// ErrVersionMismatch is returned when the backup version is not
	// supported by this service.
	ErrVersionMismatch = errors.New("backup: unsupported backup version")

	// ErrEncryptionFailed is returned when AEAD encryption fails.
	ErrEncryptionFailed = errors.New("backup: encryption failed")

	// ErrDecryptionFailed is returned when AEAD decryption fails.
	ErrDecryptionFailed = errors.New("backup: decryption failed")

	// ErrCollectFailed is returned when a data source fails during
	// backup collection.
	ErrCollectFailed = errors.New("backup: data collection failed")

	// ErrRestoreFailed is returned when a restore operation fails.
	ErrRestoreFailed = errors.New("backup: restore failed")

	// ErrBackupNotFound is returned when the requested backup does not
	// exist.
	ErrBackupNotFound = errors.New("backup: backup not found")

	// ErrProtectedMemory reports that an OATHCredentialInfo secret or a
	// PasswordInfo password could not be placed in mlocked protected
	// memory. The value is never kept on the ordinary heap as a fallback
	// (go-xkms#587).
	ErrProtectedMemory = errors.New("backup: protected memory allocation failed")

	// ErrLegacyBackupFormat is returned for a version 1 envelope. Version 1
	// keyed its cipher with an unsalted SHA-256 of the password and carried
	// no KDF record; such files are refused, never migrated (go-xkms#1202).
	ErrLegacyBackupFormat = errors.New("backup: unsalted version 1 backup format is no longer supported; re-create the backup")

	// ErrInvalidKey is returned for a sealing key that is not KeySize bytes.
	ErrInvalidKey = errors.New("backup: invalid sealing key")

	// ErrKeyDerivationFailed is returned when a sealing key cannot be
	// generated or derived from a password, including when the envelope's
	// KDF record does not match the parameters its version pins.
	ErrKeyDerivationFailed = errors.New("backup: key derivation failed")

	// ErrNotPasswordSealed is returned when a password is offered for an
	// envelope that was sealed with a raw key and so carries no KDF record.
	ErrNotPasswordSealed = errors.New("backup: backup was sealed with a raw key, not a password")

	// ErrMissingRecordedPurpose is returned when an archived trust-store
	// certificate carries no recorded purpose. Restore refuses it rather
	// than auto-classifying it (#1312).
	ErrMissingRecordedPurpose = errors.New("backup: certificate has no recorded purpose")

	// ErrInvalidRecordedPurpose is returned when an archived trust-store
	// certificate's recorded purpose is not a recognized trust-store purpose.
	ErrInvalidRecordedPurpose = errors.New("backup: certificate has an invalid recorded purpose")
)

// RecordedPurposeError reports an archived trust-store certificate whose
// recorded purpose restore refuses. It matches ErrRestoreFailed and its Err
// (ErrMissingRecordedPurpose or ErrInvalidRecordedPurpose) under errors.Is.
type RecordedPurposeError struct {
	// Fingerprint identifies the refused certificate.
	Fingerprint string

	// Purpose is the purpose the archive recorded, empty when none was.
	Purpose string

	// Err is the reason for the refusal.
	Err error
}

// Error implements the error interface.
func (e *RecordedPurposeError) Error() string {
	return fmt.Sprintf("%s (certificate %s, purpose %q)", e.Err.Error(), e.Fingerprint, e.Purpose)
}

// Unwrap returns ErrRestoreFailed and the refusal reason for errors.Is /
// errors.As.
func (e *RecordedPurposeError) Unwrap() []error {
	return []error{ErrRestoreFailed, e.Err}
}

// DetailError appends detail text directly after a wrapped error while
// preserving errors.Is / errors.As matching of the wrapped error through
// Unwrap. The detail text carries its own leading separator.
type DetailError struct {
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *DetailError) Error() string {
	return e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *DetailError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

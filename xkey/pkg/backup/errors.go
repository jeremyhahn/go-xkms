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

import "errors"

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
)

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

// Package luks provides a storage.Backend implementation backed by a LUKS
// encrypted volume. All key-value operations are delegated to a file-based
// storage backend whose root directory resides on the mounted LUKS volume.
// Operations are rejected with ErrVolumeLocked when the volume is not open.
package luks

// VolumeOperator abstracts LUKS volume lifecycle operations.
// This interface decouples the storage backend from any concrete LUKS
// implementation, preventing import cycles between the main module and
// the xkey module whose luks.Volume satisfies this contract.
type VolumeOperator interface {
	// Exists reports whether the LUKS container file exists on disk.
	Exists() bool

	// IsLUKS reports whether the container file is a valid LUKS volume.
	IsLUKS() bool

	// IsMounted reports whether the volume is currently mounted.
	IsMounted() bool

	// IsOpen reports whether the LUKS volume is currently unlocked.
	IsOpen() bool

	// GetMountPoint returns the filesystem path where the volume is mounted.
	GetMountPoint() string

	// Create creates a new LUKS volume of the given size and formats it
	// with the supplied passphrase.
	Create(sizeBytes int64, passphrase string) error

	// Unlock opens the LUKS volume and mounts it using the given passphrase.
	Unlock(passphrase string) error

	// Lock unmounts and closes the LUKS volume.
	Lock() error
}

// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

import (
	luksstorage "github.com/jeremyhahn/go-xkms/pkg/storage/luks"
)

// LUKS-gated storage surface re-exported from pkg/storage/luks so SDK
// consumers (xkey, and any future LUKS-backed front end) construct a
// storage.Backend that fails closed while its LUKS volume is locked without
// importing go-xkms/pkg/storage/luks directly. The symbols below complement
// StorageBackend (storage.go): LUKSStorageBackend additionally implements
// volume lifecycle (Initialize/Unlock/Attach/Lock/IsUnlocked) on top of the
// Get/Put/Delete/List/Scan/Exists/Close surface every StorageBackend has.
type (
	// LUKSStorageBackend is a StorageBackend implementation gated by a LUKS
	// encrypted volume's lock state. Every storage operation returns
	// ErrLUKSVolumeLocked while the volume is locked; once Unlock or Attach
	// succeeds, operations delegate to a file-based backend rooted at the
	// volume's mount point.
	LUKSStorageBackend = luksstorage.Backend

	// LUKSVolumeOperator abstracts LUKS volume lifecycle operations so a
	// LUKSStorageBackend can be constructed over any conforming volume type
	// without go-xkms importing that type's package. xkey's own luks.Volume
	// satisfies this interface structurally.
	LUKSVolumeOperator = luksstorage.VolumeOperator
)

// NewLUKSStorageBackend creates a new LUKSStorageBackend wrapping the given
// volume. The backend starts in the locked state; call Initialize, Unlock,
// or Attach before performing storage operations.
var NewLUKSStorageBackend = luksstorage.NewBackend

// LUKS storage error sentinels re-exported from pkg/storage/luks.
var (
	// ErrLUKSVolumeLocked is returned when a storage operation is attempted
	// while the LUKS volume is locked.
	ErrLUKSVolumeLocked = luksstorage.ErrVolumeLocked

	// ErrLUKSVolumeAlreadyUnlocked is returned when Unlock or Attach is
	// called on a backend whose volume is already unlocked.
	ErrLUKSVolumeAlreadyUnlocked = luksstorage.ErrVolumeAlreadyUnlocked

	// ErrLUKSVolumeNotInitialized is returned when operating on a volume
	// that has not been created yet.
	ErrLUKSVolumeNotInitialized = luksstorage.ErrVolumeNotInitialized

	// ErrLUKSVolumeNotMounted is returned by Attach when the volume exists
	// but is not currently mounted by any process.
	ErrLUKSVolumeNotMounted = luksstorage.ErrVolumeNotMounted

	// ErrLUKSInitializeRequiresPassphrase is returned when Initialize is
	// called with an empty passphrase.
	ErrLUKSInitializeRequiresPassphrase = luksstorage.ErrInitializeRequiresPassphrase

	// ErrLUKSDelegateCreateFailed is returned when the file storage delegate
	// cannot be created on the mounted volume.
	ErrLUKSDelegateCreateFailed = luksstorage.ErrDelegateCreateFailed

	// ErrLUKSVolumeLockFailed is returned when the volume cannot be locked.
	ErrLUKSVolumeLockFailed = luksstorage.ErrVolumeLockFailed
)

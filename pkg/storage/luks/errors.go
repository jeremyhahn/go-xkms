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

package luks

import "errors"

var (
	// ErrVolumeLocked is returned when a storage operation is attempted
	// while the LUKS volume is locked.
	ErrVolumeLocked = errors.New("luks storage: volume is locked")

	// ErrVolumeAlreadyUnlocked is returned when Unlock is called on a
	// backend whose volume is already unlocked.
	ErrVolumeAlreadyUnlocked = errors.New("luks storage: volume is already unlocked")

	// ErrVolumeNotInitialized is returned when operating on a volume
	// that has not been created yet.
	ErrVolumeNotInitialized = errors.New("luks storage: volume does not exist")

	// ErrInitializeRequiresPassphrase is returned when Initialize is
	// called with an empty passphrase.
	ErrInitializeRequiresPassphrase = errors.New("luks storage: passphrase is required for initialization")

	// ErrDelegateCreateFailed is returned when the file storage delegate
	// cannot be created on the mounted volume.
	ErrDelegateCreateFailed = errors.New("luks storage: failed to create delegate backend")

	// ErrVolumeLockFailed is returned when the volume cannot be locked.
	ErrVolumeLockFailed = errors.New("luks storage: failed to lock volume")
)

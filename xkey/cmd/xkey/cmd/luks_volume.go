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

package cmd

import "github.com/jeremyhahn/go-xkms/xkey/pkg/luks"

// luksVolume is the *luks.Volume behaviour the luks2 commands (seal, unseal,
// lock, migrate, import-data) drive: the container file, its mount and
// device-mapper state, and the dm-crypt operations on it.
type luksVolume interface {
	GetMountPoint() string
	Exists() bool
	IsMounted() (bool, error)
	IsOpen() bool
	Create(sizeBytes int64, passphrase string) error
	Unlock(passphrase string) error
	Lock() error
	CopyDataToVolume(sourceDir string) error
}

// Compile-time check that *luks.Volume satisfies luksVolume.
var _ luksVolume = (*luks.Volume)(nil)

// openLUKSVolume returns the operations for vol. The commands keep vol for
// its paths and run every host operation through the result, so tests can
// drive each flow and failure without a LUKS container, loop device, mount
// or root. The returned value must observe later changes to vol's fields.
var openLUKSVolume = func(vol *luks.Volume) luksVolume { return vol }

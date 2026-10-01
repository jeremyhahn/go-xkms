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

import (
	"os"
	"path/filepath"
	"strings"

	sdkluks "github.com/jeremyhahn/go-xkms/sdk/go/luks"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// MapperName is the device-mapper name for the LUKS volume.
const MapperName = "xkey"

// IsLUKSVolume checks if the given file is a LUKS volume by reading the
// magic header. It forwards to go-xkms/pkg/luks's canonical implementation.
func IsLUKSVolume(path string) bool {
	return sdkluks.IsLUKSVolume(path)
}

// checkMounted and checkUnlocked forward to go-xkms/pkg/luks's canonical
// mount/unlock-state checks. Each is a package variable, following the same
// pattern as checkKeyringAvailable used to (see keyring.go's history), so
// unit tests can stand in for the kernel instead of requiring a real mount
// or dm-crypt mapping.
var (
	checkMounted  = sdkluks.IsMounted
	checkUnlocked = sdkluks.IsUnlocked
)

// IsMounted checks if the data directory is currently mounted. It returns
// an error when the mount state could not be determined; callers must not
// treat that as "not mounted".
func IsMounted(mountPoint string) (bool, error) {
	return checkMounted(mountPoint)
}

// IsLUKSOpen checks if the LUKS volume is currently unlocked.
func IsLUKSOpen(mapperName string) bool {
	return checkUnlocked(mapperName)
}

// NewVolumeFromHome creates a Volume using paths from the unified xhome.Home.
// The LUKS file is at Home.LUKSPath() and the mount point is Home.MountPoint().
func NewVolumeFromHome(h *xhome.Home) *Volume {
	return &Volume{
		LUKSPath:   h.LUKSPath(),
		MountPoint: h.MountPoint(),
		MapperName: MapperName,
	}
}

// ExpandPath expands ~ to home directory.
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

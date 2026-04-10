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

	"github.com/jeremyhahn/go-luks2/pkg/luks2"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

const (
	// DefaultLUKSFile is the default LUKS container file path.
	//
	// Deprecated: Use xhome.Home.LUKSPath() for unified path resolution.
	DefaultLUKSFile = ".xkey.luks"

	// DefaultDataDir is the default data directory (mount point).
	//
	// Deprecated: Use xhome.Home.MountPoint() for unified path resolution.
	DefaultDataDir = ".xkey"

	// MapperName is the device-mapper name for the LUKS volume.
	MapperName = "xkey"
)

// LUKS2 magic bytes: "LUKS" followed by 0xba 0xbe.
var luks2Magic = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}

// GetDefaultLUKSPath returns the default LUKS file path.
func GetDefaultLUKSPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", &VolumeError{Operation: "get_home", Err: err}
	}
	return filepath.Join(home, DefaultLUKSFile), nil
}

// GetDefaultDataDir returns the default data directory path.
func GetDefaultDataDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", &VolumeError{Operation: "get_home", Err: err}
	}
	return filepath.Join(home, DefaultDataDir), nil
}

// IsLUKSVolume checks if the given file is a LUKS volume by reading the magic header.
func IsLUKSVolume(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// Read the first 6 bytes (LUKS magic)
	magic := make([]byte, 6)
	n, err := f.Read(magic)
	if err != nil || n < 6 {
		return false
	}

	// Check for LUKS magic
	for i := 0; i < 6; i++ {
		if magic[i] != luks2Magic[i] {
			return false
		}
	}
	return true
}

// IsMounted checks if the data directory is currently mounted.
func IsMounted(mountPoint string) bool {
	mounted, _ := luks2.IsMounted(mountPoint)
	return mounted
}

// IsLUKSOpen checks if the LUKS volume is currently unlocked.
func IsLUKSOpen(mapperName string) bool {
	return luks2.IsUnlocked(mapperName)
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

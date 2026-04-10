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

package tpm2

import (
	"bytes"
	"os"
)

// DMI sysfs paths for platform attributes
const (
	dmiBasePath       = "/sys/class/dmi/id"
	dmiSysVendor      = "sys_vendor"
	dmiProductName    = "product_name"
	dmiProductVersion = "product_version"
	dmiProductSerial  = "product_serial"
)

// PlatformAttributes contains device platform identification attributes
// discovered from SMBIOS/DMI or provided via configuration.
type PlatformAttributes struct {
	Manufacturer string
	Model        string
	Version      string
	Serial       string
}

// DiscoverPlatformAttributes reads platform identification attributes from
// SMBIOS/DMI via the Linux sysfs interface. Returns a PlatformAttributes
// struct with discovered values. Fields that cannot be read are left empty.
//
// The following sysfs files are read:
//   - /sys/class/dmi/id/sys_vendor -> Manufacturer
//   - /sys/class/dmi/id/product_name -> Model
//   - /sys/class/dmi/id/product_version -> Version
//   - /sys/class/dmi/id/product_serial -> Serial
func DiscoverPlatformAttributes() *PlatformAttributes {
	return &PlatformAttributes{
		Manufacturer: readDMIFile(dmiSysVendor),
		Model:        readDMIFile(dmiProductName),
		Version:      readDMIFile(dmiProductVersion),
		Serial:       readDMIFile(dmiProductSerial),
	}
}

// ResolvePlatformAttributes returns platform attributes using config values
// when available, falling back to SMBIOS/DMI discovery for empty config fields.
// This implements config-first-then-SMBIOS fallback logic.
func ResolvePlatformAttributes(config *IDevIDConfig) *PlatformAttributes {
	if config == nil {
		return DiscoverPlatformAttributes()
	}

	// Start with discovered attributes
	discovered := DiscoverPlatformAttributes()

	// Override with config values where specified
	result := &PlatformAttributes{
		Manufacturer: resolveAttribute(config.Manufacturer, discovered.Manufacturer),
		Model:        resolveAttribute(config.Model, discovered.Model),
		Version:      resolveAttribute(config.Version, discovered.Version),
		Serial:       resolveAttribute(config.Serial, discovered.Serial),
	}

	return result
}

// resolveAttribute returns the config value if non-empty, otherwise the discovered value.
func resolveAttribute(configValue, discoveredValue string) string {
	if configValue != "" {
		return configValue
	}
	return discoveredValue
}

// readDMIFile reads a single DMI attribute file from sysfs.
// Returns empty string if the file cannot be read or is empty.
func readDMIFile(filename string) string {
	path := dmiBasePath + "/" + filename
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(data))
}

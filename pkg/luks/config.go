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

import "github.com/jeremyhahn/go-xkms/pkg/crypto/fips"

// KDFType identifies a key derivation function used by LUKS.
type KDFType string

const (
	// KDFArgon2id selects the Argon2id KDF. This is the default for
	// non-FIPS environments and provides strong memory-hard resistance
	// against brute-force attacks.
	KDFArgon2id KDFType = "argon2id"

	// KDFPBKDF2 selects the PBKDF2-HMAC-SHA256 KDF. This is the required
	// default in FIPS 140 mode because Argon2 is not FIPS-approved.
	KDFPBKDF2 KDFType = "pbkdf2"

	// defaultPBKDFIterTime is the default PBKDF2 iteration time in
	// milliseconds, following the cryptsetup default.
	defaultPBKDFIterTime = 2000
)

// validKDFs is a lookup table of supported KDF types for O(1) validation.
var validKDFs = map[KDFType]struct{}{
	KDFArgon2id: {},
	KDFPBKDF2:   {},
}

// VolumeConfig holds the configuration for a LUKS encrypted volume.
type VolumeConfig struct {
	// LUKSPath is the filesystem path to the LUKS container file.
	LUKSPath string

	// MountPoint is the directory where the unlocked volume is mounted.
	MountPoint string

	// MapperName is the device mapper name (e.g., "xkms-vault") used by
	// cryptsetup to identify the unlocked device under /dev/mapper/.
	MapperName string

	// KDF is the key derivation function for LUKS key slot processing.
	// When empty, SetDefaults selects a FIPS-appropriate default.
	KDF KDFType

	// PBKDFIterTime is the PBKDF2 iteration time in milliseconds. A
	// higher value increases resistance to brute-force attacks at the
	// cost of slower unlock times. Defaults to 2000 ms.
	PBKDFIterTime int
}

// DefaultKDF returns the FIPS-appropriate default KDF type. In FIPS 140 mode
// it returns KDFPBKDF2; otherwise it returns KDFArgon2id.
func DefaultKDF() KDFType {
	if fips.Enabled() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}

// Validate checks the VolumeConfig for required fields and valid values.
// It returns ErrInvalidConfig when a required path or name is empty, and
// ErrInvalidKDF when a non-empty KDF is not a recognised type.
func (c *VolumeConfig) Validate() error {
	if c.LUKSPath == "" {
		return ErrInvalidConfig
	}
	if c.MountPoint == "" {
		return ErrInvalidConfig
	}
	if c.MapperName == "" {
		return ErrInvalidConfig
	}
	if c.KDF != "" {
		if _, ok := validKDFs[c.KDF]; !ok {
			return ErrInvalidKDF
		}
	}
	return nil
}

// SetDefaults fills zero-value fields with sensible defaults. The KDF is
// chosen based on the current FIPS policy and PBKDFIterTime defaults to
// 2000 ms.
func (c *VolumeConfig) SetDefaults() {
	if c.KDF == "" {
		c.KDF = DefaultKDF()
	}
	if c.PBKDFIterTime == 0 {
		c.PBKDFIterTime = defaultPBKDFIterTime
	}
}

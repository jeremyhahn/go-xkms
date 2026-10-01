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
	"crypto/fips140"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

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
// (crypto/fips140.Enabled -- GODEBUG=fips140=on|only, or a GOFIPS140 build;
// go-xkms #21) it returns KDFPBKDF2; otherwise it returns KDFArgon2id.
func DefaultKDF() KDFType {
	if fips140.Enabled() {
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

// SealParent identifies which TPM storage hierarchy a LUKS passphrase seal
// is parented to. It is the configurable answer to go-xkms#917: previously
// pkg/luks always sealed under the Shared SRK with empty auth, an
// undocumented exception to go-xkms#681's PSRK-only rule. See
// docs/luks/architecture.md for the full tradeoff between the two modes.
type SealParent uint8

const (
	// SealParentPSRK seals under go-xkms's own Platform Storage Root Key,
	// bound to go-xkms's platform PCR policy (pkg/tpm2's "platform" policy)
	// and written as an xkms-native LUKS2 token (XKMSTPMTokenType). This is
	// the default: it keeps the sealed passphrase under the one storage
	// parent every other go-xkms secret is sealed under (go-xkms#681), and
	// unattended boot-time unlock goes through go-xkms's own auto-unseal
	// path (go-xkms#677) rather than systemd-cryptsetup. A LUKS volume
	// sealed this way can only be unlocked by go-xkms itself.
	SealParentPSRK SealParent = iota

	// SealParentSSRK seals under the TCG-standard Shared Storage Root Key
	// (handle 0x81000001) with empty parent auth, binding the sealed object
	// to a plain PolicyPCR digest over the caller-supplied PCR selection --
	// not go-xkms's platform policy -- and writing a systemd-tpm2
	// compatible LUKS2 token (TPMTokenType) so
	// systemd-cryptenroll/crypttab can unlock the volume at boot without
	// go-xkms running at all. This is a deliberate, narrow exception to
	// go-xkms's PSRK-only sealing rule (go-xkms#681), scoped to LUKS boot
	// tokens.
	//
	// TPMSealer can seal in this mode but does not unseal it: pkg/tpm2's
	// Unseal only builds policy sessions for its platform policy or a
	// named/authorized policy, neither of which is a plain PolicyPCR
	// digest, so UnsealPassphrase refuses with ErrTPMSSRKUnsealUnsupported.
	// systemd-cryptsetup builds that session itself at boot.
	SealParentSSRK
)

// String returns the config-file spelling of the seal parent
// ("psrk"/"ssrk"), or "invalid" for an out-of-range value.
func (p SealParent) String() string {
	switch p {
	case SealParentPSRK:
		return "psrk"
	case SealParentSSRK:
		return "ssrk"
	default:
		return "invalid"
	}
}

// Validate reports SealParentInvalidError when p is not a recognised value.
func (p SealParent) Validate() error {
	switch p {
	case SealParentPSRK, SealParentSSRK:
		return nil
	default:
		return &SealParentInvalidError{Value: uint8(p)}
	}
}

// ParseSealParent parses the config-file spelling of a seal parent
// ("psrk" or "ssrk", case-insensitive, surrounding whitespace ignored).
// An empty string resolves to SealParentPSRK, the default. Any other value
// returns a SealParentInvalidError.
func ParseSealParent(s string) (SealParent, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return SealParentPSRK, nil
	case "psrk":
		return SealParentPSRK, nil
	case "ssrk":
		return SealParentSSRK, nil
	default:
		return 0, &SealParentInvalidError{Raw: s}
	}
}

// TPMSealerConfig configures a TPMSealer's storage parent and, for
// SealParentSSRK, the PCR bank its PolicyPCR digest is computed over.
type TPMSealerConfig struct {
	// Parent selects the TPM storage hierarchy the sealed passphrase is
	// parented to. The zero value is SealParentPSRK.
	Parent SealParent `yaml:"parent" json:"parent" mapstructure:"parent"`

	// PCRBank names the PCR hash algorithm bank: "sha1", "sha256", "sha384"
	// or "sha512". Empty selects "sha256". Ignored for SealParentPSRK,
	// which always uses the platform policy's own configured bank.
	PCRBank string `yaml:"pcr-bank,omitempty" json:"pcr_bank" mapstructure:"pcr-bank"`
}

// SetDefaults fills PCRBank with "sha256" when empty.
func (c *TPMSealerConfig) SetDefaults() {
	if c.PCRBank == "" {
		c.PCRBank = "sha256"
	}
}

// Validate checks Parent and PCRBank. It returns SealParentInvalidError for
// an unrecognised Parent and ErrInvalidPCRBank for a PCRBank naming
// anything other than sha1, sha256, sha384 or sha512.
func (c *TPMSealerConfig) Validate() error {
	if err := c.Parent.Validate(); err != nil {
		return err
	}
	if c.PCRBank != "" {
		if _, ok := pcrBankAlgIDs[strings.ToLower(c.PCRBank)]; !ok {
			return &errs.Detail{Err: ErrInvalidPCRBank, Detail: c.PCRBank}
		}
	}
	return nil
}

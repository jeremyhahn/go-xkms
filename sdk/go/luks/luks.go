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

// Package luks re-exports go-xkms's canonical LUKS surface: the FIPS-aware
// volume configuration and lifecycle manager, its production go-luks2
// backed Executor, and the TPM 2.0 passphrase sealer with its configurable
// storage parent (Platform SRK or Shared SRK). Downstream consumers
// (go-quicbaas SDK shims, go-trusted-platform's LUKS backend, xkey) reach
// LUKS + TPM sealing through this package instead of importing
// go-xkms/pkg/luks directly.
package luks

import pkgluks "github.com/jeremyhahn/go-xkms/pkg/luks"

// =============================================================================
// Volume configuration + lifecycle
// =============================================================================

type (
	// KDFType identifies a key derivation function used by LUKS.
	KDFType = pkgluks.KDFType

	// VolumeConfig holds the configuration for a LUKS encrypted volume.
	VolumeConfig = pkgluks.VolumeConfig

	// Executor performs the actual LUKS volume operations.
	Executor = pkgluks.Executor

	// Manager manages the lifecycle of a LUKS encrypted volume.
	Manager = pkgluks.Manager

	// LibExecutor is the production Executor, implemented on go-luks2.
	LibExecutor = pkgluks.LibExecutor
)

const (
	// KDFArgon2id selects the Argon2id KDF (non-FIPS default).
	KDFArgon2id = pkgluks.KDFArgon2id

	// KDFPBKDF2 selects the PBKDF2-HMAC-SHA256 KDF (FIPS default).
	KDFPBKDF2 = pkgluks.KDFPBKDF2
)

var (
	// DefaultKDF returns the FIPS-appropriate default KDF.
	DefaultKDF = pkgluks.DefaultKDF

	// NewManager constructs a Manager from an explicit VolumeConfig.
	NewManager = pkgluks.NewManager

	// NewFIPSAwareManager constructs a Manager with FIPS-appropriate KDF
	// defaults.
	NewFIPSAwareManager = pkgluks.NewFIPSAwareManager

	// NewLibExecutor constructs the production Executor.
	NewLibExecutor = pkgluks.NewLibExecutor

	// IsLUKSVolume reports whether a file begins with the LUKS2 magic bytes.
	IsLUKSVolume = pkgluks.IsLUKSVolume

	// IsMounted reports whether a path is currently a mount point.
	IsMounted = pkgluks.IsMounted

	// IsUnlocked reports whether a LUKS device-mapper mapping exists.
	IsUnlocked = pkgluks.IsUnlocked

	// EnsureKeyringAvailable proves the kernel keyring is usable by this
	// process before a volume key is handled.
	EnsureKeyringAvailable = pkgluks.EnsureKeyringAvailable
)

// =============================================================================
// TPM 2.0 passphrase sealing
// =============================================================================

type (
	// SealParent identifies which TPM storage hierarchy a LUKS passphrase
	// seal is parented to: the Platform SRK (default) or the Shared SRK.
	SealParent = pkgluks.SealParent

	// TPMSealerConfig configures a TPMSealer's storage parent and PCR bank.
	TPMSealerConfig = pkgluks.TPMSealerConfig

	// TPMSealUnsealer is the subset of pkg/tpm2.TPM2's behavior TPMSealer
	// depends on.
	TPMSealUnsealer = pkgluks.TPMSealUnsealer

	// TPMSealResult is the sealed passphrase plus the LUKS2 token to persist
	// in the volume's header and the raw sealed blobs.
	TPMSealResult = pkgluks.TPMSealResult

	// TPMSealer seals and unseals LUKS volume passphrases against a TPM 2.0.
	TPMSealer = pkgluks.TPMSealer
)

const (
	// SealParentPSRK seals under go-xkms's own Platform Storage Root Key,
	// bound to go-xkms's platform PCR policy. This is the default.
	SealParentPSRK = pkgluks.SealParentPSRK

	// SealParentSSRK seals under the TCG-standard Shared Storage Root Key
	// with empty parent auth, for systemd-cryptsetup compatibility.
	SealParentSSRK = pkgluks.SealParentSSRK

	// TPMTokenType is the LUKS2 token type written for a SealParentSSRK
	// seal, matching systemd-cryptsetup's "systemd-tpm2" token.
	TPMTokenType = pkgluks.TPMTokenType

	// XKMSTPMTokenType is the LUKS2 token type written for a SealParentPSRK
	// seal.
	XKMSTPMTokenType = pkgluks.XKMSTPMTokenType
)

var (
	// ParseSealParent parses the config-file spelling of a seal parent.
	ParseSealParent = pkgluks.ParseSealParent

	// NewTPMSealer constructs a TPM-backed LUKS passphrase sealer.
	NewTPMSealer = pkgluks.NewTPMSealer

	// EncodeTPMSealBlobs packs sealed public/private blobs into the single
	// base64 tpm2-blob token field.
	EncodeTPMSealBlobs = pkgluks.EncodeTPMSealBlobs

	// DecodeTPMSealBlobs reverses EncodeTPMSealBlobs.
	DecodeTPMSealBlobs = pkgluks.DecodeTPMSealBlobs
)

// =============================================================================
// Errors
// =============================================================================

var (
	ErrNotMounted      = pkgluks.ErrNotMounted
	ErrAlreadyMounted  = pkgluks.ErrAlreadyMounted
	ErrNotUnlocked     = pkgluks.ErrNotUnlocked
	ErrAlreadyUnlocked = pkgluks.ErrAlreadyUnlocked
	ErrInvalidConfig   = pkgluks.ErrInvalidConfig
	ErrEmptyPassphrase = pkgluks.ErrEmptyPassphrase
	ErrInvalidSize     = pkgluks.ErrInvalidSize
	ErrInvalidKDF      = pkgluks.ErrInvalidKDF
	ErrOperationFailed = pkgluks.ErrOperationFailed
	ErrNilExecutor     = pkgluks.ErrNilExecutor

	ErrVolumeAlreadyExists = pkgluks.ErrVolumeAlreadyExists
	ErrVolumeNotFound      = pkgluks.ErrVolumeNotFound

	ErrTPMNoTransport              = pkgluks.ErrTPMNoTransport
	ErrTPMPolicyFailed             = pkgluks.ErrTPMPolicyFailed
	ErrTPMSealFailed               = pkgluks.ErrTPMSealFailed
	ErrTPMUnsealFailed             = pkgluks.ErrTPMUnsealFailed
	ErrTPMInvalidToken             = pkgluks.ErrTPMInvalidToken
	ErrInvalidSealParent           = pkgluks.ErrInvalidSealParent
	ErrInvalidPCRBank              = pkgluks.ErrInvalidPCRBank
	ErrTPMSSRKUnsealUnsupported    = pkgluks.ErrTPMSSRKUnsealUnsupported
	ErrTPMPCRSelectionNotSupported = pkgluks.ErrTPMPCRSelectionNotSupported
	ErrKeyringUnavailable          = pkgluks.ErrKeyringUnavailable
)

type (
	// SealParentInvalidError reports a SealParent value or raw config
	// string that names neither "psrk" nor "ssrk".
	SealParentInvalidError = pkgluks.SealParentInvalidError

	// ExecutorError reports which production LUKS operation failed and
	// against which path or device.
	ExecutorError = pkgluks.ExecutorError

	// KeyringError reports a failed kernel keyring preflight.
	KeyringError = pkgluks.KeyringError
)

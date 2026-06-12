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

// Package luks re-exports go-xkms's canonical LUKS surface: FIPS-aware
// volume configuration / lifecycle management and the TPM 2.0 passphrase
// sealer that produces systemd-tpm2 compatible LUKS2 tokens. Downstream
// consumers (go-quicbaas SDK shims, go-trusted-platform's LUKS backend)
// reach LUKS + TPM sealing through this package instead of importing
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
)

// =============================================================================
// TPM 2.0 passphrase sealing (systemd-tpm2 token format)
// =============================================================================

type (
	// TPMOpener opens a go-tpm transport for a sealing / unsealing operation.
	TPMOpener = pkgluks.TPMOpener

	// TPMOpenerFunc adapts a function to the TPMOpener interface.
	TPMOpenerFunc = pkgluks.TPMOpenerFunc

	// TPMToken is the systemd-tpm2 compatible LUKS2 token payload.
	TPMToken = pkgluks.TPMToken

	// TPMSealResult is the richer seal output: passphrase, token JSON, and
	// raw sealed blobs.
	TPMSealResult = pkgluks.TPMSealResult

	// TPMSealer seals and unseals LUKS volume passphrases against a TPM 2.0.
	TPMSealer = pkgluks.TPMSealer
)

const (
	// TPMTokenType is the LUKS2 token type written for TPM-sealed keyslots.
	TPMTokenType = pkgluks.TPMTokenType

	// DefaultTPMParentHandle is the default persistent sealing parent
	// handle (the TCG storage SRK, 0x81000001).
	DefaultTPMParentHandle = pkgluks.DefaultTPMParentHandle
)

var (
	// NewTPMSealer constructs a TPM-backed LUKS passphrase sealer.
	NewTPMSealer = pkgluks.NewTPMSealer

	// DefaultTPMOpener returns a TPMOpener that opens /dev/tpmrm0 on Linux.
	DefaultTPMOpener = pkgluks.DefaultTPMOpener

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

	ErrTPMNoTransport   = pkgluks.ErrTPMNoTransport
	ErrTPMPolicyFailed  = pkgluks.ErrTPMPolicyFailed
	ErrTPMSealFailed    = pkgluks.ErrTPMSealFailed
	ErrTPMUnsealFailed  = pkgluks.ErrTPMUnsealFailed
	ErrTPMInvalidHandle = pkgluks.ErrTPMInvalidHandle
	ErrTPMInvalidToken  = pkgluks.ErrTPMInvalidToken
)

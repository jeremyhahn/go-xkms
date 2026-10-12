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

// Package luks provides FIPS-aware LUKS volume configuration and lifecycle
// management. It wraps LUKS volume operations with automatic KDF selection
// based on the runtime FIPS policy and exposes an Executor interface so
// callers can supply platform-specific implementations (or test mocks).
package luks

import (
	"errors"
	"fmt"
)

var (
	// ErrNotMounted is returned when an operation requires a mounted volume
	// but the volume is not currently mounted.
	ErrNotMounted = errors.New("luks: volume is not mounted")

	// ErrAlreadyMounted is returned when attempting to mount a volume that
	// is already mounted.
	ErrAlreadyMounted = errors.New("luks: volume is already mounted")

	// ErrNotUnlocked is returned when an operation requires an unlocked
	// volume but the volume is not currently unlocked.
	ErrNotUnlocked = errors.New("luks: volume is not unlocked")

	// ErrAlreadyUnlocked is returned when attempting to unlock a volume
	// that is already unlocked.
	ErrAlreadyUnlocked = errors.New("luks: volume is already unlocked")

	// ErrInvalidConfig is returned when the volume configuration is missing
	// required fields or contains invalid values.
	ErrInvalidConfig = errors.New("luks: invalid configuration")

	// ErrEmptyPassphrase is returned when a passphrase is required but an
	// empty string was provided.
	ErrEmptyPassphrase = errors.New("luks: passphrase must not be empty")

	// ErrInvalidSize is returned when a volume size is zero or negative.
	ErrInvalidSize = errors.New("luks: size must be positive")

	// ErrInvalidKDF is returned when the configured KDF type is not one of
	// the supported values (argon2id or pbkdf2).
	ErrInvalidKDF = errors.New("luks: unsupported KDF type")

	// ErrOperationFailed is returned when the underlying LUKS executor
	// reports a failure during a create, unlock, or lock operation.
	ErrOperationFailed = errors.New("luks: operation failed")

	// ErrNilExecutor is returned when a nil Executor is provided to
	// NewManager.
	ErrNilExecutor = errors.New("luks: executor must not be nil")

	// ErrTPMNoTransport is returned when NewTPMSealer is given a nil
	// TPMSealUnsealer.
	ErrTPMNoTransport = errors.New("luks: no tpm transport available")

	// ErrTPMPolicyFailed is returned when the PCR policy digest could not
	// be computed. This is typically a bug in the requested PCR selection.
	ErrTPMPolicyFailed = errors.New("luks: tpm pcr policy digest failed")

	// ErrTPMSealFailed is returned when the underlying TPM2_Create seal
	// command fails.
	ErrTPMSealFailed = errors.New("luks: tpm seal failed")

	// ErrTPMUnsealFailed is returned when the TPM2_Unseal command fails
	// (most commonly because current PCR state does not match the policy).
	ErrTPMUnsealFailed = errors.New("luks: tpm unseal failed")

	// ErrTPMInvalidToken is returned when the TPM LUKS token could not be
	// decoded.
	ErrTPMInvalidToken = errors.New("luks: invalid tpm token payload")

	// ErrInvalidSealParent is the identity of every SealParentInvalidError:
	// a SealParent value or config string that names neither the Platform
	// SRK nor the Shared SRK.
	ErrInvalidSealParent = errors.New("luks: invalid tpm seal parent")

	// ErrInvalidPCRBank is returned when a TPMSealerConfig.PCRBank names
	// anything other than sha1, sha256, sha384 or sha512.
	ErrInvalidPCRBank = errors.New("luks: invalid tpm pcr bank")

	// ErrTPMSSRKUnsealUnsupported is returned by TPMSealer.UnsealPassphrase
	// for a SealParentSSRK token. go-xkms deliberately does not unseal
	// systemd-tpm2 tokens: pkg/tpm2's Unseal only builds policy sessions
	// for its platform policy or a named/authorized policy, neither of
	// which is the plain PolicyPCR digest an SSRK-parented LUKS token
	// carries. systemd-cryptsetup builds that session itself at boot; see
	// docs/luks/architecture.md.
	ErrTPMSSRKUnsealUnsupported = errors.New("luks: unsealing an ssrk-parented token is not supported; systemd-cryptsetup unseals it at boot")

	// ErrTPMPCRSelectionNotSupported is returned when a caller supplies a
	// PCR selection to TPMSealer.SealPassphrase under SealParentPSRK. The
	// Platform SRK path always binds to go-xkms's platform PCR policy,
	// whose PCR selection is fixed by pkg/tpm2 configuration, not chosen
	// per call.
	ErrTPMPCRSelectionNotSupported = errors.New("luks: explicit pcr selection is not supported when sealing under the platform srk")

	// ErrVolumeAlreadyExists is returned by the production Executor's
	// Create when a container file already exists at the configured path.
	ErrVolumeAlreadyExists = errors.New("luks: encrypted container already exists")

	// ErrVolumeNotFound is returned by the production Executor when the
	// configured container file does not exist.
	ErrVolumeNotFound = errors.New("luks: volume not found")
)

// SealParentInvalidError reports a SealParent value or raw config string
// that names neither "psrk" nor "ssrk". Raw is set when the value came from
// parsing a config string; Value is set when it came from an out-of-range
// SealParent constant.
type SealParentInvalidError struct {
	Raw   string
	Value uint8
}

// Error implements the error interface.
func (e *SealParentInvalidError) Error() string {
	if e.Raw != "" {
		return fmt.Sprintf("%s: %q (must be \"psrk\" or \"ssrk\")", ErrInvalidSealParent.Error(), e.Raw)
	}
	return fmt.Sprintf("%s: value %d (must be SealParentPSRK or SealParentSSRK)", ErrInvalidSealParent.Error(), e.Value)
}

// Unwrap reports ErrInvalidSealParent so callers can match with errors.Is.
func (e *SealParentInvalidError) Unwrap() error { return ErrInvalidSealParent }

// ExecutorError reports which production LUKS operation failed and against
// which path or device, wrapping the underlying cause.
type ExecutorError struct {
	Operation string
	Path      string
	Err       error
}

// Error implements the error interface.
func (e *ExecutorError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("luks: %s failed for %s: %v", e.Operation, e.Path, e.Err)
	}
	return fmt.Sprintf("luks: %s failed: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ExecutorError) Unwrap() error { return e.Err }

// KeyringError reports a failed kernel keyring preflight. It is
// ErrKeyringUnavailable to errors.Is, and it unwraps to go-luks2's own
// classification (dmcrypt.ErrKeyringBlocked for a seccomp policy,
// dmcrypt.ErrKeyringUnsupported for a kernel without key support,
// dmcrypt.ErrKeyringQuotaExhausted, dmcrypt.ErrKeyringFailed), whose message
// names the syscalls and the remedy.
type KeyringError struct {
	// Err is go-luks2's classified error.
	Err error
}

// Error implements the error interface.
func (e *KeyringError) Error() string {
	return "luks: kernel keyring preflight failed: " + e.Err.Error()
}

// Unwrap returns go-luks2's classified error.
func (e *KeyringError) Unwrap() error { return e.Err }

// Is reports ErrKeyringUnavailable as this error's identity.
func (e *KeyringError) Is(target error) bool { return target == ErrKeyringUnavailable }

// ErrKeyringUnavailable is the identity of every KeyringError: the kernel
// keyring is not usable by this process, so no volume can be unlocked.
var ErrKeyringUnavailable = errors.New("luks: the kernel keyring is unavailable to this process")

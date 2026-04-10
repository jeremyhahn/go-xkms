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

import "errors"

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
)

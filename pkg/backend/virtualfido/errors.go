// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package virtualfido

import "errors"

var (
	// ErrConfigNil is returned when the configuration is nil.
	ErrConfigNil = errors.New("virtualfido: config is nil")

	// ErrBackendClosed is returned when an operation is attempted on a closed backend.
	ErrBackendClosed = errors.New("virtualfido: backend is closed")

	// ErrKeyNotFound is returned when a requested key does not exist.
	ErrKeyNotFound = errors.New("virtualfido: key not found")

	// ErrSlotNotFound is returned when a requested PIV slot does not exist.
	ErrSlotNotFound = errors.New("virtualfido: slot not found")

	// ErrSlotOccupied is returned when attempting to use an already occupied slot.
	ErrSlotOccupied = errors.New("virtualfido: slot is already occupied")

	// ErrInvalidSlot is returned when an invalid PIV slot is specified.
	ErrInvalidSlot = errors.New("virtualfido: invalid PIV slot")

	// ErrPINRequired is returned when a PIN is required but not provided.
	ErrPINRequired = errors.New("virtualfido: PIN is required for this operation")

	// ErrPINInvalid is returned when the provided PIN is incorrect.
	ErrPINInvalid = errors.New("virtualfido: invalid PIN")

	// ErrPINBlocked is returned when the PIN retry counter is exhausted.
	ErrPINBlocked = errors.New("virtualfido: PIN is blocked")

	// ErrPUKInvalid is returned when the provided PUK is incorrect.
	ErrPUKInvalid = errors.New("virtualfido: invalid PUK")

	// ErrPUKBlocked is returned when the PUK retry counter is exhausted.
	ErrPUKBlocked = errors.New("virtualfido: PUK is blocked")

	// ErrManagementKeyInvalid is returned when the management key is incorrect.
	ErrManagementKeyInvalid = errors.New("virtualfido: invalid management key")

	// ErrKeyAlgorithmNotSupported is returned when the key algorithm is not supported.
	ErrKeyAlgorithmNotSupported = errors.New("virtualfido: key algorithm not supported")

	// ErrOperationNotSupported is returned when an operation is not supported.
	ErrOperationNotSupported = errors.New("virtualfido: operation not supported")

	// ErrStorageRead is returned when reading from storage fails.
	ErrStorageRead = errors.New("virtualfido: failed to read from storage")

	// ErrStorageWrite is returned when writing to storage fails.
	ErrStorageWrite = errors.New("virtualfido: failed to write to storage")

	// ErrEncryption is returned when encryption fails.
	ErrEncryption = errors.New("virtualfido: encryption failed")

	// ErrDecryption is returned when decryption fails.
	ErrDecryption = errors.New("virtualfido: decryption failed")

	// ErrCredentialNotFound is returned when a FIDO2 credential is not found.
	ErrCredentialNotFound = errors.New("virtualfido: credential not found")

	// ErrInvalidPassphrase is returned when the passphrase is invalid for decryption.
	ErrInvalidPassphrase = errors.New("virtualfido: invalid passphrase")

	// ErrDeviceNotInitialized is returned when the virtual device is not initialized.
	ErrDeviceNotInitialized = errors.New("virtualfido: device not initialized")
)

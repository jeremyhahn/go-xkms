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

package main

import "errors"

// Configuration errors for the virtual FIDO2 device.
var (
	// ErrInvalidStorageType indicates an unsupported storage type was specified.
	ErrInvalidStorageType = errors.New("vfido2: invalid storage type")

	// ErrStoragePathRequired indicates a storage path is required for file storage.
	ErrStoragePathRequired = errors.New("vfido2: storage path required for file storage type")

	// ErrInvalidLogLevel indicates an unsupported log level was specified.
	ErrInvalidLogLevel = errors.New("vfido2: invalid log level")

	// ErrInteractiveDaemonConflict indicates interactive mode cannot be used with daemon mode.
	ErrInteractiveDaemonConflict = errors.New("vfido2: interactive mode cannot be used with daemon mode")

	// ErrInvalidBackend indicates an unsupported backend was specified.
	ErrInvalidBackend = errors.New("vfido2: invalid backend type")

	// ErrInvalidAttestationFormat indicates an unsupported attestation format was specified.
	ErrInvalidAttestationFormat = errors.New("vfido2: invalid attestation format")

	// ErrTPMAttestationRequiresTPMBackend indicates TPM attestation requires TPM2 backend.
	ErrTPMAttestationRequiresTPMBackend = errors.New("vfido2: TPM attestation requires tpm2 backend")
)

// Daemon lifecycle errors for the virtual FIDO2 device.
var (
	// ErrPIDFileWriteFailed indicates the PID file could not be written.
	ErrPIDFileWriteFailed = errors.New("vfido2: failed to write PID file")

	// ErrPIDFileRemoveFailed indicates the PID file could not be removed.
	ErrPIDFileRemoveFailed = errors.New("vfido2: failed to remove PID file")

	// ErrLogFileOpenFailed indicates the log file could not be opened.
	ErrLogFileOpenFailed = errors.New("vfido2: failed to open log file")
)

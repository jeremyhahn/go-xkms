//go:build ignore

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

// Configuration errors for the FIDO2 authenticator.
var (
	// ErrInvalidStorageType indicates an unsupported storage type was specified.
	ErrInvalidStorageType = errors.New("fido2key: invalid storage type")

	// ErrStoragePathRequired indicates a storage path is required for file storage.
	ErrStoragePathRequired = errors.New("fido2key: storage path required for file storage type")

	// ErrInvalidLogLevel indicates an unsupported log level was specified.
	ErrInvalidLogLevel = errors.New("fido2key: invalid log level")

	// ErrInvalidBackend indicates an unsupported backend was specified.
	ErrInvalidBackend = errors.New("fido2key: invalid backend type")

	// ErrInvalidAttestationFormat indicates an unsupported attestation format was specified.
	ErrInvalidAttestationFormat = errors.New("fido2key: invalid attestation format")

	// ErrTPMAttestationRequiresTPMBackend indicates TPM attestation requires TPM2 backend.
	ErrTPMAttestationRequiresTPMBackend = errors.New("fido2key: TPM attestation requires tpm2 backend")
)

// Logging errors for the FIDO2 authenticator.
var (
	// ErrLogFileOpenFailed indicates the log file could not be opened.
	ErrLogFileOpenFailed = errors.New("fido2key: failed to open log file")
)

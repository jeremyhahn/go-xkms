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

// Package bootstrap provides the bootstrap authentication service for first-time
// server initialization. It manages setup tokens, admin user creation, and
// optional M-of-N threshold ceremony for multi-admin initialization.
package bootstrap

import "errors"

var (
	// ErrAlreadyInitialized indicates the system has already been initialized.
	ErrAlreadyInitialized = errors.New("bootstrap: system already initialized")

	// ErrNotReady indicates the system is not ready for initialization.
	ErrNotReady = errors.New("bootstrap: system not ready for initialization")

	// ErrInvalidToken indicates the setup token is invalid.
	ErrInvalidToken = errors.New("bootstrap: invalid setup token")

	// ErrTokenExpired indicates the setup token has expired.
	ErrTokenExpired = errors.New("bootstrap: setup token expired")

	// ErrTokenUsed indicates the setup token has already been used.
	ErrTokenUsed = errors.New("bootstrap: setup token already used")

	// ErrNoToken indicates no setup token has been generated.
	ErrNoToken = errors.New("bootstrap: no setup token generated")

	// ErrInvalidRequest indicates the initialization request is invalid.
	ErrInvalidRequest = errors.New("bootstrap: invalid initialization request")

	// ErrUsernameTaken indicates the requested username already exists.
	ErrUsernameTaken = errors.New("bootstrap: username already exists")

	// ErrInvalidInvitation indicates the invitation token is invalid.
	ErrInvalidInvitation = errors.New("bootstrap: invalid invitation token")

	// ErrInvitationExpired indicates the invitation has expired.
	ErrInvitationExpired = errors.New("bootstrap: invitation expired")

	// ErrInvitationUsed indicates the invitation has already been used.
	ErrInvitationUsed = errors.New("bootstrap: invitation already used")

	// ErrCeremonyNotStarted indicates the threshold ceremony has not started.
	ErrCeremonyNotStarted = errors.New("bootstrap: ceremony not started")

	// ErrCeremonyComplete indicates the threshold ceremony is already complete.
	ErrCeremonyComplete = errors.New("bootstrap: ceremony already complete")

	// ErrEmptyUsername indicates the username cannot be empty.
	ErrEmptyUsername = errors.New("bootstrap: username cannot be empty")

	// ErrEmptyToken indicates the setup token cannot be empty.
	ErrEmptyToken = errors.New("bootstrap: setup token cannot be empty")

	// ErrEmptyAttestation indicates the FIDO2 attestation cannot be empty.
	ErrEmptyAttestation = errors.New("bootstrap: FIDO2 attestation cannot be empty")

	// ErrNilUserStore indicates the user store cannot be nil.
	ErrNilUserStore = errors.New("bootstrap: user store cannot be nil")

	// ErrNilLogger indicates the logger cannot be nil.
	ErrNilLogger = errors.New("bootstrap: logger cannot be nil")

	// ErrThresholdConfig indicates invalid threshold mode configuration.
	ErrThresholdConfig = errors.New("bootstrap: admin_threshold must be > 0 and <= admin_total in threshold mode")
)

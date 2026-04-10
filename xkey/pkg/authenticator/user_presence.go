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

package authenticator

import (
	"context"
	"errors"
	"time"
)

// User presence and verification errors.
var (
	// ErrUserPresenceDenied indicates the user explicitly denied presence confirmation.
	ErrUserPresenceDenied = errors.New("authenticator: user presence denied")

	// ErrUserPresenceTimeout indicates the user presence request timed out.
	ErrUserPresenceTimeout = errors.New("authenticator: user presence timeout")

	// ErrUserVerificationDenied indicates user verification failed.
	ErrUserVerificationDenied = errors.New("authenticator: user verification denied")

	// ErrTerminalUnavailable indicates interactive mode requires a terminal but none is available.
	ErrTerminalUnavailable = errors.New("authenticator: terminal unavailable")

	// ErrInvalidPIN indicates the provided PIN is invalid.
	ErrInvalidPIN = errors.New("authenticator: invalid PIN")
)

// UserPresenceRequest contains information about a user presence request.
type UserPresenceRequest struct {
	// RPID is the relying party identifier.
	RPID string

	// RPName is the human-readable relying party name for display.
	RPName string

	// UserName is the username for display purposes.
	UserName string

	// Operation describes the operation type: "register" or "authenticate".
	Operation string

	// Timeout specifies how long to wait for user response.
	// A zero value uses the default timeout.
	Timeout time.Duration
}

// UserPresenceResult contains the result of a user presence request.
type UserPresenceResult struct {
	// Approved indicates whether the user approved the presence request.
	Approved bool
}

// UserVerificationRequest contains information about a user verification request.
type UserVerificationRequest struct {
	// RPID is the relying party identifier.
	RPID string

	// RPName is the human-readable relying party name for display.
	RPName string

	// UserName is the username for display purposes.
	UserName string

	// Operation describes the operation type: "register" or "authenticate".
	Operation string

	// Timeout specifies how long to wait for user response.
	// A zero value uses the default timeout.
	Timeout time.Duration

	// PINRequired indicates whether PIN entry is required for verification.
	PINRequired bool
}

// UserVerificationResult contains the result of a user verification request.
type UserVerificationResult struct {
	// Verified indicates whether user verification succeeded.
	Verified bool

	// PIN contains the entered PIN when PINRequired was true.
	// Empty if PIN was not required.
	PIN string
}

// UserPresenceHandler defines the interface for handling user presence and verification.
// Implementations must be safe for concurrent use.
type UserPresenceHandler interface {
	// RequestUserPresence requests user presence confirmation (touch simulation).
	// Returns ErrUserPresenceTimeout if timeout expires before user responds.
	// Returns ErrUserPresenceDenied if user explicitly denies the request.
	RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error)

	// RequestUserVerification requests user verification (PIN entry for software authenticator).
	// Returns ErrUserVerificationDenied if verification fails.
	// Returns ErrTerminalUnavailable if interactive mode requires a terminal but none is available.
	RequestUserVerification(ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error)
}

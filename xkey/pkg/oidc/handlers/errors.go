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

// Package handlers provides output handlers for processing OIDC token responses.
package handlers

import "errors"

var (
	// ErrExecCommandRequired is returned when no exec command is specified.
	ErrExecCommandRequired = errors.New("handlers: exec command is required")

	// ErrExecCommandFailed is returned when the exec command fails.
	ErrExecCommandFailed = errors.New("handlers: exec command failed")

	// ErrJSONMarshalFailed is returned when JSON marshaling fails.
	ErrJSONMarshalFailed = errors.New("handlers: JSON marshal failed")

	// ErrAWSCredentialsPathRequired is returned when no credentials path is specified.
	ErrAWSCredentialsPathRequired = errors.New("handlers: AWS credentials path is required")

	// ErrAWSProfileRequired is returned when no AWS profile is specified.
	ErrAWSProfileRequired = errors.New("handlers: AWS profile is required")

	// ErrAWSCredentialsWrite is returned when writing AWS credentials fails.
	ErrAWSCredentialsWrite = errors.New("handlers: failed to write AWS credentials")

	// ErrAWSCredentialsRead is returned when reading AWS credentials fails.
	ErrAWSCredentialsRead = errors.New("handlers: failed to read AWS credentials")

	// ErrAWSResponseMissingCredentials is returned when AWS response lacks credentials.
	ErrAWSResponseMissingCredentials = errors.New("handlers: AWS response missing credentials")

	// ErrAWSInvalidAccessKeyID is returned when an access key ID is not
	// 16 to 128 characters of A-Z and 0-9.
	ErrAWSInvalidAccessKeyID = errors.New("handlers: invalid AWS access key ID")

	// ErrAWSInvalidSecretAccessKey is returned when a secret access key is
	// empty or contains a byte outside printable, non-space ASCII.
	ErrAWSInvalidSecretAccessKey = errors.New("handlers: invalid AWS secret access key")

	// ErrAWSInvalidSessionToken is returned when a session token contains a
	// byte outside the base64 alphabet (A-Z, a-z, 0-9, '+', '/', '=').
	ErrAWSInvalidSessionToken = errors.New("handlers: invalid AWS session token")

	// ErrAWSInvalidProfile is returned when a profile name contains a byte
	// outside A-Z, a-z, 0-9 and "._-@+:/".
	ErrAWSInvalidProfile = errors.New("handlers: invalid AWS profile name")

	// ErrAWSInvalidRegion is returned when a region contains a byte outside
	// a-z, 0-9 and '-'.
	ErrAWSInvalidRegion = errors.New("handlers: invalid AWS region")

	// ErrInvalidAWSResponse is returned when the AWS response format is invalid.
	ErrInvalidAWSResponse = errors.New("handlers: invalid AWS response format")

	// ErrNilTokenResponse is returned when a nil token response is provided.
	ErrNilTokenResponse = errors.New("handlers: nil token response")

	// ErrOutputWriteFailed is returned when writing output fails.
	ErrOutputWriteFailed = errors.New("handlers: output write failed")

	// ErrUnknownOutputMode is returned by NewForMode when mode names no
	// known output handler.
	ErrUnknownOutputMode = errors.New("handlers: unknown output mode")

	// ErrExecModeRequiresCommand is returned by NewForMode when mode is
	// ModeExec but no command was given.
	ErrExecModeRequiresCommand = errors.New("handlers: exec output mode requires a command")
)

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

// DetailError appends detail text directly after a wrapped error while
// preserving errors.Is / errors.As matching of the wrapped error through
// Unwrap. The detail text carries its own leading separator.
type DetailError struct {
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *DetailError) Error() string {
	return e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *DetailError) Unwrap() error {
	return e.Err
}

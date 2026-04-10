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

	// ErrInvalidAWSResponse is returned when the AWS response format is invalid.
	ErrInvalidAWSResponse = errors.New("handlers: invalid AWS response format")

	// ErrNilTokenResponse is returned when a nil token response is provided.
	ErrNilTokenResponse = errors.New("handlers: nil token response")

	// ErrOutputWriteFailed is returned when writing output fails.
	ErrOutputWriteFailed = errors.New("handlers: output write failed")
)

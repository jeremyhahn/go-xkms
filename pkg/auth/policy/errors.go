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

package policy

import "errors"

var (
	// ErrPolicyNotFound is returned when no policy matches the operation.
	ErrPolicyNotFound = errors.New("auth/policy: policy not found for operation")

	// ErrInsufficientMFA is returned when the provided MFA level does not
	// meet the required level for the operation.
	ErrInsufficientMFA = errors.New("auth/policy: insufficient MFA level")

	// ErrInvalidMFALevel is returned when an unrecognized MFA level is specified.
	ErrInvalidMFALevel = errors.New("auth/policy: invalid MFA level")

	// ErrInvalidOperation is returned when an empty operation name is provided.
	ErrInvalidOperation = errors.New("auth/policy: operation name cannot be empty")

	// ErrNilPolicy is returned when a nil policy is provided.
	ErrNilPolicy = errors.New("auth/policy: policy cannot be nil")

	// ErrDuplicatePolicy is returned when a policy for the operation already exists.
	ErrDuplicatePolicy = errors.New("auth/policy: policy already exists for operation")
)

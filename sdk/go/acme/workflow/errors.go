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

package workflow

import "github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"

// RegistrationError indicates a failure during ACME account registration.
type RegistrationError struct {
	*errors.CAError
}

// NewRegistrationError creates a new RegistrationError.
func NewRegistrationError(op, message string) *RegistrationError {
	return &RegistrationError{
		CAError: errors.New(errors.CodeInternal, op, message),
	}
}

// WrapRegistrationError wraps an existing error as a RegistrationError.
func WrapRegistrationError(err error, op, message string) *RegistrationError {
	return &RegistrationError{
		CAError: errors.Wrap(err, errors.CodeInternal, op, message),
	}
}

// AuthorizationError indicates a failure during ACME authorization.
type AuthorizationError struct {
	*errors.CAError
	// Domain is the domain that failed authorization.
	Domain string
	// AuthorizationURL is the URL of the failed authorization.
	AuthorizationURL string
}

// NewAuthorizationError creates a new AuthorizationError.
func NewAuthorizationError(op, message, domain, authzURL string) *AuthorizationError {
	return &AuthorizationError{
		CAError:          errors.New(errors.CodeInternal, op, message),
		Domain:           domain,
		AuthorizationURL: authzURL,
	}
}

// WrapAuthorizationError wraps an existing error as an AuthorizationError.
func WrapAuthorizationError(err error, op, message, domain, authzURL string) *AuthorizationError {
	return &AuthorizationError{
		CAError:          errors.Wrap(err, errors.CodeInternal, op, message),
		Domain:           domain,
		AuthorizationURL: authzURL,
	}
}

// ChallengeError indicates a failure during ACME challenge processing.
type ChallengeError struct {
	*errors.CAError
	// Domain is the domain that failed challenge validation.
	Domain string
	// ChallengeType is the type of challenge that failed.
	ChallengeType string
	// ChallengeURL is the URL of the failed challenge.
	ChallengeURL string
}

// NewChallengeError creates a new ChallengeError.
func NewChallengeError(op, message, domain, challengeType, challengeURL string) *ChallengeError {
	return &ChallengeError{
		CAError:       errors.New(errors.CodeInternal, op, message),
		Domain:        domain,
		ChallengeType: challengeType,
		ChallengeURL:  challengeURL,
	}
}

// WrapChallengeError wraps an existing error as a ChallengeError.
func WrapChallengeError(err error, op, message, domain, challengeType, challengeURL string) *ChallengeError {
	return &ChallengeError{
		CAError:       errors.Wrap(err, errors.CodeInternal, op, message),
		Domain:        domain,
		ChallengeType: challengeType,
		ChallengeURL:  challengeURL,
	}
}

// FinalizationError indicates a failure during order finalization.
type FinalizationError struct {
	*errors.CAError
	// OrderURL is the URL of the order that failed finalization.
	OrderURL string
}

// NewFinalizationError creates a new FinalizationError.
func NewFinalizationError(op, message, orderURL string) *FinalizationError {
	return &FinalizationError{
		CAError:  errors.New(errors.CodeInternal, op, message),
		OrderURL: orderURL,
	}
}

// WrapFinalizationError wraps an existing error as a FinalizationError.
func WrapFinalizationError(err error, op, message, orderURL string) *FinalizationError {
	return &FinalizationError{
		CAError:  errors.Wrap(err, errors.CodeInternal, op, message),
		OrderURL: orderURL,
	}
}

// PollTimeoutError indicates that polling for a status change timed out.
type PollTimeoutError struct {
	*errors.CAError
	// ResourceURL is the URL of the resource that timed out.
	ResourceURL string
	// LastStatus is the last observed status before timeout.
	LastStatus string
}

// NewPollTimeoutError creates a new PollTimeoutError.
func NewPollTimeoutError(op, message, resourceURL, lastStatus string) *PollTimeoutError {
	return &PollTimeoutError{
		CAError:     errors.New(errors.CodeTimeout, op, message),
		ResourceURL: resourceURL,
		LastStatus:  lastStatus,
	}
}

// RevocationError indicates a failure during certificate revocation.
type RevocationError struct {
	*errors.CAError
}

// NewRevocationError creates a new RevocationError.
func NewRevocationError(op, message string) *RevocationError {
	return &RevocationError{
		CAError: errors.New(errors.CodeInternal, op, message),
	}
}

// WrapRevocationError wraps an existing error as a RevocationError.
func WrapRevocationError(err error, op, message string) *RevocationError {
	return &RevocationError{
		CAError: errors.Wrap(err, errors.CodeInternal, op, message),
	}
}

// NoChallengeError indicates no matching challenge was found for the requested type.
type NoChallengeError struct {
	*errors.CAError
	// Domain is the domain lacking a matching challenge.
	Domain string
	// RequestedType is the challenge type that was requested.
	RequestedType string
}

// NewNoChallengeError creates a new NoChallengeError.
func NewNoChallengeError(op, domain, requestedType string) *NoChallengeError {
	return &NoChallengeError{
		CAError:       errors.New(errors.CodeNotFound, op, "no matching challenge found"),
		Domain:        domain,
		RequestedType: requestedType,
	}
}

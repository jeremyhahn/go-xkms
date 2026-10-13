// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package scope

import "errors"

// ErrRefused is matched (errors.Is) by every refusal Principal.Authorize
// returns, so a caller can map a refusal without naming each type.
var ErrRefused = errors.New("scope: access refused")

// InvalidScopeError reports a scope that is not tenant, user or service.
type InvalidScopeError struct {
	// Value is the input exactly as supplied.
	Value string
}

// Error implements the error interface.
func (e *InvalidScopeError) Error() string { return "scope: invalid scope: " + e.Value }

// InvalidSegmentError reports a tenant, feature or owner that cannot be one
// key segment.
type InvalidSegmentError struct {
	// Field names the offending component (tenant, feature or owner).
	Field string
	// Value is the offending input.
	Value string
	// Reason says why it was refused, when Err is nil.
	Reason string
	// Err is the underlying validation failure, when there is one.
	Err error
}

// Error implements the error interface.
func (e *InvalidSegmentError) Error() string {
	reason := e.Reason
	if e.Err != nil {
		reason = e.Err.Error()
	}
	return "scope: invalid " + e.Field + " " + e.Value + ": " + reason
}

// Unwrap returns the underlying validation failure.
func (e *InvalidSegmentError) Unwrap() error { return e.Err }

// UnauthenticatedError refuses a request that carries no identity.
type UnauthenticatedError struct {
	TargetTenantID string
}

// Error implements the error interface.
func (e *UnauthenticatedError) Error() string {
	return "scope: an unauthenticated caller may not address tenant " + e.TargetTenantID
}

// Is matches ErrRefused.
func (e *UnauthenticatedError) Is(target error) bool { return target == ErrRefused }

// CrossTenantError refuses a caller addressing another tenant.
type CrossTenantError struct {
	CallerTenantID string
	TargetTenantID string
}

// Error implements the error interface.
func (e *CrossTenantError) Error() string {
	return "scope: tenant " + e.CallerTenantID + " may not address tenant " + e.TargetTenantID
}

// Is matches ErrRefused.
func (e *CrossTenantError) Is(target error) bool { return target == ErrRefused }

// CrossUserError refuses a caller addressing a personal object it does not
// own.
type CrossUserError struct {
	TenantID      string
	CallerSubject string
	Owner         string
}

// Error implements the error interface.
func (e *CrossUserError) Error() string {
	return "scope: " + e.CallerSubject + " may not address the personal objects of " + e.Owner + " in tenant " + e.TenantID
}

// Is matches ErrRefused.
func (e *CrossUserError) Is(target error) bool { return target == ErrRefused }

// ServiceScopeError refuses a caller without the explicit service-scope
// permission addressing a service-owned object.
type ServiceScopeError struct {
	TenantID      string
	CallerSubject string
	Owner         string
}

// Error implements the error interface.
func (e *ServiceScopeError) Error() string {
	return "scope: " + e.CallerSubject + " lacks the service-scope permission for " + e.Owner + " in tenant " + e.TenantID
}

// Is matches ErrRefused.
func (e *ServiceScopeError) Is(target error) bool { return target == ErrRefused }

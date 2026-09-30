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

package tenancy

// NilInputError reports that a required option was not supplied.
type NilInputError struct {
	// Field names the missing option.
	Field string
}

// Error implements the error interface.
func (e *NilInputError) Error() string { return "ssh/tenancy: nil input: " + e.Field }

// CallerTenantError reports that the caller's identity names a tenant that
// cannot address a storage partition. Authentication guarantees a
// well-formed tenant, so this is a server-side invariant failure, never a
// caller mistake, and every transport reports it as an internal error.
type CallerTenantError struct {
	// TenantID is the tenant the identity carried.
	TenantID string
	// Err is the validation failure.
	Err error
}

// Error implements the error interface.
func (e *CallerTenantError) Error() string {
	return "ssh/tenancy: caller tenant " + e.TenantID + " is not a valid partition: " + e.Err.Error()
}

// Unwrap returns the validation failure.
func (e *CallerTenantError) Unwrap() error { return e.Err }

// OwnerBindingError is the refusal of a request that addresses an SSH asset
// the caller does not own. It is deliberately indistinguishable from a
// missing asset: Err is the answer a partition holding nothing gives for the
// same address -- a *keys.KeyNotFoundError, *authorized.NotFoundError or
// *known_hosts.NotFoundError for a well-formed address, the store's own
// validation error otherwise -- and Error renders it verbatim, so every
// transport classifies the refusal exactly as it classifies a genuine miss
// (REST 404, gRPC NotFound, MCP JSONRPCCodeNotFound) with the same body. The
// remaining fields carry the detail for server-side diagnostics (errors.As)
// and are never rendered.
type OwnerBindingError struct {
	// Op names the refused operation.
	Op string
	// Scope and Owner are the address the request named.
	Scope string
	Owner string
	// CallerTenantID and CallerSubject identify the refused caller.
	CallerTenantID string
	CallerSubject  string
	// Cause is the scope rule's reason for the refusal (a pkg/scope error
	// matching scope.ErrRefused, or the invalid tenant a platform caller
	// named). It is diagnostic only: Unwrap returns Err, never Cause, so no
	// transport can classify a refusal differently from a miss.
	Cause error
	// Err is the genuine-miss answer for the address.
	Err error
}

// Error returns the genuine-miss answer's message verbatim.
func (e *OwnerBindingError) Error() string { return e.Err.Error() }

// Unwrap returns the genuine-miss answer, which the transports classify.
func (e *OwnerBindingError) Unwrap() error { return e.Err }

// EmptyPartitionError reports that the empty partition, which serves
// refusals and must hold nothing, answered a lookup without an error. It is
// an internal invariant failure: the refusal it replaces is still a refusal.
type EmptyPartitionError struct {
	// Op names the refused operation.
	Op string
}

// Error implements the error interface.
func (e *EmptyPartitionError) Error() string {
	return "ssh/tenancy: the empty partition answered " + e.Op + ": it must hold nothing"
}

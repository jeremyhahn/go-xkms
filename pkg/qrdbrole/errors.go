// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package qrdbrole

// Op names the reconciliation step a ReconcileError failed on.
type Op string

const (
	// OpList is the read of the tenant's current roles.
	OpList Op = "list"
	// OpCreate is the seeding of a built-in the tenant did not hold.
	OpCreate Op = "create"
	// OpUpdate is the replacement of a stored built-in's permission set.
	OpUpdate Op = "update"
)

// ReconcileError reports a failure while converging a tenant's built-in roles.
//
// It names the step and, where the failure belongs to one role, that role, so a
// caller can tell "the tenant could not be read at all" from "one built-in
// could not be repaired" without re-deriving it from the wrapped error.
type ReconcileError struct {
	// TenantID is the tenant being reconciled.
	TenantID string

	// Role is the built-in role's name, or empty when the failure is not
	// tied to a single role.
	Role string

	// Op is the step that failed.
	Op Op

	// Err is the underlying store failure.
	Err error
}

// Error returns a human-readable description.
func (e *ReconcileError) Error() string {
	msg := "qrdbrole: reconcile " + string(e.Op) + " failed for tenant " + e.TenantID
	if e.Role != "" {
		msg += ", role " + e.Role
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap exposes the underlying store failure to errors.Is and errors.As.
func (e *ReconcileError) Unwrap() error { return e.Err }

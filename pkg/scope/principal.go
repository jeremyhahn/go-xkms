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

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// pkg/scope reads identities through the go-qrdb SDK, never pkg/auth (whose
// auth.Identity is an alias of qrdbsdk.Identity): pkg/auth imports the PKCS#11
// module and through it the transports, which themselves use pkg/scope.

// Principal is the caller a request is authorized for. The zero Principal is
// unauthenticated: Authorize refuses it every object.
type Principal struct {
	// TenantID is the caller's tenant scope name (SystemTenant for the
	// system tenant).
	TenantID string

	// Subject is the caller's principal ID within its tenant.
	Subject string

	// Authenticated is true for a principal built from an identity. Without
	// one there is no caller to authorize, so Authorize refuses every object.
	Authenticated bool

	// ServiceAccess is true when the caller holds the feature's explicit
	// service-scope permission. The caller's feature sets it after checking
	// that permission; Principal carries no permission model of its own.
	ServiceAccess bool
}

// PrincipalOf returns the principal id authenticates. A nil id is the
// unauthenticated principal, which Authorize refuses: an absent identity is
// never the platform. Every other identity, the system tenant's included, is
// confined to its own tenant, exactly as go-qrdb confines it.
func PrincipalOf(id *qrdbsdk.Identity) Principal {
	if id == nil {
		return Principal{}
	}
	return Principal{TenantID: TenantName(id.TenantID), Subject: id.Subject, Authenticated: true}
}

// PrincipalFromContext returns the principal of the identity ctx carries.
func PrincipalFromContext(ctx context.Context) Principal {
	return PrincipalOf(qrdbsdk.IdentityFromContext(ctx))
}

// Target is the owner of an object a request addresses.
type Target struct {
	// TenantID is the tenant holding the object ("" is the system tenant).
	TenantID string

	// Scope is the object's scope.
	Scope Scope

	// Owner is the owning subject (User) or workload (Service). It is
	// ignored for Tenant scope.
	Owner string
}

// Authorize reports whether p may address objects of t. It returns nil when
// allowed and otherwise one of *UnauthenticatedError, *CrossTenantError,
// *CrossUserError, *ServiceScopeError or *InvalidScopeError; all but the last
// match ErrRefused.
//
// The rule:
//   - an unauthenticated principal reaches nothing;
//   - every caller, the system tenant's included, reaches only its own tenant;
//   - Tenant scope: every user of the tenant;
//   - User scope: only the owner;
//   - Service scope: only a caller holding the service-scope permission.
func (p Principal) Authorize(t Target) error {
	if !t.Scope.Valid() {
		return &InvalidScopeError{Value: string(t.Scope)}
	}
	target := TenantName(t.TenantID)
	if !p.Authenticated {
		return &UnauthenticatedError{TargetTenantID: target}
	}
	if target != TenantName(p.TenantID) {
		return &CrossTenantError{CallerTenantID: p.TenantID, TargetTenantID: target}
	}
	switch t.Scope {
	case User:
		if t.Owner != p.Subject || p.Subject == "" {
			return &CrossUserError{TenantID: target, CallerSubject: p.Subject, Owner: t.Owner}
		}
	case Service:
		if !p.ServiceAccess {
			return &ServiceScopeError{TenantID: target, CallerSubject: p.Subject, Owner: t.Owner}
		}
	}
	return nil
}

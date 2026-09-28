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

package auth

import (
	"context"
	"errors"
	"slices"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// ErrRoleClientRequired is returned by HoldsSystemRole when no qrdb role
// client is supplied. Without the role store there is no way to learn which
// identifier a system role is persisted under, so membership cannot be
// established and the caller must fail closed.
var ErrRoleClientRequired = errors.New("auth: a qrdb role client is required to resolve role membership")

// RoleResolutionError reports that the qrdb role store could not say which
// identifier the named system role is persisted under in the tenant. The
// caller must treat it as "membership unknown" and fail closed, never as
// "not a member".
type RoleResolutionError struct {
	TenantID string
	Role     string
	Err      error
}

// Error implements the error interface.
func (e *RoleResolutionError) Error() string {
	return "auth: resolve system role " + e.Role + " in tenant " + e.TenantID + ": " + e.Err.Error()
}

// Unwrap exposes the role store failure for errors.Is/As.
func (e *RoleResolutionError) Unwrap() error {
	return e.Err
}

// HoldsSystemRole reports whether identity holds the named qrdb system role
// (qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameSO, ...) of its own tenant.
//
// An authenticated identity carries qrdb role IDENTIFIERS in Roles — go-qrdb's
// middleware and xkms's mTLS authenticator both copy the user record's RoleIDs
// verbatim — so comparing Roles against a role NAME never matches a real
// grant, and matches a forged one: an identity whose Roles came from an
// unverified token claim spelling "admin". This resolves the name to the
// identifier the role is actually persisted under, through the SDK's
// qrdbsdk.ResolveSystemRoleID and the node's role store, and matches the
// identity's identifiers against that. A role name on the identity therefore
// confers nothing.
//
// Use it only where the decision genuinely is role membership. An operation
// that declares a resource:action permission is authorized through
// Authorizer, never through this.
//
// A nil identity, or one with no roles, holds no role. A nil role client
// yields ErrRoleClientRequired and a store failure a *RoleResolutionError;
// both mean membership is unknown and the caller must fail closed.
func HoldsSystemRole(ctx context.Context, roles qrdbtransport.RoleClient, identity *Identity, roleName string) (bool, error) {
	if roles == nil {
		return false, ErrRoleClientRequired
	}
	if identity == nil || len(identity.Roles) == 0 {
		return false, nil
	}

	tenantID := identity.TenantID
	if tenantID == "" {
		tenantID = qrdbsdk.SystemTenantID
	}

	// The role store scopes reads to the context tenant, so the lookup runs
	// under the identity's own tenant: the role being resolved is the one
	// granted in that tenant, not in whatever tenant the request targets.
	lookupCtx := qrdbsdk.ContextWithTenant(ctx, tenantID)
	roleID, err := qrdbsdk.ResolveSystemRoleID(lookupCtx, roleNameResolver{roles: roles}, tenantID, roleName)
	if err != nil {
		return false, &RoleResolutionError{TenantID: tenantID, Role: roleName, Err: err}
	}
	return slices.Contains(identity.Roles, roleID), nil
}

// roleNameResolver presents a qrdb RoleClient as the qrdbsdk.RoleNameResolver
// qrdbsdk.ResolveSystemRoleID consults. Only the identifier is carried across:
// it is the one field the resolver reads.
type roleNameResolver struct {
	roles qrdbtransport.RoleClient
}

// GetRoleByName implements qrdbsdk.RoleNameResolver.
func (r roleNameResolver) GetRoleByName(ctx context.Context, tenantID, name string) (*qrdbsdk.Role, error) {
	found, err := r.roles.GetRoleByName(ctx, &qrdbtransport.GetRoleByNameRequest{TenantID: tenantID, Name: name})
	if err != nil {
		return nil, err
	}
	if found == nil {
		// Surface the broken contract to ResolveSystemRoleID, which refuses a
		// nil role with a nil error rather than reading it as "no such role".
		return nil, nil
	}
	return &qrdbsdk.Role{ID: found.ID, Name: found.Name, TenantID: found.TenantID, System: found.System}, nil
}

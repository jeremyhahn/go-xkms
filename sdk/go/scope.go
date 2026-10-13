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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/scope"

// Object ownership scopes. pkg/scope is the one ownership model for the
// security objects xkms stores (passwords, SSH assets, TPM policies, OIDC
// credentials): every object belongs to a tenant and is tenant-shared,
// personal to one user, or owned by a workload. ScopePrincipal.Authorize is
// the single access rule; a host that stores its own objects in the same
// layout applies it through these aliases. Identifiers carry an Object or
// Scope prefix because Tenant, User and Principal are taken in this flat
// namespace.

// ObjectScope is the ownership scope of a stored object.
type ObjectScope = scope.Scope

const (
	// ObjectScopeTenant is a tenant-shared object, visible to every user of
	// the tenant.
	ObjectScopeTenant = scope.Tenant
	// ObjectScopeUser is a personal object, visible only to its owner.
	ObjectScopeUser = scope.User
	// ObjectScopeService is an object owned by a workload.
	ObjectScopeService = scope.Service

	// ScopeSystemTenant is the platform tenant's scope name: go-qrdb's
	// reserved system tenant ID.
	ScopeSystemTenant = scope.SystemTenant
)

// ScopePrincipal is the caller a request is authorized for. The zero value is
// the unauthenticated principal, which Authorize refuses for every target.
type ScopePrincipal = scope.Principal

// ScopeTarget is the owner of an object a request addresses.
type ScopeTarget = scope.Target

// ParseObjectScope normalizes a scope name (trimmed, case-insensitive) or
// returns *ScopeInvalidScopeError.
var ParseObjectScope = scope.Parse

// ScopePrincipalOf returns the principal an identity authenticates. No
// identity is the unauthenticated principal; every other identity, the system
// tenant's included, is confined to its own tenant.
var ScopePrincipalOf = scope.PrincipalOf

// ScopePrincipalFromContext returns the principal of the identity a context
// carries, with ScopePrincipalOf's rules.
var ScopePrincipalFromContext = scope.PrincipalFromContext

// ScopeTenantName returns the scope name of a tenant ID: the empty tenant and
// the reserved system tenant are both ScopeSystemTenant.
var ScopeTenantName = scope.TenantName

// ScopeIsSystem reports whether a tenant ID names the system tenant.
var ScopeIsSystem = scope.IsSystem

// ScopeTenantRoot returns "{tenant}/", the root of every feature's keyspace.
var ScopeTenantRoot = scope.TenantRoot

// ScopeFeatureRoot returns "{tenant}/{feature}/", a feature's keyspace root.
var ScopeFeatureRoot = scope.Root

// ScopePrefix returns the keyspace holding a feature's objects of one scope
// and owner in a tenant.
var ScopePrefix = scope.Prefix

// ScopeFeaturePrefix returns a scope's keyspace relative to its tenant root.
var ScopeFeaturePrefix = scope.FeaturePrefix

// ScopeOwnersRoot returns the relative prefix of every owner's objects of one
// scope, for listing a scope across owners.
var ScopeOwnersRoot = scope.ScopeRoot

// ScopeSharedPrefix returns "{tenant}/{feature}/shared/".
var ScopeSharedPrefix = scope.SharedPrefix

// ScopePersonalPrefix returns "{tenant}/{feature}/users/{subject}/".
var ScopePersonalPrefix = scope.PersonalPrefix

// ScopeSharedSuffix returns "/{feature}/shared/", for a scan that enumerates
// tenants.
var ScopeSharedSuffix = scope.SharedSuffix

// ErrScopeRefused is matched (errors.Is) by every refusal
// ScopePrincipal.Authorize returns.
var ErrScopeRefused = scope.ErrRefused

// ScopeUnauthenticatedError refuses a request that carries no identity. It
// matches ErrScopeRefused.
type ScopeUnauthenticatedError = scope.UnauthenticatedError

// ScopeCrossTenantError refuses a caller addressing another tenant, the
// system tenant's callers included. It matches ErrScopeRefused.
type ScopeCrossTenantError = scope.CrossTenantError

// ScopeCrossUserError refuses a caller addressing a personal object it does
// not own. It matches ErrScopeRefused.
type ScopeCrossUserError = scope.CrossUserError

// ScopeServiceError refuses a caller without the service-scope permission
// addressing a workload's object. It matches ErrScopeRefused.
type ScopeServiceError = scope.ServiceScopeError

// ScopeInvalidScopeError reports a scope that is not tenant, user or service.
type ScopeInvalidScopeError = scope.InvalidScopeError

// ScopeInvalidSegmentError reports a tenant, feature or owner that cannot be
// one key segment.
type ScopeInvalidSegmentError = scope.InvalidSegmentError

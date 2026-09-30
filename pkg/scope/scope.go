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

// Package scope is the one ownership model for the security objects xkms
// stores: passwords, SSH assets, TPM policies and every later feature.
//
// Every object belongs to a tenant and has one of three scopes:
//
//   - Tenant (shared): visible to every user of the tenant.
//   - User (personal): visible only to the user who owns it.
//   - Service: owned by a workload; reachable only with an explicit
//     permission the feature names.
//
// The keyspace follows the scope:
//
//	{tenant}/{feature}/shared/...             Tenant scope
//	{tenant}/{feature}/users/{subject}/...    User scope
//	{tenant}/{feature}/services/{owner}/...   Service scope
//
// The platform (system) tenant is an ordinary tenant named "system": it has
// its own shared and personal objects and never sees another tenant's
// personal objects.
//
// Principal.Authorize is the single access rule. It refuses a cross-tenant
// or cross-user request with a typed error that matches ErrRefused, so each
// transport can map it to the answer it gives a missing object.
package scope

import (
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Scope is the ownership scope of a stored object.
type Scope string

// Scope values. The strings are the canonical wire and storage form.
const (
	// Tenant is a tenant-shared object, visible to every user of the tenant.
	Tenant Scope = "tenant"

	// User is a personal object, visible only to its owner.
	User Scope = "user"

	// Service is an object owned by a workload (a service account).
	Service Scope = "service"
)

// SystemTenant is the name of the platform tenant's scope. It is go-qrdb's
// reserved system tenant ID, so a scope name and a tenant ID never disagree.
const SystemTenant = qrdbsdk.SystemTenantID

// Keyspace segments that follow "{tenant}/{feature}/".
const (
	sharedSegment   = "shared"
	usersSegment    = "users"
	servicesSegment = "services"
)

// Valid reports whether s is one of the three scopes.
func (s Scope) Valid() bool {
	switch s {
	case Tenant, User, Service:
		return true
	default:
		return false
	}
}

// String returns the canonical string form.
func (s Scope) String() string { return string(s) }

// Parse normalizes s (trimmed, case-insensitive) and returns its Scope, or
// *InvalidScopeError.
func Parse(s string) (Scope, error) {
	sc := Scope(strings.ToLower(strings.TrimSpace(s)))
	if !sc.Valid() {
		return "", &InvalidScopeError{Value: s}
	}
	return sc, nil
}

// TenantName returns the scope name of tenantID: the empty tenant and the
// reserved system tenant are both SystemTenant.
func TenantName(tenantID string) string {
	if tenantID == "" || qrdbsdk.IsSystemTenant(tenantID) {
		return SystemTenant
	}
	return tenantID
}

// IsSystem reports whether tenantID names the system tenant.
func IsSystem(tenantID string) bool {
	return TenantName(tenantID) == SystemTenant
}

// TenantRoot returns "{tenant}/", the root of every feature's keyspace in
// tenantID ("" and the system tenant are "system/").
func TenantRoot(tenantID string) (string, error) {
	tenant := TenantName(tenantID)
	if err := storage.ValidateTenantID(tenant); err != nil {
		return "", &InvalidSegmentError{Field: "tenant", Value: tenant, Err: err}
	}
	if err := validSegment("tenant", tenant); err != nil {
		return "", err
	}
	return tenant + "/", nil
}

// Root returns "{tenant}/{feature}/", the root of a feature's keyspace in
// tenantID.
func Root(tenantID, feature string) (string, error) {
	tenant, err := TenantRoot(tenantID)
	if err != nil {
		return "", err
	}
	if err := validSegment("feature", feature); err != nil {
		return "", err
	}
	return tenant + feature + "/", nil
}

// Prefix returns the keyspace holding a feature's objects of scope sc in
// tenantID: TenantRoot(tenantID) + FeaturePrefix(feature, sc, owner).
func Prefix(tenantID, feature string, sc Scope, owner string) (string, error) {
	tenant, err := TenantRoot(tenantID)
	if err != nil {
		return "", err
	}
	rel, err := FeaturePrefix(feature, sc, owner)
	if err != nil {
		return "", err
	}
	return tenant + rel, nil
}

// FeaturePrefix returns a scope's keyspace relative to its tenant root:
// "{feature}/shared/", "{feature}/users/{owner}/" or
// "{feature}/services/{owner}/". owner is the owning subject (User) or
// workload (Service); it is ignored for Tenant scope. A store whose backend
// is already a tenant's partition (the tenant root) keys its records with it.
func FeaturePrefix(feature string, sc Scope, owner string) (string, error) {
	if err := validSegment("feature", feature); err != nil {
		return "", err
	}
	root := feature + "/"
	switch sc {
	case Tenant:
		return root + sharedSegment + "/", nil
	case User:
		if err := validSegment("owner", owner); err != nil {
			return "", err
		}
		return root + usersSegment + "/" + owner + "/", nil
	case Service:
		if err := validSegment("owner", owner); err != nil {
			return "", err
		}
		return root + servicesSegment + "/" + owner + "/", nil
	default:
		return "", &InvalidScopeError{Value: string(sc)}
	}
}

// ScopeRoot returns "{feature}/shared/", "{feature}/users/" or
// "{feature}/services/": the relative prefix of every owner's objects of
// scope sc, for listing a scope across owners.
func ScopeRoot(feature string, sc Scope) (string, error) {
	if err := validSegment("feature", feature); err != nil {
		return "", err
	}
	switch sc {
	case Tenant:
		return feature + "/" + sharedSegment + "/", nil
	case User:
		return feature + "/" + usersSegment + "/", nil
	case Service:
		return feature + "/" + servicesSegment + "/", nil
	default:
		return "", &InvalidScopeError{Value: string(sc)}
	}
}

// SharedPrefix returns "{tenant}/{feature}/shared/".
func SharedPrefix(tenantID, feature string) (string, error) {
	return Prefix(tenantID, feature, Tenant, "")
}

// PersonalPrefix returns "{tenant}/{feature}/users/{subject}/".
func PersonalPrefix(tenantID, feature, subject string) (string, error) {
	return Prefix(tenantID, feature, User, subject)
}

// SharedSuffix returns "/{feature}/shared/": what follows the tenant in every
// tenant's shared prefix, for a scan that enumerates tenants.
func SharedSuffix(feature string) (string, error) {
	if err := validSegment("feature", feature); err != nil {
		return "", err
	}
	return "/" + feature + "/" + sharedSegment + "/", nil
}

// validSegment refuses a value that cannot be exactly one key segment.
func validSegment(field, value string) error {
	switch {
	case value == "":
		return &InvalidSegmentError{Field: field, Value: value, Reason: "empty"}
	case value == "." || value == ".." || strings.Contains(value, ".."):
		return &InvalidSegmentError{Field: field, Value: value, Reason: "path traversal"}
	case strings.ContainsAny(value, "/\\\x00"):
		return &InvalidSegmentError{Field: field, Value: value, Reason: "contains a separator"}
	default:
		return nil
	}
}

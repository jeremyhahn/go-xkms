// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

// Package scope defines the ownership scope (tenant / user / service) of
// SSH assets managed by xkms, the "<scope>/<owner>/<name>" identifier of an
// asset, and the storage layout shared by the keys, known_hosts and
// authorized_keys stores.
//
// The identifier (BuildKeyID / ParseKeyID) names an asset in APIs, backend
// key IDs and certificate CNs. The storage path (Kind.RecordPath) is where
// the asset's record lives inside its tenant's partition, following the
// xkms-wide scope layout (pkg/scope):
//
//	ssh/shared/<kind>/<name>             Tenant scope
//	ssh/users/<owner>/<kind>/<name>      User scope
//	ssh/services/<owner>/<kind>/<name>   Service scope
//
// Under the tenant root "{tenant}/" every partition is rooted at, that is
// "{tenant}/ssh/shared/...", "{tenant}/ssh/users/{subject}/..." and
// "{tenant}/ssh/services/{owner}/...". This package is the single source of
// truth for both forms; no SSH subpackage or SDK client open-codes joins or
// splits on "/".
package scope

import (
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

// Scope identifies the ownership domain of an SSH asset. It is the
// xkms-wide ownership scope (pkg/scope): a tenant-scoped key is visible to
// every user in that tenant, a user-scoped key only to the owning user, and a
// service-scoped key only to callers holding the explicit service permission.
type Scope = scope.Scope

// Scope constants, re-exported from pkg/scope. The string values are the
// canonical on-disk form.
const (
	// Tenant identifies tenant-owned SSH assets.
	Tenant = scope.Tenant

	// User identifies user-owned SSH assets.
	User = scope.User

	// Service identifies service-account-owned SSH assets.
	Service = scope.Service
)

// Parse normalizes s and returns the matching Scope or a
// *ScopeInvalidError. See scope.Parse.
func Parse(s string) (Scope, error) {
	return scope.Parse(s)
}

// BuildKeyID returns the canonical identifier "<scope>/<owner>/<name>" of
// an SSH asset. It is not a storage path; see Kind.RecordPath.
//
// owner and name must be non-empty and must not contain "/" — the
// separator is reserved for the layout itself. scope must satisfy
// Valid(). On violation the function returns *KeyIDMalformedError with
// Field set to the offending component.
func BuildKeyID(s Scope, owner, name string) (string, error) {
	if !s.Valid() {
		return "", &ScopeInvalidError{Value: string(s)}
	}
	if err := validateComponent("owner", owner); err != nil {
		return "", err
	}
	if err := validateComponent("name", name); err != nil {
		return "", err
	}
	// strings.Builder avoids the extra allocations of fmt.Sprintf on the
	// hot path; key IDs are constructed per request.
	var b strings.Builder
	b.Grow(len(s) + len(owner) + len(name) + 2)
	b.WriteString(string(s))
	b.WriteByte('/')
	b.WriteString(owner)
	b.WriteByte('/')
	b.WriteString(name)
	return b.String(), nil
}

// ParseKeyID splits id into its three components. Exactly two "/"
// separators are required; additional separators are treated as part of
// the name (so SSH key names with "/" in them still round-trip after
// construction via BuildKeyID, which rejects them).
//
// Returns *KeyIDMalformedError on a malformed id.
func ParseKeyID(id string) (Scope, string, string, error) {
	// SplitN(n=3) yields [scope, owner, name] even if name contains
	// additional "/" — we reject that case at BuildKeyID time, but this
	// keeps Parse resilient for forward compatibility.
	parts := strings.SplitN(id, "/", 3)
	if len(parts) != 3 {
		return "", "", "", &KeyIDMalformedError{Field: "id", Reason: "expected three /-separated components"}
	}
	sc := Scope(parts[0])
	if !sc.Valid() {
		return "", "", "", &ScopeInvalidError{Value: parts[0]}
	}
	if parts[1] == "" {
		return "", "", "", &KeyIDMalformedError{Field: "owner", Reason: "empty"}
	}
	if parts[2] == "" {
		return "", "", "", &KeyIDMalformedError{Field: "name", Reason: "empty"}
	}
	return sc, parts[1], parts[2], nil
}

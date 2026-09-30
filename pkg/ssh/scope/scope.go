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
// SSH assets managed by xkms and provides the canonical key-ID layout
// shared by keys, known_hosts, and authorized_keys storage.
//
// A key ID is "<scope>/<owner>/<name>", where owner is a tenant ID,
// user ID, or service ID depending on scope. This package is the single
// source of truth for that layout — every SSH subpackage and SDK client
// routes through BuildKeyID / ParseKeyID instead of open-coding joins or
// splits on "/" so future layout changes stay local.
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

// BuildKeyID returns the canonical storage-path fragment
// "<scope>/<owner>/<name>" identifying an SSH asset.
//
// owner and name must be non-empty and must not contain "/" — the
// separator is reserved for the layout itself. scope must satisfy
// Valid(). On violation the function returns *KeyIDMalformedError with
// Field set to the offending component.
func BuildKeyID(s Scope, owner, name string) (string, error) {
	if !s.Valid() {
		return "", &ScopeInvalidError{Value: string(s)}
	}
	if owner == "" {
		return "", &KeyIDMalformedError{Field: "owner", Reason: "empty"}
	}
	if name == "" {
		return "", &KeyIDMalformedError{Field: "name", Reason: "empty"}
	}
	if strings.ContainsRune(owner, '/') {
		return "", &KeyIDMalformedError{Field: "owner", Reason: "contains separator"}
	}
	if strings.ContainsRune(name, '/') {
		return "", &KeyIDMalformedError{Field: "name", Reason: "contains separator"}
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

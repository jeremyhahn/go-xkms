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

import "strings"

// Scope identifies the ownership domain of an SSH asset. A key owned at
// tenant scope is visible to every user in that tenant; a user-scoped
// key is visible only to the owning user; a service-scoped key is owned
// by an automated workload.
type Scope string

// Scope constants. The string values are the canonical on-disk form and
// MUST NOT change without a storage-migration plan.
const (
	// Tenant identifies tenant-owned SSH assets.
	Tenant Scope = "tenant"

	// User identifies user-owned SSH assets.
	User Scope = "user"

	// Service identifies service-account-owned SSH assets.
	Service Scope = "service"
)

// Valid reports whether s is one of the three canonical scope values.
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

// Parse normalizes s and returns the matching Scope or a
// *ScopeInvalidError. Leading and trailing whitespace is trimmed and
// comparison is case-insensitive; the returned Scope is always the
// canonical lowercase form.
func Parse(s string) (Scope, error) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	sc := Scope(trimmed)
	if !sc.Valid() {
		return "", &ScopeInvalidError{Value: s}
	}
	return sc, nil
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

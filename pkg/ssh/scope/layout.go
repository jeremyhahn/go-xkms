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
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

// Feature is the pkg/scope feature name every SSH asset is stored under.
const Feature = "ssh"

// Kind identifies which SSH store a record belongs to. It is the segment
// that follows the scope's keyspace in a record path.
type Kind string

// Kind values. The strings are the canonical storage form.
const (
	// KindKeys identifies SSH key envelopes.
	KindKeys Kind = "keys"

	// KindKnownHosts identifies known_hosts host-key pins.
	KindKnownHosts Kind = "known_hosts"

	// KindAuthorizedKeys identifies authorized_keys entries.
	KindAuthorizedKeys Kind = "authorized_keys"
)

// scopes is every scope, in the order Match tries their keyspaces.
var scopes = [...]Scope{Tenant, User, Service}

// Valid reports whether k is one of the three kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindKeys, KindKnownHosts, KindAuthorizedKeys:
		return true
	default:
		return false
	}
}

// RecordPath returns the storage path of the record of kind k named name,
// relative to its tenant's partition:
//
//	ssh/shared/<kind>/<name>             Tenant scope
//	ssh/users/<owner>/<kind>/<name>      User scope
//	ssh/services/<owner>/<kind>/<name>   Service scope
//
// The path is distinct from the "<scope>/<owner>/<name>" identifier
// BuildKeyID returns. A Tenant-scoped path carries no owner -- the tenant is
// the partition -- so a store keeps the owner in the record and must compare
// it with the owner a caller names.
//
// owner and name are validated exactly as BuildKeyID validates them
// (*KeyIDMalformedError); sc must be valid (*ScopeInvalidError) and k must be
// valid (*KindInvalidError).
func (k Kind) RecordPath(sc Scope, owner, name string) (string, error) {
	if !k.Valid() {
		return "", &KindInvalidError{Value: string(k)}
	}
	if !sc.Valid() {
		return "", &ScopeInvalidError{Value: string(sc)}
	}
	if err := validateComponent("owner", owner); err != nil {
		return "", err
	}
	if err := validateComponent("name", name); err != nil {
		return "", err
	}
	prefix, err := scope.FeaturePrefix(Feature, sc, owner)
	if err != nil {
		return "", err
	}
	return prefix + string(k) + "/" + name, nil
}

// ListPrefix returns the storage prefix a listing filtered by (sc, owner)
// scans. It spans every kind, so the caller keeps only the keys its kind
// Matches:
//
//   - sc empty: "ssh/", every scope (owner is ignored);
//   - owner empty, or sc Tenant: the scope's root across owners
//     ("ssh/shared/", "ssh/users/", "ssh/services/") -- a Tenant-scoped path
//     carries no owner, so the caller filters those records by their owner;
//   - otherwise: the owner's keyspace ("ssh/users/<owner>/",
//     "ssh/services/<owner>/").
//
// Returns *ScopeInvalidError for an invalid non-empty sc and
// *KeyIDMalformedError for an owner containing "/".
func ListPrefix(sc Scope, owner string) (string, error) {
	if sc == "" {
		return Feature + "/", nil
	}
	if !sc.Valid() {
		return "", &ScopeInvalidError{Value: string(sc)}
	}
	if strings.ContainsRune(owner, '/') {
		return "", &KeyIDMalformedError{Field: "owner", Reason: "contains separator"}
	}
	if owner == "" || sc == Tenant {
		return scope.ScopeRoot(Feature, sc)
	}
	return scope.FeaturePrefix(Feature, sc, owner)
}

// Match reports whether key is the storage path of a record of kind k, in
// the layout RecordPath builds. It lets a listing that scans a prefix shared
// by every kind keep only its own records.
func (k Kind) Match(key string) bool {
	for _, sc := range scopes {
		root, err := scope.ScopeRoot(Feature, sc)
		if err != nil {
			return false
		}
		rest, ok := strings.CutPrefix(key, root)
		if !ok {
			continue
		}
		if sc != Tenant {
			var owner string
			owner, rest, ok = strings.Cut(rest, "/")
			if !ok || owner == "" {
				return false
			}
		}
		kind, name, ok := strings.Cut(rest, "/")
		return ok && Kind(kind) == k && name != "" && !strings.ContainsRune(name, '/')
	}
	return false
}

// validateComponent refuses an owner or name that is empty or contains the
// "/" separator.
func validateComponent(field, value string) error {
	if value == "" {
		return &KeyIDMalformedError{Field: field, Reason: "empty"}
	}
	if strings.ContainsRune(value, '/') {
		return &KeyIDMalformedError{Field: field, Reason: "contains separator"}
	}
	return nil
}

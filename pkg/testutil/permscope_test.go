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

package testutil

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// TestPermissionScopeResolverReadsDeclaredScopes checks the read path against
// go-qrdb's own declarations, which the resolver must report unchanged: a
// self-scoped built-in, a tenant-only one, and a cross-tenant one. Asserting
// three different scopes rather than one guards against a resolver that
// answers a constant.
func TestPermissionScopeResolverReadsDeclaredScopes(t *testing.T) {
	resolver, err := NewPermissionScopeResolver()
	if err != nil {
		t.Fatalf("NewPermissionScopeResolver: %v", err)
	}

	cases := []struct {
		name string
		perm qrdbsdk.Permission
		want qrdbsdk.PermissionScope
	}{
		{"self-scoped built-in", qrdbsdk.Permission("keys:get"), qrdbsdk.PermissionScopeSelf},
		{"tenant-only built-in", qrdbsdk.Permission("tenant_barrier:init"), qrdbsdk.PermissionScopeTenantOnly},
		{"cross-scoped built-in", qrdbsdk.Permission("credentials:submit"), qrdbsdk.PermissionScopeCross},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolver.Scope(context.Background(), tc.perm)
			if err != nil {
				t.Fatalf("Scope(%q): %v", tc.perm, err)
			}
			if got != tc.want {
				t.Errorf("Scope(%q) = %v, want %v", tc.perm, got, tc.want)
			}
		})
	}
}

// TestPermissionScopeResolverRefusesUndeclared is the error path, and the one
// that makes the resolver worth having: a permission no layer declared must
// surface the authorizer's own refusal rather than a scope. A resolver that
// defaulted to self here would report every missing declaration as a
// deliberate one — the fail-open go-qrdb#504 closed.
func TestPermissionScopeResolverRefusesUndeclared(t *testing.T) {
	resolver, err := NewPermissionScopeResolver()
	if err != nil {
		t.Fatalf("NewPermissionScopeResolver: %v", err)
	}

	const never = qrdbsdk.Permission("xkms-testutil-never-declared:read")
	scope, err := resolver.Scope(context.Background(), never)
	if err == nil {
		t.Fatalf("Scope(%q) = %v, want an undeclared-scope error", never, scope)
	}
	var undeclared *qrdbsdk.PermissionUndeclaredScopeError
	if !errors.As(err, &undeclared) {
		t.Fatalf("Scope(%q) error = %T (%v), want *qrdbsdk.PermissionUndeclaredScopeError", never, err, err)
	}
	if undeclared.Permission != never {
		t.Errorf("error names permission %q, want %q", undeclared.Permission, never)
	}
}

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

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// TestScopeSurface proves the scope aliases carry the canonical access rule.
func TestScopeSurface(t *testing.T) {
	alice := ScopePrincipalFromContext(qrdbsdk.WithIdentity(context.Background(), &qrdbsdk.Identity{Subject: "alice", TenantID: "acme"}))
	if err := alice.Authorize(ScopeTarget{TenantID: "acme", Scope: ObjectScopeUser, Owner: "alice"}); err != nil {
		t.Fatalf("owner refused its own personal object: %v", err)
	}
	var cross *ScopeCrossTenantError
	if err := alice.Authorize(ScopeTarget{TenantID: "other", Scope: ObjectScopeTenant}); !errors.As(err, &cross) || !errors.Is(err, ErrScopeRefused) {
		t.Fatalf("cross-tenant err = %v", err)
	}

	root := ScopePrincipalOf(&qrdbsdk.Identity{Subject: "root", TenantID: ScopeSystemTenant})
	if err := root.Authorize(ScopeTarget{TenantID: ScopeSystemTenant, Scope: ObjectScopeTenant}); err != nil {
		t.Fatalf("system tenant refused its own shared object: %v", err)
	}
	if err := root.Authorize(ScopeTarget{TenantID: "acme", Scope: ObjectScopeTenant}); !errors.As(err, &cross) {
		t.Fatalf("system tenant to a tenant's shared object err = %v, want *ScopeCrossTenantError", err)
	}

	var unauthenticated *ScopeUnauthenticatedError
	if err := ScopePrincipalOf(nil).Authorize(ScopeTarget{TenantID: ScopeSystemTenant, Scope: ObjectScopeTenant}); !errors.As(err, &unauthenticated) || !errors.Is(err, ErrScopeRefused) {
		t.Fatalf("no identity err = %v, want *ScopeUnauthenticatedError", err)
	}
}

func TestScopeSurface_KeyspaceAndParse(t *testing.T) {
	if sc, err := ParseObjectScope(" User "); err != nil || sc != ObjectScopeUser {
		t.Fatalf("ParseObjectScope = %q, %v", sc, err)
	}
	var invalid *ScopeInvalidScopeError
	if _, err := ParseObjectScope("bogus"); !errors.As(err, &invalid) {
		t.Fatalf("ParseObjectScope(bogus) err = %v", err)
	}
	if p, err := ScopePersonalPrefix("acme", "ssh", "alice"); err != nil || p != "acme/ssh/users/alice/" {
		t.Fatalf("ScopePersonalPrefix = %q, %v", p, err)
	}
	if p, err := ScopeSharedPrefix("", "ssh"); err != nil || p != ScopeSystemTenant+"/ssh/shared/" {
		t.Fatalf("ScopeSharedPrefix = %q, %v", p, err)
	}
	var segment *ScopeInvalidSegmentError
	if _, err := ScopeTenantRoot("a/b"); !errors.As(err, &segment) {
		t.Fatalf("ScopeTenantRoot(a/b) err = %v", err)
	}
	if !ScopeIsSystem("") || ScopeTenantName("") != ScopeSystemTenant {
		t.Fatal("the empty tenant is the system tenant")
	}
}

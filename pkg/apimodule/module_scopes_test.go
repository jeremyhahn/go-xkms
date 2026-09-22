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

package apimodule

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// minModulePermissions is a discovery floor, borrowed from go-qrdb's own
// scope gate. Every assertion below is inside a loop over
// modulePermissions(), and an empty loop reports success — so the gate first
// insists the derived set is at least as large as it was when the gate was
// written. Measured 2026-09-22: 73. Raise it when the API surface grows; a
// drop below it is a red run, which is the point.
const minModulePermissions = 73

// upstreamDeclared records which of this module's permissions already had a
// scope BEFORE registerRoleGrants ran — that is, the ones go-qrdb declares
// itself. It is captured in init() because registerRoleGrants is a sync.Once
// reached from NewModule, so any test that constructs a module would
// otherwise blur the two layers together and make the ownership assertion in
// TestModuleDeclaresOnlyItsOwnScopes unable to fail.
//
// init() rather than TestMain: the snapshot needs only to precede the first
// test, and claiming TestMain for the whole package to take it would put a
// package-wide hook in the way of the next person who needs one.
var (
	upstreamDeclared    map[qrdbsdk.Permission]qrdbsdk.PermissionScope
	upstreamSnapshotErr error
)

func init() {
	resolver, err := testutil.NewPermissionScopeResolver()
	if err != nil {
		upstreamSnapshotErr = err
		return
	}
	ctx := context.Background()
	upstreamDeclared = map[qrdbsdk.Permission]qrdbsdk.PermissionScope{}
	for _, p := range modulePermissions() {
		scope, err := resolver.Scope(ctx, p)
		if err != nil {
			continue // undeclared upstream; xkms must declare it
		}
		upstreamDeclared[p] = scope
	}
}

// TestEveryModulePermissionDeclaresItsScope is the build gate for
// go-qrdb#504: no permission this module contributes may reach the authorizer
// without a declared tenancy scope.
//
// Before go-qrdb v0.19.0-alpha an unscoped permission was silently admitted
// as ScopeSelf. It is now refused, and rbac.ListPermissions — the path token
// issuance walks — fails on the FIRST unscoped permission an identity holds,
// so a single omission does not deny one call, it denies login. Four of this
// module's permissions were undeclared when go-quicbaas v0.11.0-alpha adopted
// go-xkms v0.14.0-alpha, and every login for a role carrying keys:read was
// rejected with "permission: no scope declared for keys:read".
//
// The gate reads scopes back through the SDK's per-tenant scope store, the
// same resolution path the RBAC authorizer uses, so it asserts what the
// authorizer sees rather than what a registry happens to hold.
func TestEveryModulePermissionDeclaresItsScope(t *testing.T) {
	if upstreamSnapshotErr != nil {
		t.Fatalf("upstream scope snapshot failed: %v", upstreamSnapshotErr)
	}

	// The module's own declarations land in the process-global layer here.
	registerRoleGrants()

	resolver, err := testutil.NewPermissionScopeResolver()
	if err != nil {
		t.Fatalf("NewPermissionScopeResolver: %v", err)
	}

	perms := modulePermissions()
	if len(perms) < minModulePermissions {
		t.Fatalf("modulePermissions() returned %d permissions, below the floor of %d — the surface shrank or derivation is broken, and an empty loop would pass every check below", len(perms), minModulePermissions)
	}

	ctx := context.Background()
	var undeclared []string
	counts := map[qrdbsdk.PermissionScope]int{}
	for _, p := range perms {
		scope, err := resolver.Scope(ctx, p)
		if err != nil {
			var undeclaredErr *qrdbsdk.PermissionUndeclaredScopeError
			if !errors.As(err, &undeclaredErr) {
				t.Errorf("Scope(%q): unexpected error type %T: %v", p, err, err)
				continue
			}
			undeclared = append(undeclared, string(p))
			continue
		}
		if !scope.Valid() {
			t.Errorf("Scope(%q) = %v, which is not a valid scope", p, scope)
			continue
		}
		counts[scope]++
	}

	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Fatalf("%d permission(s) this module contributes have no declared scope — the authorizer refuses each, and token issuance fails for every identity holding one. Declare each by name in module_scopes.go:\n  %s",
			len(undeclared), strings.Join(undeclared, "\n  "))
	}

	t.Logf("module scope declarations: total=%d self=%d cross=%d tenantOnly=%d (xkms-owned=%d, go-qrdb-owned=%d)",
		len(perms),
		counts[qrdbsdk.PermissionScopeSelf],
		counts[qrdbsdk.PermissionScopeCross],
		counts[qrdbsdk.PermissionScopeTenantOnly],
		len(selfScopedPermissions()),
		len(upstreamDeclared))
}

// TestModuleDeclaresOnlyItsOwnScopes keeps the ownership boundary: xkms
// declares the scope of the permissions go-qrdb does not, and of nothing
// else.
//
// RegisterPermissionScope overwrites, and xkms registers after go-qrdb's
// package init(). A declaration here for a name go-qrdb already declares
// would therefore not be a harmless duplicate — it would replace an upstream
// decision with a local one, silently, forever. If go-qrdb later narrows
// certs:revoke to tenant-only, an xkms entry for it would widen it straight
// back to self, which is the exact fail-open go-qrdb#504 closed.
func TestModuleDeclaresOnlyItsOwnScopes(t *testing.T) {
	if upstreamSnapshotErr != nil {
		t.Fatalf("upstream scope snapshot failed: %v", upstreamSnapshotErr)
	}

	var overrides []string
	for _, p := range selfScopedPermissions() {
		if scope, ok := upstreamDeclared[p]; ok {
			overrides = append(overrides, string(p)+" (go-qrdb declares it "+scope.String()+")")
		}
	}
	sort.Strings(overrides)
	if len(overrides) > 0 {
		t.Fatalf("%d scope declaration(s) in module_scopes.go overwrite a go-qrdb decision — remove them, go-qrdb owns those names:\n  %s",
			len(overrides), strings.Join(overrides, "\n  "))
	}
}

// TestModuleScopeDeclarationsAreAllContributed is the other direction: every
// permission module_scopes.go declares must be one this module actually
// contributes. A declaration for a name that is not in modulePermissions() is
// a typo or a stale entry, and either one hides a real omission behind a gate
// that looks green.
func TestModuleScopeDeclarationsAreAllContributed(t *testing.T) {
	contributed := map[qrdbsdk.Permission]struct{}{}
	for _, p := range modulePermissions() {
		contributed[p] = struct{}{}
	}

	var strays []string
	for _, p := range selfScopedPermissions() {
		if _, ok := contributed[p]; !ok {
			strays = append(strays, string(p))
		}
	}
	sort.Strings(strays)
	if len(strays) > 0 {
		t.Fatalf("%d scope declaration(s) name a permission this module does not contribute:\n  %s",
			len(strays), strings.Join(strays, "\n  "))
	}
}

// TestUndeclaredPermissionHasNoScope proves the gate above can fail. A scope
// gate whose resolver answered a scope for everything — including a name no
// layer ever declared — would pass over the very regression it exists to
// catch, so the negative case is asserted explicitly: an undeclared
// permission must surface the authorizer's own error, not a scope.
func TestUndeclaredPermissionHasNoScope(t *testing.T) {
	resolver, err := testutil.NewPermissionScopeResolver()
	if err != nil {
		t.Fatalf("NewPermissionScopeResolver: %v", err)
	}

	const never = qrdbsdk.Permission("xkms-scope-gate-never-declared:read")
	scope, err := resolver.Scope(context.Background(), never)
	if err == nil {
		t.Fatalf("Scope(%q) = %v, want an undeclared-scope error: a resolver that answers for an undeclared permission cannot detect a missing declaration", never, scope)
	}
	var undeclaredErr *qrdbsdk.PermissionUndeclaredScopeError
	if !errors.As(err, &undeclaredErr) {
		t.Fatalf("Scope(%q) error = %T (%v), want *qrdbsdk.PermissionUndeclaredScopeError — the RBAC authorizer denies on that type", never, err, err)
	}
	if undeclaredErr.Permission != never {
		t.Errorf("error names permission %q, want %q", undeclaredErr.Permission, never)
	}
}

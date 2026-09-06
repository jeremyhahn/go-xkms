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

// Package qrdbrole converges a role store onto the built-in role definitions
// the linked go-qrdb build publishes.
//
// It is NOT a role service and it defines no role model: roles, their reserved
// names, their permission sets and the reconciliation contract all belong to
// go-qrdb, and this package reads them through qrdbsdk.BuiltInRoles and
// qrdbsdk.AllPermissions — the SDK seams go-qrdb exports for exactly this.
// What it provides is ONE implementation of qrdb's ReconcileBuiltInRoles
// semantics over the transport.RoleClient seam, so go-xkms's several
// in-memory RoleClient implementations answer the verb identically instead of
// each carrying its own copy of the diff.
package qrdbrole

import (
	"context"
	"sort"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// Store is the narrow subset of qrdb's transport.RoleClient that
// reconciliation needs: read the tenant's roles, seed a built-in the tenant
// does not hold, and replace a stored built-in's permission set.
//
// Reading through ListRoles rather than a per-name lookup is deliberate: it
// needs no not-found classification, so a store whose miss is reported by an
// error value this package cannot name still reconciles correctly.
type Store interface {
	ListRoles(ctx context.Context, req *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error)
	CreateRole(ctx context.Context, req *qrdbtransport.CreateRoleRequest) (*qrdbtransport.Role, error)
	UpdateRole(ctx context.Context, req *qrdbtransport.UpdateRoleRequest) (*qrdbtransport.Role, error)
}

// Reconcile brings a tenant's stored built-in roles back into agreement with
// the definitions this build publishes, and reports only what changed.
//
// It mirrors go-qrdb's ReconcileBuiltInRoles (go-qrdb#354) semantics:
//
//   - A built-in the tenant does not hold is seeded from its canonical
//     definition — deterministic id included — and reported with Created set
//     and its whole permission set in Added.
//   - A built-in whose stored permission SET differs from the build's has its
//     permissions replaced, reported as Added and Removed.
//   - A built-in already in agreement is left completely alone: no write at
//     all, so a second call performs zero writes and reports no roles.
//   - Owner is repaired when the tenant holds it and is NEVER created. Owner is
//     provisioned only under the standard RBAC posture, so seeding it would
//     hand a strict separation-of-duties tenant a superuser role nobody asked
//     for.
//   - A role whose name is not a built-in name is never read and never written.
//
// An empty req, or an empty TenantID, reconciles the system tenant.
//
// TIMING IS PART OF THE CONTRACT: qrdbsdk.BuiltInRoles resolves its permission
// sets through the global permission registry at call time, so a caller that
// contributes its own permissions must register them BEFORE calling, or every
// tenant converges onto a definition missing those verbs.
func Reconcile(ctx context.Context, store Store, req *qrdbtransport.ReconcileRolesRequest) (*qrdbtransport.ReconcileRolesResponse, error) {
	tenantID := qrdbsdk.SystemTenantID
	if req != nil && req.TenantID != "" {
		tenantID = req.TenantID
	}

	stored, err := storedByName(ctx, store, tenantID)
	if err != nil {
		return nil, err
	}

	report := &qrdbtransport.ReconcileRolesResponse{TenantID: tenantID}

	for _, canonical := range qrdbsdk.BuiltInRoles(tenantID) {
		result, err := reconcileRole(ctx, store, tenantID, canonical.Name, canonical.ID,
			permissionStrings(canonical.Permissions), stored[canonical.Name], true)
		if err != nil {
			return nil, err
		}
		if result != nil {
			report.Roles = append(report.Roles, *result)
		}
	}

	// Owner is repaired in place when present and never created — see the
	// method doc. Its canonical grant is every registered permission.
	owner, held := stored[qrdbsdk.RoleNameOwner]
	if held {
		result, err := reconcileRole(ctx, store, tenantID, qrdbsdk.RoleNameOwner, owner.ID,
			permissionStrings(qrdbsdk.AllPermissions()), owner, false)
		if err != nil {
			return nil, err
		}
		if result != nil {
			report.Roles = append(report.Roles, *result)
		}
	}

	return report, nil
}

// storedByName indexes the tenant's roles by name. Roles belonging to another
// tenant are dropped, because a store that ignores the tenant filter must not
// be able to make this converge one tenant onto another's records.
func storedByName(ctx context.Context, store Store, tenantID string) (map[string]*qrdbtransport.Role, error) {
	listed, err := store.ListRoles(ctx, &qrdbtransport.ListRolesRequest{TenantID: tenantID})
	if err != nil {
		return nil, &ReconcileError{TenantID: tenantID, Op: OpList, Err: err}
	}

	byName := make(map[string]*qrdbtransport.Role)
	if listed == nil {
		return byName, nil
	}
	for _, r := range listed.Roles {
		if r == nil || (r.TenantID != "" && r.TenantID != tenantID) {
			continue
		}
		byName[r.Name] = r
	}
	return byName, nil
}

// reconcileRole converges ONE role and returns the result, or nil when the
// stored record already agreed with the build. seed decides whether an absent
// role is created or skipped.
func reconcileRole(
	ctx context.Context,
	store Store,
	tenantID, name, roleID string,
	want []string,
	stored *qrdbtransport.Role,
	seed bool,
) (*qrdbtransport.RoleReconcileResult, error) {
	if stored == nil {
		if !seed {
			return nil, nil
		}
		created, err := store.CreateRole(ctx, &qrdbtransport.CreateRoleRequest{
			ID:          roleID,
			Name:        name,
			TenantID:    tenantID,
			Permissions: want,
		})
		if err != nil {
			return nil, &ReconcileError{TenantID: tenantID, Role: name, Op: OpCreate, Err: err}
		}
		id := roleID
		if created != nil && created.ID != "" {
			id = created.ID
		}
		return &qrdbtransport.RoleReconcileResult{
			RoleID:  id,
			Name:    name,
			Created: true,
			Added:   append([]string(nil), want...),
		}, nil
	}

	added, removed := permissionSetDiff(stored.Permissions, want)
	if len(added) == 0 && len(removed) == 0 {
		// IDEMPOTENCY. The write is skipped rather than performed with an
		// equal value: a no-op update would still bump UpdatedAt and, in a
		// real store, emit an audit record and replicate a log entry.
		return nil, nil
	}

	if _, err := store.UpdateRole(ctx, &qrdbtransport.UpdateRoleRequest{
		ID:          stored.ID,
		Permissions: want,
	}); err != nil {
		return nil, &ReconcileError{TenantID: tenantID, Role: name, Op: OpUpdate, Err: err}
	}

	return &qrdbtransport.RoleReconcileResult{
		RoleID:  stored.ID,
		Name:    name,
		Added:   added,
		Removed: removed,
	}, nil
}

// permissionSetDiff compares two permission lists as SETS and returns the
// members of want absent from have (added) and the members of have absent from
// want (removed), each sorted. Order carries no meaning in a grant and a
// repeated permission grants nothing extra.
func permissionSetDiff(have, want []string) (added, removed []string) {
	haveSet := make(map[string]struct{}, len(have))
	for _, p := range have {
		haveSet[p] = struct{}{}
	}
	wantSet := make(map[string]struct{}, len(want))
	for _, p := range want {
		wantSet[p] = struct{}{}
	}

	for p := range wantSet {
		if _, ok := haveSet[p]; !ok {
			added = append(added, p)
		}
	}
	for p := range haveSet {
		if _, ok := wantSet[p]; !ok {
			removed = append(removed, p)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// permissionStrings renders qrdb's permission values as the strings the
// transport role payload carries, sorted so a stored grant and a report are
// both deterministic.
func permissionStrings(perms []qrdbsdk.Permission) []string {
	out := make([]string, len(perms))
	for i, p := range perms {
		out[i] = p.String()
	}
	sort.Strings(out)
	return out
}

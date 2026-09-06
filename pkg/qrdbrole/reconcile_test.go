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

package qrdbrole

import (
	"context"
	"errors"
	"sort"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// errStore is the failure a programmed store returns.
var errStore = errors.New("store unavailable")

// memStore is an in-memory Store with real semantics plus injectable failures,
// so both the convergence and its error classification are exercised against
// the same object.
type memStore struct {
	roles  map[string]*qrdbtransport.Role
	nextID int

	listErr   error
	createErr error
	updateErr error

	creates int
	updates int
}

func newMemStore() *memStore {
	return &memStore{roles: make(map[string]*qrdbtransport.Role)}
}

func (m *memStore) ListRoles(_ context.Context, req *qrdbtransport.ListRolesRequest) (*qrdbtransport.ListRolesResponse, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	out := &qrdbtransport.ListRolesResponse{}
	for _, r := range m.roles {
		if req != nil && req.TenantID != "" && r.TenantID != req.TenantID {
			continue
		}
		out.Roles = append(out.Roles, r)
	}
	out.Total = len(out.Roles)
	return out, nil
}

func (m *memStore) CreateRole(_ context.Context, req *qrdbtransport.CreateRoleRequest) (*qrdbtransport.Role, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	m.creates++
	id := req.ID
	if id == "" {
		m.nextID++
		id = "generated-" + req.Name
	}
	r := &qrdbtransport.Role{
		ID:          id,
		Name:        req.Name,
		TenantID:    req.TenantID,
		Permissions: append([]string(nil), req.Permissions...),
	}
	m.roles[id] = r
	return r, nil
}

func (m *memStore) UpdateRole(_ context.Context, req *qrdbtransport.UpdateRoleRequest) (*qrdbtransport.Role, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	r, ok := m.roles[req.ID]
	if !ok {
		return nil, &qrdbtransport.RoleNotFoundError{ID: req.ID}
	}
	m.updates++
	if req.Permissions != nil {
		r.Permissions = append([]string(nil), req.Permissions...)
	}
	return r, nil
}

// put stores a role directly, bypassing the counted write paths, so a test can
// set up drift without it showing up as a reconciliation write.
func (m *memStore) put(r *qrdbtransport.Role) { m.roles[r.ID] = r }

// canonicalPermissions returns the sorted permission strings the build grants
// the named built-in role in the given tenant.
func canonicalPermissions(t *testing.T, tenantID, name string) []string {
	t.Helper()
	for _, r := range qrdbsdk.BuiltInRoles(tenantID) {
		if r.Name != name {
			continue
		}
		out := make([]string, len(r.Permissions))
		for i, p := range r.Permissions {
			out[i] = p.String()
		}
		sort.Strings(out)
		return out
	}
	t.Fatalf("BuiltInRoles(%q) has no role named %q", tenantID, name)
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReconcileSeedsEveryBuiltInAndIsIdempotent(t *testing.T) {
	const tenantID = "tenant-a"
	store := newMemStore()

	report, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.TenantID != tenantID {
		t.Errorf("TenantID = %q, want %q", report.TenantID, tenantID)
	}

	want := qrdbsdk.BuiltInRoles(tenantID)
	if len(report.Roles) != len(want) {
		t.Fatalf("reported %d roles, want %d (one per built-in)", len(report.Roles), len(want))
	}
	if store.creates != len(want) {
		t.Errorf("creates = %d, want %d", store.creates, len(want))
	}
	for i, got := range report.Roles {
		if !got.Created {
			t.Errorf("role %q: Created = false, want true on a seeded role", got.Name)
		}
		if got.Name != want[i].Name {
			t.Errorf("role %d: Name = %q, want %q (report order follows BuiltInRoles)", i, got.Name, want[i].Name)
		}
		if got.RoleID != want[i].ID {
			t.Errorf("role %q: RoleID = %q, want the deterministic %q", got.Name, got.RoleID, want[i].ID)
		}
		if len(got.Removed) != 0 {
			t.Errorf("role %q: Removed = %v, want none on a seeded role", got.Name, got.Removed)
		}
		if wantPerms := canonicalPermissions(t, tenantID, got.Name); !equalStrings(got.Added, wantPerms) {
			t.Errorf("role %q: Added = %v, want the whole canonical set %v", got.Name, got.Added, wantPerms)
		}
	}

	// IDEMPOTENCY: a converged tenant reports nothing and writes nothing.
	creates, updates := store.creates, store.updates
	second, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if len(second.Roles) != 0 {
		t.Errorf("second Reconcile reported %d roles, want 0", len(second.Roles))
	}
	if store.creates != creates || store.updates != updates {
		t.Errorf("second Reconcile wrote: creates %d->%d, updates %d->%d",
			creates, store.creates, updates, store.updates)
	}
}

func TestReconcileRepairsDriftAndLeavesCustomRolesAlone(t *testing.T) {
	const tenantID = "tenant-b"
	store := newMemStore()

	// Seed the tenant, then drift one built-in: drop a granted permission and
	// add one the build never granted.
	if _, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID}); err != nil {
		t.Fatalf("seed Reconcile: %v", err)
	}
	custom := &qrdbtransport.Role{
		ID:          "custom-1",
		Name:        "release-manager",
		TenantID:    tenantID,
		Permissions: []string{"retired:verb"},
	}
	store.put(custom)

	canonical := canonicalPermissions(t, tenantID, qrdbsdk.RoleNameAuditor)
	if len(canonical) == 0 {
		t.Fatalf("auditor has no canonical permissions to drift")
	}
	var drifted *qrdbtransport.Role
	for _, r := range store.roles {
		if r.Name == qrdbsdk.RoleNameAuditor {
			drifted = r
		}
	}
	if drifted == nil {
		t.Fatalf("auditor was not seeded")
	}
	dropped := canonical[0]
	kept := append([]string(nil), canonical[1:]...)
	drifted.Permissions = append(kept, "retired:verb")

	store.creates, store.updates = 0, 0
	report, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(report.Roles) != 1 {
		t.Fatalf("reported %d roles, want only the drifted one: %+v", len(report.Roles), report.Roles)
	}
	got := report.Roles[0]
	if got.Name != qrdbsdk.RoleNameAuditor {
		t.Errorf("Name = %q, want %q", got.Name, qrdbsdk.RoleNameAuditor)
	}
	if got.Created {
		t.Error("Created = true, want false on a repaired role")
	}
	if !equalStrings(got.Added, []string{dropped}) {
		t.Errorf("Added = %v, want %v", got.Added, []string{dropped})
	}
	if !equalStrings(got.Removed, []string{"retired:verb"}) {
		t.Errorf("Removed = %v, want [retired:verb]", got.Removed)
	}
	if store.updates != 1 {
		t.Errorf("updates = %d, want exactly 1", store.updates)
	}
	if store.creates != 0 {
		t.Errorf("creates = %d, want 0", store.creates)
	}
	if !equalStrings(drifted.Permissions, canonical) {
		t.Errorf("stored auditor permissions = %v, want the canonical set %v", drifted.Permissions, canonical)
	}
	if !equalStrings(custom.Permissions, []string{"retired:verb"}) {
		t.Errorf("custom role was rewritten: %v", custom.Permissions)
	}
}

func TestReconcileRepairsOwnerWhenPresentAndNeverCreatesIt(t *testing.T) {
	const tenantID = "tenant-c"

	// Absent: Owner is never seeded.
	store := newMemStore()
	report, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	for _, r := range report.Roles {
		if r.Name == qrdbsdk.RoleNameOwner {
			t.Fatal("Owner was created; it is posture-conditional and must never be seeded")
		}
	}
	for _, r := range store.roles {
		if r.Name == qrdbsdk.RoleNameOwner {
			t.Fatal("Owner was written to the store")
		}
	}

	// Present but drifted: Owner is repaired to the full permission set.
	owner := &qrdbtransport.Role{
		ID:          qrdbsdk.SystemRoleID(tenantID, qrdbsdk.RoleNameOwner),
		Name:        qrdbsdk.RoleNameOwner,
		TenantID:    tenantID,
		Permissions: []string{"retired:verb"},
	}
	store.put(owner)
	store.updates = 0

	report, err = Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Reconcile with Owner: %v", err)
	}
	if len(report.Roles) != 1 || report.Roles[0].Name != qrdbsdk.RoleNameOwner {
		t.Fatalf("report = %+v, want only Owner", report.Roles)
	}
	all := qrdbsdk.AllPermissions()
	if len(owner.Permissions) != len(all) {
		t.Errorf("Owner holds %d permissions, want all %d", len(owner.Permissions), len(all))
	}
	if !equalStrings(report.Roles[0].Removed, []string{"retired:verb"}) {
		t.Errorf("Removed = %v, want [retired:verb]", report.Roles[0].Removed)
	}
}

func TestReconcileNilRequestTargetsTheSystemTenant(t *testing.T) {
	store := newMemStore()
	report, err := Reconcile(context.Background(), store, nil)
	if err != nil {
		t.Fatalf("Reconcile(nil): %v", err)
	}
	if report.TenantID != qrdbsdk.SystemTenantID {
		t.Errorf("TenantID = %q, want %q", report.TenantID, qrdbsdk.SystemTenantID)
	}
	for _, r := range store.roles {
		if r.TenantID != qrdbsdk.SystemTenantID {
			t.Errorf("seeded role %q into tenant %q, want %q", r.Name, r.TenantID, qrdbsdk.SystemTenantID)
		}
	}

	// An empty TenantID reaches the same tenant as a nil request.
	empty, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{})
	if err != nil {
		t.Fatalf("Reconcile(empty): %v", err)
	}
	if len(empty.Roles) != 0 {
		t.Errorf("empty-tenant Reconcile reported %d roles, want 0 (already converged)", len(empty.Roles))
	}
}

func TestReconcileIgnoresRolesFromAnotherTenant(t *testing.T) {
	const tenantID = "tenant-d"
	store := newMemStore()

	// A store that ignores the tenant filter must not make reconciliation
	// converge one tenant onto another's records.
	foreign := &qrdbtransport.Role{
		ID:          "foreign-admin",
		Name:        qrdbsdk.RoleNameAdmin,
		TenantID:    "someone-else",
		Permissions: []string{"retired:verb"},
	}
	store.put(foreign)

	report, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !equalStrings(foreign.Permissions, []string{"retired:verb"}) {
		t.Errorf("the other tenant's admin was rewritten: %v", foreign.Permissions)
	}
	var seededAdmin bool
	for _, r := range report.Roles {
		if r.Name == qrdbsdk.RoleNameAdmin && r.Created {
			seededAdmin = true
		}
	}
	if !seededAdmin {
		t.Error("admin was not seeded into the requested tenant")
	}
}

func TestReconcileListFailureIsReportedAsAListError(t *testing.T) {
	store := newMemStore()
	store.listErr = errStore

	_, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: "tenant-e"})
	if err == nil {
		t.Fatal("Reconcile succeeded with a failing ListRoles")
	}
	var rerr *ReconcileError
	if !errors.As(err, &rerr) {
		t.Fatalf("error is %T, want *ReconcileError", err)
	}
	if rerr.Op != OpList {
		t.Errorf("Op = %q, want %q", rerr.Op, OpList)
	}
	if rerr.TenantID != "tenant-e" {
		t.Errorf("TenantID = %q, want tenant-e", rerr.TenantID)
	}
	if rerr.Role != "" {
		t.Errorf("Role = %q, want empty: a list failure belongs to no single role", rerr.Role)
	}
	if !errors.Is(err, errStore) {
		t.Error("the underlying store failure is not reachable through errors.Is")
	}
	if rerr.Error() == "" {
		t.Error("Error() is empty")
	}
}

func TestReconcileCreateFailureIsReportedAgainstTheRole(t *testing.T) {
	store := newMemStore()
	store.createErr = errStore

	_, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: "tenant-f"})
	if err == nil {
		t.Fatal("Reconcile succeeded with a failing CreateRole")
	}
	var rerr *ReconcileError
	if !errors.As(err, &rerr) {
		t.Fatalf("error is %T, want *ReconcileError", err)
	}
	if rerr.Op != OpCreate {
		t.Errorf("Op = %q, want %q", rerr.Op, OpCreate)
	}
	if rerr.Role == "" {
		t.Error("Role is empty; a seed failure names the role it could not seed")
	}
	if !errors.Is(err, errStore) {
		t.Error("the underlying store failure is not reachable through errors.Is")
	}
}

func TestReconcileUpdateFailureIsReportedAgainstTheRole(t *testing.T) {
	const tenantID = "tenant-g"
	store := newMemStore()
	if _, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID}); err != nil {
		t.Fatalf("seed Reconcile: %v", err)
	}
	for _, r := range store.roles {
		r.Permissions = []string{"retired:verb"}
	}
	store.updateErr = errStore

	_, err := Reconcile(context.Background(), store, &qrdbtransport.ReconcileRolesRequest{TenantID: tenantID})
	if err == nil {
		t.Fatal("Reconcile succeeded with a failing UpdateRole")
	}
	var rerr *ReconcileError
	if !errors.As(err, &rerr) {
		t.Fatalf("error is %T, want *ReconcileError", err)
	}
	if rerr.Op != OpUpdate {
		t.Errorf("Op = %q, want %q", rerr.Op, OpUpdate)
	}
	if rerr.Role == "" {
		t.Error("Role is empty; a repair failure names the role it could not repair")
	}
	if !errors.Is(err, errStore) {
		t.Error("the underlying store failure is not reachable through errors.Is")
	}
}

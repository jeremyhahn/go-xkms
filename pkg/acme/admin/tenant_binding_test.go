//go:build codec_json

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

package admin

// Tenant binding tests for go-xkms#1225. The permission gate binds the
// caller's OWN tenant as the request's target tenant, so a tenant Admin's
// self-scoped grants admit a request naming ANY tenant, account or
// certificate. The binding in the admin service is what confines it. These
// tests drive the service directly with an identity on the context and a qrdb
// double that enforces nothing, so no transport or qrdb check can mask a
// missing service-layer check.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

const (
	boundTenantA = "tenant-a"
	boundTenantB = "tenant-b"
)

// callerCtx returns a context carrying a tenant-scoped Admin of tenantID, as
// the authentication middleware publishes it.
func callerCtx(tenantID string) context.Context {
	return withUser(context.Background(), &AuthenticatedUser{
		UserID:   "admin@" + tenantID,
		Username: "admin@" + tenantID,
		TenantID: tenantID,
		Roles:    []string{qrdbsdk.RoleNameAdmin},
	})
}

// platformCtx returns a context carrying an administrator of the reserved
// system tenant: the platform scope that may address every tenant.
func platformCtx() context.Context {
	return callerCtx(qrdbsdk.SystemTenantID)
}

// requireTenantRefusal asserts err is the binding's refusal and that it is
// indistinguishable from a genuinely missing tenant.
func requireTenantRefusal(t *testing.T, err error, op string) {
	t.Helper()
	var bindErr *TenantBindingError
	require.ErrorAs(t, err, &bindErr, op)
	assert.ErrorIs(t, err, ErrTenantNotFound, op)
	assert.Equal(t, ErrTenantNotFound.Error(), err.Error(), op)
	assert.True(t, IsNotFoundError(err), op)
}

// bindingFixture is a tenant-aware admin service holding two tenants, each
// with a custom role and a user, plus a victim EAB in tenant-b.
type bindingFixture struct {
	svc   *TenantAwareAdminService
	roleB *db.Role
	userB *db.User
	roleA *db.Role
	userA *db.User
	eabB  string
}

func newBindingFixture(t *testing.T) *bindingFixture {
	t.Helper()
	svc := newTenantAwareTestService(t)
	ctx := platformCtx()
	f := &bindingFixture{svc: svc}

	for _, id := range []string{boundTenantA, boundTenantB} {
		_, err := svc.CreateTenant(ctx, CreateTenantRequest{ID: id, Name: id})
		require.NoError(t, err)
	}

	var err error
	f.roleA, err = svc.CreateTenantRole(ctx, boundTenantA, &db.CreateRoleRequest{Name: "role-a", Permissions: []string{"kv:get"}})
	require.NoError(t, err)
	f.roleB, err = svc.CreateTenantRole(ctx, boundTenantB, &db.CreateRoleRequest{Name: "role-b", Permissions: []string{"kv:get"}})
	require.NoError(t, err)
	f.userA, err = svc.CreateTenantUser(ctx, boundTenantA, &db.CreateUserRequest{Username: "user-a", Name: "User A", Email: "user-a@example.com"})
	require.NoError(t, err)
	f.userB, err = svc.CreateTenantUser(ctx, boundTenantB, &db.CreateUserRequest{Username: "user-b", Name: "User B", Email: "user-b@example.com"})
	require.NoError(t, err)

	eab, err := svc.CreateTenantEAB(ctx, boundTenantB, CreateEABRequest{Purpose: "account-binding"})
	require.NoError(t, err)
	f.eabB = eab.ID
	return f
}

// TestTenantBinding_ForeignTenantRefusedAsNotFound is the go-xkms#1225
// regression for every {id}-scoped tenant operation: a tenant-a Admin naming
// tenant-b is refused exactly like a missing tenant, and tenant-b is intact.
func TestTenantBinding_ForeignTenantRefusedAsNotFound(t *testing.T) {
	f := newBindingFixture(t)
	svc := f.svc
	ctx := callerCtx(boundTenantA)
	userBID := strconv.FormatUint(f.userB.ID, 10)

	ops := map[string]func() error{
		"get tenant": func() error { _, err := svc.GetTenant(ctx, boundTenantB); return err },
		"update tenant": func() error {
			_, err := svc.UpdateTenant(ctx, boundTenantB, UpdateTenantRequest{Name: "pwned"})
			return err
		},
		"update tenant status": func() error { return svc.UpdateTenantStatus(ctx, boundTenantB, "suspended") },
		"delete tenant":        func() error { return svc.DeleteTenant(ctx, boundTenantB) },
		"create root CA": func() error {
			_, err := svc.CreateTenantRootCA(ctx, boundTenantB, CreateTenantRootCARequest{CommonName: "x", KeyAlgorithm: "ECDSA", ValidityYears: 1})
			return err
		},
		"create intermediate CA": func() error {
			_, err := svc.CreateTenantIntermediateCA(ctx, boundTenantB, CreateTenantIntermediateCARequest{CommonName: "x", KeyAlgorithm: "ECDSA", ParentType: "global", ValidityYears: 1})
			return err
		},
		"get intermediate CA": func() error { _, err := svc.GetTenantIntermediateCA(ctx, boundTenantB, "ca-1"); return err },
		"list intermediate CAs": func() error {
			_, err := svc.ListTenantIntermediateCAs(ctx, boundTenantB)
			return err
		},
		"update intermediate CA status": func() error {
			return svc.UpdateTenantIntermediateCAStatus(ctx, boundTenantB, "ca-1", "revoked")
		},
		"set default intermediate CA": func() error { return svc.SetTenantDefaultIntermediateCA(ctx, boundTenantB, "ca-1") },
		"get CA status":               func() error { _, err := svc.GetTenantCAStatus(ctx, boundTenantB); return err },
		"create EAB": func() error {
			_, err := svc.CreateTenantEAB(ctx, boundTenantB, CreateEABRequest{Purpose: "account-binding"})
			return err
		},
		"get EAB":    func() error { _, err := svc.GetTenantEAB(ctx, boundTenantB, f.eabB); return err },
		"delete EAB": func() error { return svc.DeleteTenantEAB(ctx, boundTenantB, f.eabB) },
		"list EABs": func() error {
			_, _, err := svc.ListTenantEABs(ctx, boundTenantB, ListEABRequest{})
			return err
		},
		"create role": func() error {
			_, err := svc.CreateTenantRole(ctx, boundTenantB, &db.CreateRoleRequest{Name: "planted", Permissions: []string{"kv:get"}})
			return err
		},
		"get role": func() error { _, err := svc.GetTenantRole(ctx, boundTenantB, f.roleB.ID); return err },
		"update role": func() error {
			_, err := svc.UpdateTenantRole(ctx, boundTenantB, &db.UpdateRoleRequest{ID: f.roleB.ID, Permissions: []string{"kv:put"}})
			return err
		},
		"delete role": func() error { return svc.DeleteTenantRole(ctx, boundTenantB, f.roleB.ID) },
		"list roles": func() error {
			_, err := svc.ListTenantRoles(ctx, boundTenantB, &db.ListRolesRequest{})
			return err
		},
		"create user": func() error {
			_, err := svc.CreateTenantUser(ctx, boundTenantB, &db.CreateUserRequest{Username: "planted"})
			return err
		},
		"get user": func() error { _, err := svc.GetTenantUser(ctx, boundTenantB, userBID); return err },
		"update user": func() error {
			_, err := svc.UpdateTenantUser(ctx, boundTenantB, &db.UpdateUserRequest{ID: f.userB.ID, Name: "pwned"})
			return err
		},
		"delete user": func() error { return svc.DeleteTenantUser(ctx, boundTenantB, userBID) },
		"list users": func() error {
			_, err := svc.ListTenantUsers(ctx, boundTenantB, &db.ListUsersRequest{})
			return err
		},
	}
	for op, call := range ops {
		t.Run(op, func(t *testing.T) {
			requireTenantRefusal(t, call(), op)
		})
	}

	// Tenant-b is intact.
	pctx := platformCtx()
	info, err := svc.GetTenant(pctx, boundTenantB)
	require.NoError(t, err)
	assert.Equal(t, boundTenantB, info.Name)
	assert.Equal(t, entities.TenantStatusActive, info.Status)
	role, err := svc.GetTenantRole(pctx, boundTenantB, f.roleB.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"kv:get"}, role.Permissions)
	user, err := svc.GetTenantUser(pctx, boundTenantB, userBID)
	require.NoError(t, err)
	assert.Equal(t, "User B", user.Name)
	_, err = svc.GetTenantEAB(pctx, boundTenantB, f.eabB)
	require.NoError(t, err)
	roles, err := svc.ListTenantRoles(pctx, boundTenantB, &db.ListRolesRequest{})
	require.NoError(t, err)
	assert.Len(t, roles.Roles, 1, "no role may be planted in tenant-b")
	users, err := svc.ListTenantUsers(pctx, boundTenantB, &db.ListUsersRequest{})
	require.NoError(t, err)
	assert.Len(t, users.Users, 1, "no user may be planted in tenant-b")
}

// TestTenantBinding_MissingTenantMatchesForeignTenant proves the refusal adds
// nothing a probe could enumerate: a tenant that does not exist answers the
// tenant caller with the same error as one that exists but is foreign.
func TestTenantBinding_MissingTenantMatchesForeignTenant(t *testing.T) {
	f := newBindingFixture(t)
	ctx := callerCtx(boundTenantA)

	_, foreign := f.svc.GetTenant(ctx, boundTenantB)
	_, missing := f.svc.GetTenant(ctx, "no-such-tenant")
	requireTenantRefusal(t, foreign, "foreign")
	requireTenantRefusal(t, missing, "missing")
	assert.Equal(t, foreign.Error(), missing.Error())
}

// TestTenantBinding_ForeignRoleAndUserUnderOwnTenant proves a role or user is
// checked against the tenant the path names before it is read or mutated:
// tenant-b's role and user, addressed under tenant-a, are absent -- for the
// tenant caller and for the platform alike -- and are left untouched.
func TestTenantBinding_ForeignRoleAndUserUnderOwnTenant(t *testing.T) {
	f := newBindingFixture(t)
	svc := f.svc
	userBID := strconv.FormatUint(f.userB.ID, 10)

	for name, ctx := range map[string]context.Context{"tenant caller": callerCtx(boundTenantA), "platform": platformCtx()} {
		t.Run(name, func(t *testing.T) {
			_, err := svc.GetTenantRole(ctx, boundTenantA, f.roleB.ID)
			assert.ErrorIs(t, err, ErrRoleNotFound)
			_, err = svc.UpdateTenantRole(ctx, boundTenantA, &db.UpdateRoleRequest{ID: f.roleB.ID, Permissions: []string{"kv:put"}})
			assert.ErrorIs(t, err, ErrRoleNotFound)
			assert.ErrorIs(t, svc.DeleteTenantRole(ctx, boundTenantA, f.roleB.ID), ErrRoleNotFound)

			_, err = svc.GetTenantUser(ctx, boundTenantA, userBID)
			assert.ErrorIs(t, err, ErrUserNotFound)
			_, err = svc.UpdateTenantUser(ctx, boundTenantA, &db.UpdateUserRequest{ID: f.userB.ID, Name: "pwned"})
			assert.ErrorIs(t, err, ErrUserNotFound)
			assert.ErrorIs(t, svc.DeleteTenantUser(ctx, boundTenantA, userBID), ErrUserNotFound)
		})
	}

	pctx := platformCtx()
	role, err := svc.GetTenantRole(pctx, boundTenantB, f.roleB.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"kv:get"}, role.Permissions)
	user, err := svc.GetTenantUser(pctx, boundTenantB, userBID)
	require.NoError(t, err)
	assert.Equal(t, "User B", user.Name)
}

// TestTenantBinding_MissingRoleAndUserMatchForeign proves a foreign role or
// user reads exactly like one that does not exist.
func TestTenantBinding_MissingRoleAndUserMatchForeign(t *testing.T) {
	f := newBindingFixture(t)
	ctx := callerCtx(boundTenantA)

	_, foreign := f.svc.UpdateTenantRole(ctx, boundTenantA, &db.UpdateRoleRequest{ID: f.roleB.ID})
	_, missing := f.svc.UpdateTenantRole(ctx, boundTenantA, &db.UpdateRoleRequest{ID: "no-such-role"})
	assert.ErrorIs(t, foreign, ErrRoleNotFound)
	assert.ErrorIs(t, missing, ErrRoleNotFound)
	assert.Equal(t, foreign.Error(), missing.Error())

	foreignUser := f.svc.DeleteTenantUser(ctx, boundTenantA, strconv.FormatUint(f.userB.ID, 10))
	missingUser := f.svc.DeleteTenantUser(ctx, boundTenantA, "987654321")
	assert.ErrorIs(t, foreignUser, ErrUserNotFound)
	assert.ErrorIs(t, missingUser, ErrUserNotFound)
	assert.Equal(t, foreignUser.Error(), missingUser.Error())
}

// TestTenantBinding_TenantCallerManagesOwnTenant proves the binding confines
// without disabling: the tenant caller still administers its own tenant.
func TestTenantBinding_TenantCallerManagesOwnTenant(t *testing.T) {
	f := newBindingFixture(t)
	svc := f.svc
	ctx := callerCtx(boundTenantA)
	userAID := strconv.FormatUint(f.userA.ID, 10)

	_, err := svc.GetTenant(ctx, boundTenantA)
	require.NoError(t, err)
	require.NoError(t, svc.UpdateTenantStatus(ctx, boundTenantA, entities.TenantStatusActive))

	role, err := svc.UpdateTenantRole(ctx, boundTenantA, &db.UpdateRoleRequest{ID: f.roleA.ID, Permissions: []string{"kv:put"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"kv:put"}, role.Permissions)
	user, err := svc.UpdateTenantUser(ctx, boundTenantA, &db.UpdateUserRequest{ID: f.userA.ID, Name: "Renamed A"})
	require.NoError(t, err)
	assert.Equal(t, "Renamed A", user.Name)

	created, err := svc.CreateTenantUser(ctx, boundTenantA, &db.CreateUserRequest{Username: "new-a", Email: "new-a@example.com"})
	require.NoError(t, err)
	assert.Equal(t, boundTenantA, created.TenantID)

	require.NoError(t, svc.DeleteTenantRole(ctx, boundTenantA, f.roleA.ID))
	require.NoError(t, svc.DeleteTenantUser(ctx, boundTenantA, userAID))
}

// TestTenantBinding_ListTenantsShowsOnlyOwnTenant proves tenant enumeration is
// confined, with the pagination total counting only what the caller may see.
func TestTenantBinding_ListTenantsShowsOnlyOwnTenant(t *testing.T) {
	f := newBindingFixture(t)

	tenants, page, err := f.svc.ListTenants(callerCtx(boundTenantA), ListTenantsRequest{})
	require.NoError(t, err)
	require.Len(t, tenants, 1)
	assert.Equal(t, boundTenantA, tenants[0].ID)
	assert.Equal(t, 1, page.Total)

	tenants, page, err = f.svc.ListTenants(platformCtx(), ListTenantsRequest{})
	require.NoError(t, err)
	assert.Len(t, tenants, 2)
	assert.Equal(t, 2, page.Total)
}

// TestTenantBinding_CreateTenantIsPlatformOnly proves creating a tenant is a
// platform operation: a tenant-scoped caller, even for an unused ID, is
// refused as lacking the grant.
func TestTenantBinding_CreateTenantIsPlatformOnly(t *testing.T) {
	f := newBindingFixture(t)

	_, err := f.svc.CreateTenant(callerCtx(boundTenantA), CreateTenantRequest{ID: "tenant-c", Name: "C"})
	var scopeErr *PlatformScopeError
	require.ErrorAs(t, err, &scopeErr)
	assert.ErrorIs(t, err, ErrForbidden)
	assert.True(t, IsUnauthorizedError(err))
	_, err = f.svc.GetTenant(platformCtx(), "tenant-c")
	assert.ErrorIs(t, err, ErrTenantNotFound, "the refused tenant must not exist")

	_, err = f.svc.CreateTenant(platformCtx(), CreateTenantRequest{ID: "tenant-c", Name: "C"})
	require.NoError(t, err)
}

// TestTenantBinding_PlatformReachesEveryTenant proves the system identity
// keeps its cross-tenant reach, including the destructive operations.
func TestTenantBinding_PlatformReachesEveryTenant(t *testing.T) {
	f := newBindingFixture(t)
	svc := f.svc
	ctx := platformCtx()

	require.NoError(t, svc.UpdateTenantStatus(ctx, boundTenantB, entities.TenantStatusSuspended))
	user, err := svc.UpdateTenantUser(ctx, boundTenantB, &db.UpdateUserRequest{ID: f.userB.ID, Name: "Renamed B"})
	require.NoError(t, err)
	assert.Equal(t, "Renamed B", user.Name)
	require.NoError(t, svc.DeleteTenantRole(ctx, boundTenantB, f.roleB.ID))
	require.NoError(t, svc.DeleteTenant(ctx, boundTenantB))
	_, err = svc.GetTenant(ctx, boundTenantB)
	assert.ErrorIs(t, err, ErrTenantNotFound)
}

// acmeScopeFixture is an admin service over real ACME storage holding one
// account, order and issued certificate per tenant, plus a tenant-less
// (platform) account.
type acmeScopeFixture struct {
	svc          *AdminService
	certA, certB *entities.ACMECertificate
	serialA      string
	serialB      string
}

const (
	accountA        uint64 = 101
	accountB        uint64 = 202
	accountPlatform uint64 = 303
	orderA          uint64 = 1001
	orderB          uint64 = 2002
)

func newACMEScopeFixture(t *testing.T) *acmeScopeFixture {
	t.Helper()
	svc, ctx, cleanup := setupTestService(t)
	t.Cleanup(cleanup)

	accountDAO, err := svc.storageFactory.AccountDAO()
	require.NoError(t, err)
	for id, tenantID := range map[uint64]string{accountA: boundTenantA, accountB: boundTenantB, accountPlatform: ""} {
		require.NoError(t, accountDAO.Save(ctx, &entities.ACMEAccount{
			ID: id, Status: "valid", TenantID: tenantID, CreatedAt: time.Now(),
		}))
	}

	f := &acmeScopeFixture{svc: svc}
	f.certA = createTestACMECertificate(t, 1, "a.example.com", "valid")
	f.certB = createTestACMECertificate(t, 2, "b.example.com", "valid")
	certDAO, err := svc.storageFactory.CertificateDAO()
	require.NoError(t, err)
	require.NoError(t, certDAO.Save(ctx, f.certA))
	require.NoError(t, certDAO.Save(ctx, f.certB))
	f.serialA = mustSerial(t, f.certA)
	f.serialB = mustSerial(t, f.certB)

	for _, o := range []*entities.ACMEOrder{
		{ID: orderA, AccountID: accountA, Status: "valid", Certificate: f.certA.CertURL},
		{ID: orderB, AccountID: accountB, Status: "valid", Certificate: f.certB.CertURL},
	} {
		orderDAO, err := svc.storageFactory.OrderDAO(o.AccountID)
		require.NoError(t, err)
		require.NoError(t, orderDAO.Save(ctx, o))
	}
	return f
}

func mustSerial(t *testing.T, cert *entities.ACMECertificate) string {
	t.Helper()
	parsed, err := parsePEMCertificate(cert.PEM)
	require.NoError(t, err)
	return parsed.SerialNumber.String()
}

func (f *acmeScopeFixture) certStatus(t *testing.T, id uint64) string {
	t.Helper()
	certDAO, err := f.svc.storageFactory.CertificateDAO()
	require.NoError(t, err)
	cert, err := certDAO.Get(context.Background(), id)
	require.NoError(t, err)
	return cert.Status
}

func (f *acmeScopeFixture) accountStatus(t *testing.T, id uint64) string {
	t.Helper()
	accountDAO, err := f.svc.storageFactory.AccountDAO()
	require.NoError(t, err)
	account, err := accountDAO.Get(context.Background(), id)
	require.NoError(t, err)
	return account.Status
}

// TestTenantScope_TenantCallerCannotRevokeAnotherTenantsCertificate is the
// go-xkms#1225 certificate exploit: tenant-a revoking tenant-b's certificate.
func TestTenantScope_TenantCallerCannotRevokeAnotherTenantsCertificate(t *testing.T) {
	f := newACMEScopeFixture(t)
	ctx := callerCtx(boundTenantA)

	assert.ErrorIs(t, f.svc.RevokeCertificate(ctx, f.serialB, "keyCompromise"), ErrCertificateNotFound)
	assert.Equal(t, "valid", f.certStatus(t, 2), "tenant-b's certificate must not be revoked")

	_, err := f.svc.GetCertificate(ctx, f.serialB)
	assert.ErrorIs(t, err, ErrCertificateNotFound)

	require.NoError(t, f.svc.RevokeCertificate(ctx, f.serialA, "superseded"))
	assert.Equal(t, "revoked", f.certStatus(t, 1))

	require.NoError(t, f.svc.RevokeCertificate(platformCtx(), f.serialB, "superseded"))
	assert.Equal(t, "revoked", f.certStatus(t, 2), "the platform keeps its cross-tenant reach")
}

// TestTenantScope_CertificateListsAreScoped proves the certificate lists and
// the statistics count only the caller's tenant.
func TestTenantScope_CertificateListsAreScoped(t *testing.T) {
	f := newACMEScopeFixture(t)
	ctx := callerCtx(boundTenantA)

	certs, page, err := f.svc.ListCertificates(ctx, ListCertificatesRequest{})
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, f.serialA, certs[0].SerialNumber)
	assert.Equal(t, 1, page.Total)

	expiring, _, err := f.svc.ListExpiringCertificates(ctx, 400, 1, 20)
	require.NoError(t, err)
	require.Len(t, expiring, 1)
	assert.Equal(t, f.serialA, expiring[0].SerialNumber)

	stats, err := f.svc.GetStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, stats.TotalCertificates)
	assert.Equal(t, 1, stats.TotalAccounts)
	assert.Equal(t, 1, stats.TotalOrders)

	all, _, err := f.svc.ListCertificates(platformCtx(), ListCertificatesRequest{})
	require.NoError(t, err)
	assert.Len(t, all, 2)
	stats, err = f.svc.GetStats(platformCtx())
	require.NoError(t, err)
	assert.Equal(t, 3, stats.TotalAccounts)
}

// TestTenantScope_AccountsAreScoped proves account lists, reads and disables
// are confined, and a foreign account reads exactly like a missing one.
func TestTenantScope_AccountsAreScoped(t *testing.T) {
	f := newACMEScopeFixture(t)
	ctx := callerCtx(boundTenantA)

	accounts, page, err := f.svc.ListAccounts(ctx, ListAccountsRequest{})
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	assert.Equal(t, FlexUint64(accountA), accounts[0].ID)
	assert.Equal(t, 1, page.Total)

	_, foreign := f.svc.GetAccount(ctx, accountB)
	_, missing := f.svc.GetAccount(ctx, 999999)
	assert.ErrorIs(t, foreign, ErrAccountNotFound)
	assert.ErrorIs(t, missing, ErrAccountNotFound)
	assert.Equal(t, foreign.Error(), missing.Error())
	_, err = f.svc.GetAccount(ctx, accountPlatform)
	assert.ErrorIs(t, err, ErrAccountNotFound, "a tenant-less account is platform-owned")

	assert.ErrorIs(t, f.svc.DisableAccount(ctx, accountB), ErrAccountNotFound)
	assert.Equal(t, "valid", f.accountStatus(t, accountB), "tenant-b's account must not be disabled")

	require.NoError(t, f.svc.DisableAccount(ctx, accountA))
	assert.Equal(t, "deactivated", f.accountStatus(t, accountA))

	all, _, err := f.svc.ListAccounts(platformCtx(), ListAccountsRequest{})
	require.NoError(t, err)
	assert.Len(t, all, 3)
	require.NoError(t, f.svc.DisableAccount(platformCtx(), accountB))
}

// TestTenantScope_OrdersAreScoped proves order lists and reads are confined.
func TestTenantScope_OrdersAreScoped(t *testing.T) {
	f := newACMEScopeFixture(t)
	ctx := callerCtx(boundTenantA)

	orders, page, err := f.svc.ListOrders(ctx, ListOrdersRequest{})
	require.NoError(t, err)
	require.Len(t, orders, 1)
	assert.Equal(t, orderA, orders[0].ID)
	assert.Equal(t, 1, page.Total)

	foreign, page, err := f.svc.ListOrders(ctx, ListOrdersRequest{AccountID: accountB})
	require.NoError(t, err)
	assert.Empty(t, foreign, "a foreign account's orders read like a missing account's")
	assert.Equal(t, 0, page.Total)

	_, err = f.svc.GetOrder(ctx, orderB, accountB)
	assert.ErrorIs(t, err, ErrOrderNotFound)
	_, err = f.svc.GetOrder(ctx, 999999, accountA)
	assert.ErrorIs(t, err, ErrOrderNotFound)
	got, err := f.svc.GetOrder(ctx, orderA, accountA)
	require.NoError(t, err)
	assert.Equal(t, orderA, got.ID)

	all, _, err := f.svc.ListOrders(platformCtx(), ListOrdersRequest{})
	require.NoError(t, err)
	assert.Len(t, all, 2)
	_, err = f.svc.GetOrder(platformCtx(), orderB, accountB)
	require.NoError(t, err)
}

// staticAuditQuerier answers every query with one event.
type staticAuditQuerier struct{}

func (staticAuditQuerier) Query(context.Context, audit.Query) (*audit.QueryResult, error) {
	return &audit.QueryResult{
		Events: []*audit.AuditEvent{{EventType: audit.EventCertificateIssued, Actor: "account:202", Resource: "certificate:b"}},
		Total:  1, Page: 1, PerPage: 25,
	}, nil
}

// TestTenantScope_AuditTrailIsPlatformOnly proves the audit trail -- which
// carries no tenant attribution to filter by -- is refused to a tenant-scoped
// caller with the same answer the gate gives a caller lacking the grant, and
// served to the platform.
func TestTenantScope_AuditTrailIsPlatformOnly(t *testing.T) {
	svc, _, cleanup := setupTestService(t)
	t.Cleanup(cleanup)
	h := NewHandlers(svc, discardLogger(), WithAuditQuerier(staticAuditQuerier{}))
	router := mux.NewRouter()
	h.RegisterRoutes(router, nil, newPermissiveGate())

	req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(callerCtx(boundTenantA)))
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "account:202")
	assert.Contains(t, rec.Body.String(), "Access denied: insufficient permissions")

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req.WithContext(platformCtx()))
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "account:202")
}

// TestTenantHandlers_ForeignTenantAnswersNotFound proves the HTTP surface
// renders every refusal as the missing-tenant answer, ahead of body parsing.
func TestTenantHandlers_ForeignTenantAnswersNotFound(t *testing.T) {
	f := newBindingFixture(t)
	router := mux.NewRouter()
	NewTenantHandlers(f.svc, discardLogger()).RegisterRoutes(router, nil, newPermissiveGate())
	userBID := strconv.FormatUint(f.userB.ID, 10)

	serve := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, http.NoBody)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req.WithContext(callerCtx(boundTenantA)))
		return rec
	}

	missing := serve(http.MethodGet, "/api/v1/tenants/no-such-tenant")
	require.Equal(t, http.StatusNotFound, missing.Code)

	for _, tc := range []struct{ method, path string }{
		{http.MethodDelete, "/api/v1/tenants/" + boundTenantB},
		{http.MethodPut, "/api/v1/tenants/" + boundTenantB + "/status"},
		{http.MethodPut, "/api/v1/tenants/" + boundTenantB + "/users/" + userBID},
		{http.MethodDelete, "/api/v1/tenants/" + boundTenantB + "/roles/" + f.roleB.ID},
		{http.MethodPost, "/api/v1/tenants/" + boundTenantB + "/eab"},
	} {
		rec := serve(tc.method, tc.path)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s %s", tc.method, tc.path)
		assert.Equal(t, missing.Body.String(), rec.Body.String(), "%s %s", tc.method, tc.path)
	}

	rec := serve(http.MethodDelete, "/api/v1/tenants/"+boundTenantA+"/users/"+userBID)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "User not found")
	rec = serve(http.MethodDelete, "/api/v1/tenants/"+boundTenantA+"/roles/"+f.roleB.ID)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "Role not found")
}

// TestWithUser_BindsQRDBTenant proves the authentication boundary binds the
// caller's tenant as the context's qrdb tenant, so qrdb's own EffectiveTenant
// enforcement confines every identity-plane call the request makes, and that
// a user with no tenant binds the system tenant explicitly.
func TestWithUser_BindsQRDBTenant(t *testing.T) {
	bound, ok := qrdbsdk.TenantFromContext(callerCtx(boundTenantA))
	require.True(t, ok)
	assert.Equal(t, boundTenantA, bound)

	bound, ok = qrdbsdk.TenantFromContext(withUser(context.Background(), &AuthenticatedUser{UserID: "platform"}))
	require.True(t, ok, "an unscoped user must bind the system tenant, not leave the context unbound")
	assert.Equal(t, qrdbsdk.SystemTenantID, bound)
}

// TestBindTenantTarget covers the binding predicate: cross-tenant callers
// (system tenant, no tenant, no identity) reach any tenant; a tenant-scoped
// caller reaches only its own and is refused with the diagnostic fields set.
func TestBindTenantTarget(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"system tenant": platformCtx(),
		"no tenant":     withUser(context.Background(), &AuthenticatedUser{UserID: "u"}),
		"no identity":   context.Background(),
	} {
		assert.NoError(t, admitTenant(ctx, "op", boundTenantB), name)
	}

	ctx := callerCtx(boundTenantA)
	require.NoError(t, admitTenant(ctx, "op", boundTenantA))
	err := admitTenant(ctx, "delete tenant", boundTenantB)
	requireTenantRefusal(t, err, "foreign")
	var bindErr *TenantBindingError
	require.ErrorAs(t, err, &bindErr)
	assert.Equal(t, "delete tenant", bindErr.Op)
	assert.Equal(t, boundTenantA, bindErr.CallerTenantID)
	assert.Equal(t, boundTenantB, bindErr.TargetTenantID)
	requireTenantRefusal(t, admitTenant(ctx, "op", ""), "empty target is the system scope")
}

// TestBindTenantIAM proves an admitted IAM call is scoped to the tenant the
// request addressed, so a platform caller's user or role lookup resolves in
// that tenant rather than its own.
func TestBindTenantIAM(t *testing.T) {
	scoped, err := bindTenantIAM(platformCtx(), "get tenant user", boundTenantB)
	require.NoError(t, err)
	bound, ok := qrdbsdk.TenantFromContext(scoped)
	require.True(t, ok)
	assert.Equal(t, boundTenantB, bound)
}

// TestBindTenantIAM_ForeignTenantRefused proves a tenant-scoped caller is
// refused another tenant's IAM and is handed no scoped context.
func TestBindTenantIAM_ForeignTenantRefused(t *testing.T) {
	scoped, err := bindTenantIAM(callerCtx(boundTenantA), "update tenant user", boundTenantB)
	requireTenantRefusal(t, err, "foreign")
	assert.Nil(t, scoped)
}

// TestPlatformScopeError covers the platform-only refusal's shape: it reads
// exactly as a missing permission, never as a missing resource.
func TestPlatformScopeError(t *testing.T) {
	err := error(&PlatformScopeError{Op: "create tenant", CallerTenantID: boundTenantA})
	assert.ErrorIs(t, err, ErrForbidden)
	assert.Equal(t, ErrForbidden.Error(), err.Error())
	assert.False(t, IsNotFoundError(err))
}

// TestSameTenant proves the empty tenant and the system tenant are one scope,
// and distinct tenants are not.
func TestSameTenant(t *testing.T) {
	assert.True(t, sameTenant("", qrdbsdk.SystemTenantID))
	assert.True(t, sameTenant(boundTenantA, boundTenantA))
	assert.False(t, sameTenant(boundTenantA, boundTenantB))
	assert.False(t, sameTenant("", boundTenantA))
}

// TestIdentityNotFoundClassifiers proves both shapes qrdb returns for a
// missing role -- the embedded role service's and the wire transports' -- and
// the one user shape are recognized, and nothing else is.
func TestIdentityNotFoundClassifiers(t *testing.T) {
	assert.True(t, isRoleNotFound(&qrdbsdk.RoleNotFoundError{ID: "r"}))
	assert.True(t, isRoleNotFound(&db.RoleNotFoundError{ID: "r"}))
	assert.False(t, isRoleNotFound(ErrRoleNotFound))
	assert.False(t, isRoleNotFound(&db.UserNotFoundError{ID: 1}))

	assert.True(t, isUserNotFound(&db.UserNotFoundError{ID: 1}))
	assert.False(t, isUserNotFound(ErrUserNotFound))
	assert.False(t, isUserNotFound(&db.RoleNotFoundError{ID: "r"}))
}

// failingRoleClient answers every role lookup with an internal fault.
type failingRoleClient struct {
	db.RoleClient
}

func (failingRoleClient) GetRole(context.Context, string) (*db.Role, error) {
	return nil, errFailingQRDB
}

// failingUserClient answers every user lookup with an internal fault.
type failingUserClient struct {
	db.UserClient
}

func (failingUserClient) GetUser(context.Context, uint64) (*db.User, error) {
	return nil, errFailingQRDB
}

var errFailingQRDB = &db.ConnectionError{Address: "qrdb.example.com", Err: context.DeadlineExceeded}

// failingIdentityQRDB is a qrdb client whose role and user lookups fail.
type failingIdentityQRDB struct {
	QRDBClient
}

func (failingIdentityQRDB) Roles() db.RoleClient { return failingRoleClient{} }
func (failingIdentityQRDB) Users() db.UserClient { return failingUserClient{} }

// TestTenantBinding_OwnershipLookupFailureIsNotNotFound proves an ownership
// lookup that fails for any reason other than a miss is surfaced as the
// failure, never masked as not-found and never followed by the mutation.
func TestTenantBinding_OwnershipLookupFailureIsNotNotFound(t *testing.T) {
	svc := mustTenantAwareAdminService(t, nil, nil, failingIdentityQRDB{QRDBClient: newTestQRDB(t)}, discardLogger(), "test")
	ctx := platformCtx()

	_, err := svc.UpdateTenantRole(ctx, boundTenantA, &db.UpdateRoleRequest{ID: "r"})
	assert.ErrorIs(t, err, errFailingQRDB)
	assert.False(t, IsNotFoundError(err))
	assert.ErrorIs(t, svc.DeleteTenantUser(ctx, boundTenantA, "7"), errFailingQRDB)

	rec := httptest.NewRecorder()
	writeIdentityError(rec, err, "Failed to update role")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// TestWriteIdentityError_PermissionDenied proves an operation qrdb's
// authorizer refuses is answered as permission-denied rather than as an
// internal failure or a miss.
func TestWriteIdentityError_PermissionDenied(t *testing.T) {
	denied := &qrdbsdk.PermissionDeniedError{Resource: "users", Action: "update", Reason: "self-scope permission: identity not in target tenant"}

	rec := httptest.NewRecorder()
	writeIdentityError(rec, denied, "Failed to update user")
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	rec = httptest.NewRecorder()
	writeIdentityError(rec, ErrUserNotFound, "Failed to update user")
	assert.Equal(t, http.StatusNotFound, rec.Code, "a miss is still not-found")
}

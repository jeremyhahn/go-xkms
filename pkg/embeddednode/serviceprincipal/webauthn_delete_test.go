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

package serviceprincipal

import (
	"context"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// webAuthnAccount is a WebAuthn account seeded on a real node: its qrdb
// user, one passkey and the enrolment credential marker its public
// enrolment won.
type webAuthnAccount struct {
	svc       *webauthn.Service
	creds     webauthn.CredentialStore
	handle    []byte
	userID    uint64
	markerKey string
}

// newWebAuthnAccount builds the relying party's stores as the server does,
// bound to the service principal, and seeds one account through them.
func newWebAuthnAccount(t *testing.T, node *qrdbnode.Node) webAuthnAccount {
	t.Helper()
	return newWebAuthnAccountOver(t, node, node.Client().KV())
}

// newWebAuthnAccountOver is newWebAuthnAccount with the store's
// bookkeeping on storeKV.
func newWebAuthnAccountOver(t *testing.T, node *qrdbnode.Node, storeKV qrdbtransport.KVClient) webAuthnAccount {
	t.Helper()
	kv := qrdbsdk.NewMemoryKVStore()
	users, creds, err := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
		Users:       node.Client().Users(),
		DAOFactory:  qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return kv }),
		TenantID:    qrdbsdk.SystemTenantID,
		KV:          storeKV,
		CallContext: node.ServiceContext,
	})
	require.NoError(t, err)
	svc, err := webauthn.NewService(webauthn.ServiceParams{
		Config: &webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "xkms test",
			RPOrigins:     []string{"https://localhost:18444"},
		},
		UserStore:       users,
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: creds,
	})
	require.NoError(t, err)

	user, err := users.Create(context.Background(), "alice@example.com", "Alice")
	require.NoError(t, err)
	handle := user.WebAuthnID()
	require.NoError(t, creds.Save(context.Background(), &webauthn.Credential{
		ID:        []byte("alice-passkey"),
		UserID:    handle,
		PublicKey: []byte("cose-public-key"),
	}))
	userID, err := webauthn.UserIDFromHandle(handle)
	require.NoError(t, err)

	// The marker key is the store's enrolment credential marker key
	// (webauthn enrolmentCredentialPrefix + tenant + "/" + qrdb user ID).
	markerKey := "webauthn/enrolment-credential/" + qrdbsdk.SystemTenantID + "/" + strconv.FormatUint(userID, 10)
	svcCtx, err := node.ServiceContext(context.Background())
	require.NoError(t, err)
	require.NoError(t, node.Client().KV().Put(svcCtx, markerKey, []byte("consumed")))

	return webAuthnAccount{svc: svc, creds: creds, handle: handle, userID: userID, markerKey: markerKey}
}

// adminContext is a system-tenant administrator's call context, the
// identity the node's mTLS front door binds for an administrator's
// certificate. Its role holds exactly what deleting an account needs:
// the user delete and read, and the marker's KV delete.
func adminContext(t *testing.T, node *qrdbnode.Node) context.Context {
	t.Helper()
	return tenantAdminContext(t, node, qrdbsdk.SystemTenantID)
}

// tenantAdminContext is adminContext for an administrator of tenant.
func tenantAdminContext(t *testing.T, node *qrdbnode.Node, tenant string) context.Context {
	t.Helper()
	ctx := qrdbsdk.ContextWithTenant(context.Background(), tenant)
	role, err := node.Services().Role.CreateRole(ctx, &qrdbsdk.CreateRoleRequest{
		Name:        "webauthn-account-admin",
		TenantID:    tenant,
		Permissions: []qrdbsdk.Permission{"users:delete", "users:read", "kv:delete"},
	})
	require.NoError(t, err)
	admin := &qrdbsdk.Identity{Subject: "admin", TenantID: tenant, Roles: []string{role.ID}}
	return qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(context.Background(), admin), tenant)
}

// TestWebAuthnDeleteUser_AdministratorDeletesAccount proves an
// administrator's delete reaches qrdb on the administrator's own context:
// the service principal's grant (no users:delete) never stands in for it.
// The account, its passkey and its enrolment credential marker all go.
func TestWebAuthnDeleteUser_AdministratorDeletesAccount(t *testing.T) {
	node := newNode(t, Option())
	account := newWebAuthnAccount(t, node)
	ctx := adminContext(t, node)

	require.NoError(t, account.svc.DeleteUser(ctx, account.handle))

	_, err := node.Client().Users().GetUser(ctx, account.userID)
	require.Error(t, err, "the deleted account must not be readable")
	remaining, err := account.creds.GetByUserID(context.Background(), account.handle)
	require.NoError(t, err)
	require.Empty(t, remaining, "the account's passkeys must be deleted")
	svcCtx, err := node.ServiceContext(context.Background())
	require.NoError(t, err)
	marked, err := node.Client().KV().Exists(svcCtx, account.markerKey)
	require.NoError(t, err)
	require.False(t, marked, "the account's enrolment credential marker must be deleted")
}

// TestWebAuthnDeleteUser_ServicePrincipalIsRefused proves the service
// principal cannot delete an account, and that the refused delete leaves
// the account and its passkeys intact: the account is deleted before its
// credentials, so a refusal touches nothing.
func TestWebAuthnDeleteUser_ServicePrincipalIsRefused(t *testing.T) {
	node := newNode(t, Option())
	account := newWebAuthnAccount(t, node)
	ctx, err := node.ServiceContext(context.Background())
	require.NoError(t, err)

	err = account.svc.DeleteUser(ctx, account.handle)
	var denied *qrdbsdk.PermissionDeniedError
	require.ErrorAs(t, err, &denied)

	_, err = node.Client().Users().GetUser(ctx, account.userID)
	require.NoError(t, err, "a refused delete must leave the account readable")
	remaining, err := account.creds.GetByUserID(context.Background(), account.handle)
	require.NoError(t, err)
	require.Len(t, remaining, 1, "a refused delete must leave the account's passkeys")
}

// TestWebAuthnDeleteUser_OtherTenantAdministratorIsRefused proves an
// administrator of another tenant, to whom the account is invisible, removes
// nothing: the account, its passkey and its marker all survive.
func TestWebAuthnDeleteUser_OtherTenantAdministratorIsRefused(t *testing.T) {
	node := newNode(t, Option())
	account := newWebAuthnAccount(t, node)
	_, err := node.Services().Tenant.CreateTenant(context.Background(), "tenant-b", "Tenant B",
		qrdbsdk.TenantIsolationPrefix)
	require.NoError(t, err)
	ctx := tenantAdminContext(t, node, "tenant-b")

	err = account.svc.DeleteUser(ctx, account.handle)
	require.ErrorIs(t, err, webauthn.ErrUserNotFound)

	svcCtx, err := node.ServiceContext(context.Background())
	require.NoError(t, err)
	_, err = node.Client().Users().GetUser(svcCtx, account.userID)
	require.NoError(t, err, "the account must survive another tenant's delete")
	remaining, err := account.creds.GetByUserID(context.Background(), account.handle)
	require.NoError(t, err)
	require.Len(t, remaining, 1, "the account's passkey must survive another tenant's delete")
	marked, err := node.Client().KV().Exists(svcCtx, account.markerKey)
	require.NoError(t, err)
	require.True(t, marked, "the account's marker must survive another tenant's delete")
}

// markerDeleteFaultError is the fault failingMarkerDeleteKV injects.
type markerDeleteFaultError struct{}

func (markerDeleteFaultError) Error() string { return "test: marker delete fault" }

// failingMarkerDeleteKV fails the first Delete of an enrolment credential
// marker and passes every other call to the node's KV client.
type failingMarkerDeleteKV struct {
	qrdbtransport.GuardedKVClient
	failed atomic.Bool
}

func (k *failingMarkerDeleteKV) Delete(ctx context.Context, key string, opts ...qrdbtransport.WriteOption) error {
	if strings.HasPrefix(key, "webauthn/enrolment-credential/") && k.failed.CompareAndSwap(false, true) {
		return markerDeleteFaultError{}
	}
	return k.GuardedKVClient.Delete(ctx, key, opts...)
}

// TestWebAuthnDeleteUser_MarkerDeleteFailureRetries proves a delete whose
// marker removal fails is finished by a retry under the same administrator
// grant (users:delete, users:read, kv:delete).
func TestWebAuthnDeleteUser_MarkerDeleteFailureRetries(t *testing.T) {
	node := newNode(t, Option())
	guarded, ok := node.Client().KV().(qrdbtransport.GuardedKVClient)
	require.True(t, ok, "the node's KV client must be guarded")
	account := newWebAuthnAccountOver(t, node, &failingMarkerDeleteKV{GuardedKVClient: guarded})
	ctx := adminContext(t, node)

	require.ErrorAs(t, account.svc.DeleteUser(ctx, account.handle), &markerDeleteFaultError{})
	require.NoError(t, account.svc.DeleteUser(ctx, account.handle), "the retry must finish the delete")

	svcCtx, err := node.ServiceContext(context.Background())
	require.NoError(t, err)
	_, err = node.Client().Users().GetUser(svcCtx, account.userID)
	require.Error(t, err, "the deleted account must not be readable")
	remaining, err := account.creds.GetByUserID(context.Background(), account.handle)
	require.NoError(t, err)
	require.Empty(t, remaining, "the account's passkeys must be deleted")
	marked, err := node.Client().KV().Exists(svcCtx, account.markerKey)
	require.NoError(t, err)
	require.False(t, marked, "the account's enrolment credential marker must be deleted")
}

func TestWebAuthnDeleteUser_OtherTenantCannotFinishInterruptedDelete(t *testing.T) {
	node := newNode(t, Option())
	guarded, ok := node.Client().KV().(qrdbtransport.GuardedKVClient)
	require.True(t, ok, "the node's KV client must be guarded")
	account := newWebAuthnAccountOver(t, node, &failingMarkerDeleteKV{GuardedKVClient: guarded})
	_, err := node.Services().Tenant.CreateTenant(context.Background(), "tenant-b", "Tenant B",
		qrdbsdk.TenantIsolationPrefix)
	require.NoError(t, err)
	ctx := adminContext(t, node)
	otherCtx := tenantAdminContext(t, node, "tenant-b")
	// The deletion record key is the store's account deletion record key
	// (webauthn enrolmentDeletionPrefix + tenant + "/" + qrdb user ID).
	recordKey := "webauthn/account-deletion/" + qrdbsdk.SystemTenantID + "/" + strconv.FormatUint(account.userID, 10)
	svcCtx, err := node.ServiceContext(context.Background())
	require.NoError(t, err)

	require.ErrorAs(t, account.svc.DeleteUser(ctx, account.handle), &markerDeleteFaultError{})
	require.Error(t, account.svc.DeleteUser(otherCtx, account.handle),
		"another tenant's administrator must not finish this tenant's delete")
	marked, err := node.Client().KV().Exists(svcCtx, account.markerKey)
	require.NoError(t, err)
	require.True(t, marked, "the marker must survive another tenant's delete")
	recorded, err := node.Client().KV().Exists(svcCtx, recordKey)
	require.NoError(t, err)
	require.True(t, recorded, "the deletion record must survive another tenant's delete")

	require.NoError(t, account.svc.DeleteUser(ctx, account.handle), "the retry must finish the delete")
	marked, err = node.Client().KV().Exists(svcCtx, account.markerKey)
	require.NoError(t, err)
	require.False(t, marked, "the retry must delete the marker")
	recorded, err = node.Client().KV().Exists(svcCtx, recordKey)
	require.NoError(t, err)
	require.False(t, recorded, "the retry must drop the deletion record")
}

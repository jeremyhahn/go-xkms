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
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
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
	kv := qrdbsdk.NewMemoryKVStore()
	users, creds, err := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
		Users:       node.Client().Users(),
		DAOFactory:  qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return kv }),
		TenantID:    qrdbsdk.SystemTenantID,
		KV:          node.Client().KV(),
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
	ctx := qrdbsdk.ContextWithTenant(context.Background(), qrdbsdk.SystemTenantID)
	role, err := node.Services().Role.CreateRole(ctx, &qrdbsdk.CreateRoleRequest{
		Name:        "webauthn-account-admin",
		TenantID:    qrdbsdk.SystemTenantID,
		Permissions: []qrdbsdk.Permission{"users:delete", "users:read", "kv:delete"},
	})
	require.NoError(t, err)
	admin := &qrdbsdk.Identity{Subject: "admin", TenantID: qrdbsdk.SystemTenantID, Roles: []string{role.ID}}
	return qrdbsdk.ContextWithTenant(qrdbsdk.WithIdentity(context.Background(), admin), qrdbsdk.SystemTenantID)
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

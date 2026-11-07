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
	"encoding/base64"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// beginAddCredential runs the legacy credentials/begin path: the session
// account is derived from the caller's identity, then the ceremony begins.
func beginAddCredential(account webAuthnAccount, id *auth.Identity) (string, error) {
	acct, err := webauthn.SessionAccountFromIdentity(id)
	if err != nil {
		return "", err
	}
	_, sessionID, err := account.svc.BeginAddCredential(context.Background(), acct)
	return sessionID, err
}

// TestWebAuthnBeginAddCredential_CertificateLoginCannotTakeOver is Codex 9037:
// a certificate-login account in tenant B whose username is the base64url of
// a tenant-A victim's handle, and whose email is the victim's, must not begin
// a passkey enrolment on the victim's account through the service-context
// lookup.
func TestWebAuthnBeginAddCredential_CertificateLoginCannotTakeOver(t *testing.T) {
	node := newNode(t, Option())
	victim := newWebAuthnAccount(t, node)
	colliding := base64.RawURLEncoding.EncodeToString(victim.handle)

	attackers := map[string]*auth.Identity{
		"username subject": {
			Subject:  colliding,
			TenantID: "tenant-b",
			Metadata: map[string]string{
				"email":                     "alice@example.com",
				auth.SubjectKindMetadataKey: auth.SubjectKindUsername,
			},
		},
		"handle subject in another tenant": {
			Subject:  colliding,
			TenantID: "tenant-b",
			Metadata: map[string]string{
				"email":                     "alice@example.com",
				auth.SubjectKindMetadataKey: auth.SubjectKindUserHandle,
			},
		},
	}
	for name, id := range attackers {
		sessionID, err := beginAddCredential(victim, id)
		require.ErrorIs(t, err, webauthn.ErrSessionAccountMismatch, name)
		require.Empty(t, sessionID, name)
	}

	remaining, err := victim.creds.GetByUserID(context.Background(), victim.handle)
	require.NoError(t, err)
	require.Len(t, remaining, 1, "a refused begin must leave the victim's passkeys")
}

// TestWebAuthnBeginAddCredential_SameTenantHandleSessionBegins proves the
// victim's own WebAuthn session, in the store's tenant, still begins.
func TestWebAuthnBeginAddCredential_SameTenantHandleSessionBegins(t *testing.T) {
	node := newNode(t, Option())
	account := newWebAuthnAccount(t, node)

	sessionID, err := beginAddCredential(account, &auth.Identity{
		Subject:  base64.RawURLEncoding.EncodeToString(account.handle),
		TenantID: qrdbsdk.SystemTenantID,
		Metadata: map[string]string{
			"email":                     "alice@example.com",
			auth.SubjectKindMetadataKey: auth.SubjectKindUserHandle,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)
}

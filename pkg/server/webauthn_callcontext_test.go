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

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// TestWebAuthnBegin_RegisteredUserListsCredentialInExcludeCredentials pins
// main run 74687 cause 1: a signed-in user adding a passkey
// (credentials/begin) carries a session identity with no grant over user
// records, so the relying party must look the account up as the node's
// service principal. With the session's identity kept, qrdb refused the
// lookup and the begin failed before excludeCredentials was built.
func TestWebAuthnBegin_RegisteredUserListsCredentialInExcludeCredentials(t *testing.T) {
	node := newPrincipalTestNode(t)
	ds, err := datastore.New(node.Client(), config.DatastoreConfig{Engine: "memory"},
		datastore.WithCallContext(node.ServiceContext))
	require.NoError(t, err)

	s := newMinimalServer(t, &config.Config{})
	s.qrdbNode = node
	s.datastore.Store(ds)
	s.webauthnConfig = &webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "xkms test",
		RPOrigins:     []string{"https://localhost:18444"},
	}
	require.NoError(t, s.initializeWebAuthnService())

	// Seed the registered account and its passkey as the server itself
	// stores them, through the relying party's own records.
	users, creds, err := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
		Users:       node.Client().Users(),
		DAOFactory:  ds.DAOFactory(),
		TenantID:    webAuthnSystemTenant,
		CallContext: node.ServiceContext,
	})
	require.NoError(t, err)
	const email = "alice@example.com"
	user, err := users.Create(context.Background(), email, "Alice")
	require.NoError(t, err)
	credentialID := []byte("alice-first-passkey")
	require.NoError(t, creds.Save(context.Background(), &webauthn.Credential{
		ID:        credentialID,
		UserID:    user.WebAuthnID(),
		PublicKey: []byte("cose-public-key"),
	}))

	session := &auth.Identity{Subject: base64.RawURLEncoding.EncodeToString(user.WebAuthnID())}
	ctx := auth.WithIdentity(context.Background(), session)
	options, sessionID, err := s.webauthnService.BeginAddCredential(ctx, webauthn.SessionAccount{
		UserID: user.WebAuthnID(),
		Email:  email,
	})
	require.NoError(t, err, "a session without a users grant must still begin its own added passkey")
	require.NotEmpty(t, sessionID)

	excluded := false
	for _, descriptor := range options.Response.CredentialExcludeList {
		if bytes.Equal(descriptor.CredentialID, credentialID) {
			excluded = true
		}
	}
	require.True(t, excluded, "the account's registered passkey must be in excludeCredentials")
}

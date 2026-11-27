// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package apimodule

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// TestModuleHost_NodeUsers_WebAuthnFinishOverAuthNode is the open
// user-store question of row 2310 (ruling 1038 (3)): a registration finish,
// on a node that enforces authentication and with a request context that
// carries no identity, looks the user up by ID and updates it. Those calls
// must reach the user store through the node user service (WithNodeUsers),
// the route begin already takes, and the ceremony must answer 200 instead of
// internal_error.
//
// The SDK begin answers 200 over such a node, as the service principal holds the users grant.
func TestModuleHost_NodeUsers_WebAuthnFinishOverAuthNode(t *testing.T) {
	m, _, h := nodeHostedModule(t)

	w := serveJSON(t, h, http.MethodPost, "/api/v1/webauthn/sdk/registration/begin", transport.BeginRegistrationRequest{
		Email:       "anonymous-user@example.com",
		DisplayName: "Anonymous User",
	})
	require.Equal(t, http.StatusOK, w.Code, "anonymous sdk registration/begin: %s", w.Body.String())

	// The first request builds the host (and composes its stores).
	w = serveJSON(t, h, http.MethodGet, "/api/v1/invites/"+qrdbsdk.SystemTenantID+"/not-a-token", nil)
	require.NotEqual(t, http.StatusInternalServerError, w.Code, w.Body.String())
	stores := m.HostStores()
	require.NotNil(t, stores, "the module host composes its stores on first use")
	require.NotNil(t, stores.Invite, "invite store: %v", stores.Disabled)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	users := auth.NewNodeUserClient(m.nodeUsers)
	user, err := users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: "finish-user",
		Email:    "finish-user@example.com",
		Name:     "Finish User",
		Pending:  true,
	})
	require.NoError(t, err)
	token, _, err := stores.Invite.Create(ctx, strconv.FormatUint(user.ID, 10), qrdbsdk.SystemTenantID, time.Hour)
	require.NoError(t, err)
	invite := "/api/v1/invites/" + qrdbsdk.SystemTenantID + "/" + token

	w = serveJSON(t, h, http.MethodPost, invite+"/fido2/begin", nil)
	require.Equal(t, http.StatusOK, w.Code, "invite fido2/begin: %s", w.Body.String())
	var begin transport.BeginInviteRegistrationResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &begin))
	require.NotEmpty(t, begin.SessionID)
	var options protocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(begin.OptionsJSON), &options))
	encodedUserID, ok := options.Response.User.ID.(string)
	require.True(t, ok, "the ceremony options must carry a base64url user handle, got %T", options.Response.User.ID)
	userHandle, err := base64.RawURLEncoding.DecodeString(encodedUserID)
	require.NoError(t, err)

	authenticator, err := webauthn.NewMockAuthenticator("example.com")
	require.NoError(t, err)
	attestation, err := authenticator.CreateAttestationObject(options.Response.Challenge, userHandle, "https://example.com")
	require.NoError(t, err)
	attestationJSON, err := json.Marshal(attestation.Raw)
	require.NoError(t, err)

	w = serveJSON(t, h, http.MethodPost, invite+"/fido2/finish", map[string]string{
		"session_id":       begin.SessionID,
		"attestation_json": string(attestationJSON),
	})
	require.Equal(t, http.StatusOK, w.Code, "invite fido2/finish: %s", w.Body.String())

	// The finish wrote the user through the node user service: the invited
	// account is now active.
	got, err := users.GetUser(ctx, qrdbsdk.SystemTenantID, user.ID)
	require.NoError(t, err)
	require.Equal(t, string(qrdbsdk.LifecycleActive), got.Lifecycle)
}

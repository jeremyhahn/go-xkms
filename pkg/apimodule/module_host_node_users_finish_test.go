// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package apimodule

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestModuleHost_NodeUsers_WebAuthnFinishOverAuthNode is the open
// user-store question of row 2310 (ruling 1038 (3)): public registration
// finish, on a node that enforces authentication and with a request
// context that carries no identity, looks the user up by ID and updates its
// display name. Both calls must reach the user store through the node user
// service (WithNodeUsers), the route begin already takes, and the ceremony
// must answer 200 instead of internal_error.
func TestModuleHost_NodeUsers_WebAuthnFinishOverAuthNode(t *testing.T) {
	_, _, h := nodeHostedModule(t)

	serve := func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }
	routes := map[string]http.HandlerFunc{
		"POST /api/v1/webauthn/sdk/registration/begin":  serve,
		"POST /api/v1/webauthn/sdk/registration/finish": serve,
	}
	credentialID := registerThroughSDKLane(t, routes, "finish-user@example.com")
	require.NotEmpty(t, credentialID, "registration finish must return the new credential")

	// A second begin for the same account now sees an active user with a
	// credential: the finish wrote the user through the node user service.
	w := serveJSON(t, h, http.MethodPost, "/api/v1/webauthn/registration/begin", map[string]string{
		"email":        "finish-user@example.com",
		"display_name": "Finish User",
	})
	require.NotEqual(t, http.StatusInternalServerError, w.Code, "begin after finish: %s", w.Body.String())
}

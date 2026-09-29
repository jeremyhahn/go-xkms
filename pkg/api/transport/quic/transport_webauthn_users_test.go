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

package quic

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRecordingTransport starts an httptest.TLSServer whose handler records the
// exact method, path, and body of the single request it expects, then writes
// the caller-supplied response. It proves the QUIC transport's WebAuthn/User
// methods dial the same route, verb, and JSON body the REST transport does,
// mirroring the exact-path/verb/body assertions in
// transport_leader_redirect_test.go.
func newRecordingTransport(t *testing.T, wantMethod, wantPath string, respond func(w http.ResponseWriter)) (*Transport, func()) {
	t.Helper()

	var gotMethod, gotPath string
	var gotBody []byte

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.EscapedPath()
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody = body
		respond(w)
	}))

	t.Cleanup(func() {
		assert.Equal(t, wantMethod, gotMethod, "unexpected HTTP method")
		assert.Equal(t, wantPath, gotPath, "unexpected path")
		if len(gotBody) > 0 {
			assert.True(t, json.Valid(gotBody), "request body must be valid JSON")
		}
	})

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	return tr, srv.Close
}

func writeJSONResponse(t *testing.T, w http.ResponseWriter, status int, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	require.NoError(t, json.NewEncoder(w).Encode(v))
}

// --- WebAuthn: BeginRegistration ---

func TestBeginRegistration_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodPost, "/api/v1/webauthn/sdk/registration/begin", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, transport.BeginRegistrationResponse{
			SessionID:   "sess-1",
			OptionsJSON: `{"publicKey":{}}`,
		})
	})
	defer cleanup()

	resp, err := tr.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{
		Email:       "alice",
		DisplayName: "Alice",
	})
	require.NoError(t, err)
	assert.Equal(t, "sess-1", resp.SessionID)
	assert.Equal(t, `{"publicKey":{}}`, resp.OptionsJSON)
}

func TestBeginRegistration_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	_, err := tr.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{Email: "alice"})
	require.Error(t, err)
}

// --- WebAuthn: FinishRegistration ---

func TestFinishRegistration_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodPost, "/api/v1/webauthn/sdk/registration/finish", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, transport.FinishRegistrationResponse{
			Success:      true,
			CredentialID: "cred-1",
			Token:        "tok-1",
		})
	})
	defer cleanup()

	resp, err := tr.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{
		SessionID:       "sess-1",
		AttestationJSON: `{"id":"cred-1"}`,
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "cred-1", resp.CredentialID)
	assert.Equal(t, "tok-1", resp.Token)
}

func TestFinishRegistration_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	_, err := tr.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{SessionID: "sess-1"})
	require.Error(t, err)
}

// --- WebAuthn: BeginAuthentication ---

func TestBeginAuthentication_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodPost, "/api/v1/webauthn/sdk/authentication/begin", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, transport.BeginAuthenticationResponse{
			SessionID:   "sess-2",
			OptionsJSON: `{"publicKey":{"challenge":"c"}}`,
		})
	})
	defer cleanup()

	resp, err := tr.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{Email: "alice"})
	require.NoError(t, err)
	assert.Equal(t, "sess-2", resp.SessionID)
	assert.Equal(t, `{"publicKey":{"challenge":"c"}}`, resp.OptionsJSON)
}

func TestBeginAuthentication_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	_, err := tr.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{Email: "alice"})
	require.Error(t, err)
}

// --- WebAuthn: FinishAuthentication ---

func TestFinishAuthentication_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodPost, "/api/v1/webauthn/sdk/authentication/finish", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, transport.FinishAuthenticationResponse{
			Success:  true,
			Token:    "tok-2",
			Username: "alice",
		})
	})
	defer cleanup()

	resp, err := tr.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{
		SessionID:     "sess-2",
		Email:         "alice",
		AssertionJSON: `{"id":"cred-1"}`,
	})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, "tok-2", resp.Token)
	assert.Equal(t, "alice", resp.Username)
}

func TestFinishAuthentication_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	_, err := tr.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{SessionID: "sess-2"})
	require.Error(t, err)
}

// --- Users: CreateUser ---

func TestCreateUser_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodPost, "/api/v1/users/", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, transport.GetUserResponse{
			User: transport.UserInfo{
				ID:       1,
				Username: "bob",
				Role:     "admin",
				Enabled:  true,
			},
		})
	})
	defer cleanup()

	resp, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username:    "bob",
		DisplayName: "Bob",
		Role:        "admin",
		TenantID:    "t1",
	})
	require.NoError(t, err)
	assert.Equal(t, "bob", resp.User.Username)
	assert.Equal(t, "admin", resp.User.Role)
	assert.True(t, resp.User.Enabled)
}

func TestCreateUser_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	_, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "bob"})
	require.Error(t, err)
}

// --- Users: ListUsers ---

func TestListUsers_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodGet, "/api/v1/users/", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, transport.ListUsersResponse{
			Users: []transport.UserInfo{{ID: 1, Username: "bob"}, {ID: 2, Username: "carol"}},
		})
	})
	defer cleanup()

	resp, err := tr.ListUsers(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Users, 2)
	assert.Equal(t, "bob", resp.Users[0].Username)
	assert.Equal(t, "carol", resp.Users[1].Username)
}

func TestListUsers_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	_, err := tr.ListUsers(context.Background())
	require.Error(t, err)
}

// --- Users: GetUser ---

func TestGetUser_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodGet, "/api/v1/users/bob", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, transport.UserInfo{ID: 1, Username: "bob", Enabled: true})
	})
	defer cleanup()

	resp, err := tr.GetUser(context.Background(), "bob")
	require.NoError(t, err)
	assert.Equal(t, "bob", resp.User.Username)
	assert.True(t, resp.User.Enabled)
}

func TestGetUser_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	_, err := tr.GetUser(context.Background(), "bob")
	require.Error(t, err)
}

func TestGetUser_PathEscapesUsername(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodGet, "/api/v1/users/bob%2Fsmith", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, transport.UserInfo{Username: "bob/smith"})
	})
	defer cleanup()

	resp, err := tr.GetUser(context.Background(), "bob/smith")
	require.NoError(t, err)
	assert.Equal(t, "bob/smith", resp.User.Username)
}

// --- Users: DeleteUser ---

func TestDeleteUser_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodDelete, "/api/v1/users/bob", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, map[string]bool{"success": true})
	})
	defer cleanup()

	err := tr.DeleteUser(context.Background(), "bob")
	require.NoError(t, err)
}

func TestDeleteUser_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	err := tr.DeleteUser(context.Background(), "bob")
	require.Error(t, err)
}

// --- Users: EnableUser / DisableUser ---

func TestEnableUser_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodPut, "/api/v1/users/bob", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, map[string]bool{"success": true})
	})
	defer cleanup()

	err := tr.EnableUser(context.Background(), "bob")
	require.NoError(t, err)
}

func TestEnableUser_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	err := tr.EnableUser(context.Background(), "bob")
	require.Error(t, err)
}

func TestDisableUser_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodPut, "/api/v1/users/bob", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, map[string]bool{"success": true})
	})
	defer cleanup()

	err := tr.DisableUser(context.Background(), "bob")
	require.NoError(t, err)
}

func TestDisableUser_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	err := tr.DisableUser(context.Background(), "bob")
	require.Error(t, err)
}

// TestSetUserEnabled_RequestBody proves EnableUser/DisableUser send the
// {"enabled": <bool>} body the REST transport sends, not just hit the route.
func TestSetUserEnabled_RequestBody(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody = body
		writeJSONResponse(t, w, http.StatusOK, map[string]bool{"success": true})
	}))
	defer srv.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	require.NoError(t, tr.EnableUser(context.Background(), "bob"))
	var enabled map[string]bool
	require.NoError(t, json.Unmarshal(gotBody, &enabled))
	assert.True(t, enabled["enabled"])

	require.NoError(t, tr.DisableUser(context.Background(), "bob"))
	require.NoError(t, json.Unmarshal(gotBody, &enabled))
	assert.False(t, enabled["enabled"])
}

// --- Users: BindUserCert ---

func TestBindUserCert_Success(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/users/bob/cert-bindings", r.URL.Path)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody = body
		writeJSONResponse(t, w, http.StatusOK, map[string]bool{"success": true})
	}))
	defer srv.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	err := tr.BindUserCert(context.Background(), "bob", "abc123thumbprint", 1700000000)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(gotBody, &got))
	assert.Equal(t, "abc123thumbprint", got["thumbprint"])
	assert.EqualValues(t, 1700000000, got["not_after_unix"])
}

func TestBindUserCert_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	err := tr.BindUserCert(context.Background(), "bob", "thumb", 1)
	require.Error(t, err)
}

// --- Users: ListUserCredentials ---

func TestListUserCredentials_Success(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodGet, "/api/v1/users/bob/credentials", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{
				{"id": "cred-1", "name": "YubiKey"},
				{"id": "cred-2", "name": "TouchID"},
			},
		})
	})
	defer cleanup()

	resp, err := tr.ListUserCredentials(context.Background(), "bob")
	require.NoError(t, err)
	require.Len(t, resp.Credentials, 2)
	assert.Equal(t, "cred-1", resp.Credentials[0].ID)
	assert.Equal(t, "YubiKey", resp.Credentials[0].DisplayName)
	assert.Equal(t, "cred-2", resp.Credentials[1].ID)
	assert.Equal(t, "TouchID", resp.Credentials[1].DisplayName)
}

func TestListUserCredentials_Empty(t *testing.T) {
	tr, cleanup := newRecordingTransport(t, http.MethodGet, "/api/v1/users/bob/credentials", func(w http.ResponseWriter) {
		writeJSONResponse(t, w, http.StatusOK, map[string]interface{}{"credentials": []map[string]string{}})
	})
	defer cleanup()

	resp, err := tr.ListUserCredentials(context.Background(), "bob")
	require.NoError(t, err)
	assert.Empty(t, resp.Credentials)
}

func TestListUserCredentials_ServerErr(t *testing.T) {
	tr, cleanup := newErrTransport(t)
	defer cleanup()

	_, err := tr.ListUserCredentials(context.Background(), "bob")
	require.Error(t, err)
}

// The no-email exemption must survive serialization over QUIC too.
//
// CreateUser built its body as map[string]string, which cannot carry a bool, so
// WithoutEmailLoginKey never left the client and the certificate-authenticated
// admin was rejected server-side as a missing login key (Codex, go-xkms #190).
// This captures the body the server actually received rather than asserting on
// the client's own request struct, which would pass either way.
func TestCreateUser_CarriesWithoutEmailLoginKey(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody = body
		writeJSONResponse(t, w, http.StatusOK, transport.UserInfo{ID: 1, Username: "root", Enabled: true})
	}))
	defer srv.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}

	_, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username:             "root",
		WithoutEmailLoginKey: true,
	})
	require.NoError(t, err)

	var body map[string]any
	require.NoError(t, json.Unmarshal(gotBody, &body))
	got, ok := body["without_email_login_key"].(bool)
	require.True(t, ok, "without_email_login_key missing from the wire body: %#v", body)
	assert.True(t, got, "the no-email exemption was dropped in serialization")
	assert.Equal(t, "", body["email"], "a cert-authenticated admin sends an empty email")
}

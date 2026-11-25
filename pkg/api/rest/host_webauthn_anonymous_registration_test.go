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

package rest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
)

// newAuthNode builds an auth-enabled qrdb node with go-xkms's service
// principal, as xkmsd runs it.
func newAuthNode(t *testing.T) *qrdbnode.Node {
	t.Helper()
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Auth.Enabled = qrdbsdk.BoolPtr(true)
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false

	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil, serviceprincipal.Option())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	return node
}

// buildXKMSDWebAuthnService builds the WebAuthn service the way xkmsd does
// (pkg/server initializeWebAuthnService) over an auth-enabled node.
func buildXKMSDWebAuthnService(t *testing.T, node *qrdbnode.Node) *webauthn.Service {
	t.Helper()
	ds, err := datastore.New(node.Client(), config.DatastoreConfig{}, datastore.WithCallContext(node.ServiceContext))
	require.NoError(t, err)
	svc, err := BuildWebAuthnService(WebAuthnServiceParams{
		Config:     qrdbWebAuthnConfig(),
		QRDBClient: ds.Client(),
		DAOFactory: ds.DAOFactory(),
		TenantID:   DefaultWebAuthnTenant,
	})
	require.NoError(t, err)
	return svc
}

// TestBuildWebAuthnService_AnonymousRegistrationOnAuthNode drives an open
// sign-up (no caller identity) through the REST handler against an
// auth-enabled node, as the browser suite does against xkmsd.
func TestBuildWebAuthnService_AnonymousRegistrationOnAuthNode(t *testing.T) {
	node := newAuthNode(t)
	handler := webauthnhttp.NewHandler(buildXKMSDWebAuthnService(t, node))

	beginBody, err := json.Marshal(map[string]string{"email": "anon@example.com", "display_name": "Anon"})
	require.NoError(t, err)
	beginRec := httptest.NewRecorder()
	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", bytes.NewReader(beginBody))
	beginReq.Header.Set("Content-Type", "application/json")
	handler.BeginRegistration(beginRec, beginReq)
	require.Equal(t, http.StatusOK, beginRec.Code, "begin body: %s", beginRec.Body.String())

	sessionID := beginRec.Header().Get(webauthnhttp.HeaderSessionID)
	require.NotEmpty(t, sessionID)
	var options protocol.CredentialCreation
	require.NoError(t, json.Unmarshal(beginRec.Body.Bytes(), &options))
	encodedUserID, ok := options.Response.User.ID.(string)
	require.True(t, ok, "user handle must be a base64url string, got %T", options.Response.User.ID)
	userID, err := base64.RawURLEncoding.DecodeString(encodedUserID)
	require.NoError(t, err)

	authenticator, err := webauthn.NewMockAuthenticator("example.com")
	require.NoError(t, err)
	attestation, err := authenticator.CreateAttestationObject(options.Response.Challenge, userID, "https://example.com")
	require.NoError(t, err)
	finishBody, err := json.Marshal(attestation.Raw)
	require.NoError(t, err)

	finishRec := httptest.NewRecorder()
	finishReq := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/finish", bytes.NewReader(finishBody))
	finishReq.Header.Set("Content-Type", "application/json")
	finishReq.Header.Set(webauthnhttp.HeaderSessionID, sessionID)
	handler.FinishRegistration(finishRec, finishReq)
	require.Equal(t, http.StatusOK, finishRec.Code, "finish body: %s", finishRec.Body.String())

	var resp webauthnhttp.AuthResponse
	require.NoError(t, json.Unmarshal(finishRec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Token)
	require.NotEmpty(t, resp.UserID)
}

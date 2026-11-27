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

package rest_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
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

// openWebAuthnConfig is the example.com relying party with public registration on.
func openWebAuthnConfig() *webauthn.Config {
	allow := true
	return rest.WebAuthnConfigFromXKMS(&config.WebAuthnConfig{
		RPID:                    "example.com",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: &allow,
	})
}

// buildXKMSDWebAuthnService builds the WebAuthn service the way xkmsd does
// (pkg/server initializeWebAuthnService) over an auth-enabled node.
func buildXKMSDWebAuthnService(t *testing.T, node *qrdbnode.Node) (*webauthn.Service, *token.Issuer, *atomic.Int32) {
	t.Helper()
	ds, err := datastore.New(node.Client(), config.DatastoreConfig{}, datastore.WithCallContext(node.ServiceContext))
	require.NoError(t, err)
	var binds atomic.Int32
	issuer, err := rest.BuildTokenIssuer(context.Background(), rest.TokenIssuerParams{
		Backend:     xkmsmocks.NewMockKeyStore(),
		BackendName: "test",
		QRDBClient:  ds.Client(),
		CallContext: func(ctx context.Context) (context.Context, error) {
			binds.Add(1)
			return node.ServiceContext(ctx)
		},
	})
	require.NoError(t, err)
	svc, err := rest.BuildWebAuthnService(rest.WebAuthnServiceParams{
		Config:      openWebAuthnConfig(),
		QRDBClient:  ds.Client(),
		DAOFactory:  ds.DAOFactory(),
		TenantID:    rest.DefaultWebAuthnTenant,
		CallContext: node.ServiceContext,
		TokenIssuer: issuer,
	})
	require.NoError(t, err)
	return svc, issuer, &binds
}

// TestBuildWebAuthnService_AnonymousRegistrationOnAuthNode drives an open
// sign-up (no caller identity) through the REST handler against an
// auth-enabled node, as the browser suite does against xkmsd.
func TestBuildWebAuthnService_AnonymousRegistrationOnAuthNode(t *testing.T) {
	node := newAuthNode(t)
	svc, issuer, binds := buildXKMSDWebAuthnService(t, node)
	handler := webauthnhttp.NewHandler(svc)

	// The auth-enabled node refuses a refresh-store write off the service context.
	unbound, err := token.NewQRDBRefreshStore(node.Client().KV())
	require.NoError(t, err)
	require.Error(t, unbound.Save(context.Background(), &token.Record{JTI: "control", Family: "control", Subject: "control", ExpiresAt: 1 << 40}))

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
	require.NotEmpty(t, resp.RefreshToken)
	require.NotEmpty(t, resp.UserID)
	require.Positive(t, binds.Load(), "the refresh store's save must run on the service context")

	afterFinish := binds.Load()
	pair, err := issuer.Refresh(context.Background(), resp.RefreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)
	require.NotEmpty(t, pair.RefreshToken)
	require.Greater(t, binds.Load(), afterFinish, "refresh must run on the service context")

	require.NoError(t, issuer.Revoke(context.Background(), pair.RefreshToken))
	_, err = issuer.Refresh(context.Background(), pair.RefreshToken)
	var revoked *token.RefreshRevokedError
	require.ErrorAs(t, err, &revoked)
}

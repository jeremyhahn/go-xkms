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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// newEnforcingNode boots a real in-memory standalone qrdb node that enforces
// authentication and carries xkms's service principal, as xkmsd's embedded
// node does.
func newEnforcingNode(t *testing.T) *qrdbnode.Node {
	t.Helper()
	cfg := qrdbsdk.DefaultDaemonConfig()
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

// newEnforcingHostServer builds the host REST surface over an
// authentication-enforcing node, bound to its ServiceContext the way xkmsd
// wires it.
func newEnforcingHostServer(t *testing.T, node *qrdbnode.Node) *Server {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	// As xkmsd does when it builds WebAuthn over its embedded node: the
	// principal gains the user store's users grant.
	serviceprincipal.RegisterWebAuthnGrant()
	allow := true
	srv, err := NewHostServer(context.Background(), &HostConfig{
		XKMSService: svc,
		QRDBClient:  node.Client(),
		DAOFactory:  testutil.NewMemoryDAOFactory(),
		WebAuthn: WebAuthnConfigFromXKMS(&config.WebAuthnConfig{
			RPID:                    "example.com",
			AllowPublicRegistration: &allow,
		}),
		WebAuthnCallContext: node.ServiceContext,
	})
	require.NoError(t, err)
	require.NotNil(t, srv.tokenIssuer, "the host must mount a token issuer")
	return srv
}

// TestNewHostServer_TokenIssuerRunsOnTheCallContext is the regression test
// for #2541 P1 (1): the refresh-token record a ceremony's Finish writes runs
// on the host's bound context, so an anonymous login completes on a node
// that enforces authentication instead of failing unauthenticated (a 500).
func TestNewHostServer_TokenIssuerRunsOnTheCallContext(t *testing.T) {
	node := newEnforcingNode(t)
	srv := newEnforcingHostServer(t, node)

	pair, err := srv.tokenIssuer.Mint(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: "default",
	})
	require.NoError(t, err, "minting on an anonymous context must run as the service principal")
	require.NotNil(t, pair)
}

// TestNewHostServer_RefreshResolvesOnTheCallContext is the regression test
// for #2541 P1 (2): POST /api/v1/auth/refresh is public, so the resolver's
// current-account lookup runs on the host's bound context. A valid refresh
// token for a live account rotates (200) on a node that enforces
// authentication instead of failing unauthenticated (401).
func TestNewHostServer_RefreshResolvesOnTheCallContext(t *testing.T) {
	node := newEnforcingNode(t)
	srv := newEnforcingHostServer(t, node)

	// The account exists before the login: seed it below the RBAC layer, as
	// an operator's earlier sign-up would have.
	_, err := node.UserService().CreateUser(context.Background(), &qrdbuser.CreateUserRequest{
		Username: "alice",
		Email:    "alice@example.com",
		Name:     "Alice",
	})
	require.NoError(t, err)

	pair, err := srv.tokenIssuer.Mint(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: DefaultWebAuthnTenant,
		Metadata: map[string]string{auth.SubjectKindMetadataKey: auth.SubjectKindUsername},
	})
	require.NoError(t, err)

	body, err := json.Marshal(map[string]string{"refresh_token": pair.RefreshToken})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
}

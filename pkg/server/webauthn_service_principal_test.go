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
	"context"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn/client"
	wahttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
)

// TestWebAuthnService_RegistersOnAuthenticatingNode runs a browser-shaped
// registration (begin + finish) against the WebAuthn service xkmsd builds,
// on an embedded qrdb node that enforces authentication -- the node every
// secure xkmsd config runs (test/integration/webauthn-browser/config.yaml).
// The ceremony is unauthenticated, so the relying party's qrdb user calls
// must run as the node's service principal like the rest of the datastore;
// on the caller's context the node refuses them and every registration
// answered 500 internal_error.
func TestWebAuthnService_RegistersOnAuthenticatingNode(t *testing.T) {
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

	ds, err := datastore.New(node.Client(), config.DatastoreConfig{Engine: "memory"},
		datastore.WithCallContext(node.ServiceContext))
	require.NoError(t, err)

	const origin = "https://localhost:18443"
	allow := true
	s := newMinimalServer(t, &config.Config{})
	s.qrdbNode = node
	s.datastore.Store(ds)
	s.tokenIssuer = newTestTokenIssuer(t)
	s.webauthnConfig = &webauthn.Config{
		RPID:                    "localhost",
		RPDisplayName:           "xKMS WebAuthn Browser Test",
		RPOrigins:               []string{origin},
		AllowPublicRegistration: &allow,
	}
	require.NoError(t, s.initializeWebAuthnService())
	require.NotNil(t, s.webauthnService)

	r := chi.NewRouter()
	r.Route("/api/v1/webauthn", func(r chi.Router) {
		wahttp.MountChi(r, wahttp.NewHandler(s.webauthnService))
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	c, err := client.NewClient(&client.Config{
		ServerURL:            srv.URL,
		Origin:               origin,
		AuthenticatorAdapter: client.NewSoftwareAdapter(),
	})
	require.NoError(t, err)

	res, err := c.Register(context.Background(), &client.RegistrationRequest{
		Username:    "alice@example.com",
		DisplayName: "Alice",
	})
	require.NoError(t, err, "registration on an authenticating node")
	assert.NotEmpty(t, res.UserID)
	assert.NotEmpty(t, res.JWT, "finish answers 200 with a session token")
}

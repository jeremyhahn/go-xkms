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

package apimodule

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// TestModule_WebAuthnRunsOnTheServiceContext proves the self-built host
// hands WithServiceContext's binder to the WebAuthn store: open sign-up on
// an auth-enabled node succeeds.
func TestModule_WebAuthnRunsOnTheServiceContext(t *testing.T) {
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

	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	allow := true
	m, err := NewModule(func() *xkms.XKMSService { return svc },
		WithQRDBClient(node.Client),
		WithServiceContext(node.ServiceContext),
		WithWebAuthnConfig(&config.WebAuthnConfig{
			RPID:                    "example.com",
			RPOrigins:               []string{"https://example.com"},
			AllowPublicRegistration: &allow,
		}))
	require.NoError(t, err)
	srv, err := m.restServer()
	require.NoError(t, err)
	require.NotNil(t, srv)

	body, err := json.Marshal(map[string]string{"email": "anon@example.com", "display_name": "Anon"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
}

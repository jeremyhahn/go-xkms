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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// newAuthNodeHostServer builds a host server over an auth-enabled node with
// the given WebAuthn call context and logger.
func newAuthNodeHostServer(t *testing.T, node *qrdbnode.Node, bind webauthn.CallContext, logger *slog.Logger) *Server {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	ds, err := datastore.New(node.Client(), config.DatastoreConfig{}, datastore.WithCallContext(node.ServiceContext))
	require.NoError(t, err)

	srv, err := NewHostServer(context.Background(), &HostConfig{
		XKMSService: svc,
		QRDBClient:  ds.Client(),
		DAOFactory:  ds.DAOFactory(),
		WebAuthn:    qrdbWebAuthnConfig(),
		Logger:      logger,
	})
	require.NoError(t, err)
	return srv
}

func beginAnonymousRegistration(t *testing.T, srv *Server) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"email": "anon@example.com", "display_name": "Anon"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// TestNewHostServer_WebAuthnUnclassifiedErrorLogsAtError proves an
// unclassified ceremony error is logged at Error through the host's
// configured logger and kept out of the response body.
func TestNewHostServer_WebAuthnUnclassifiedErrorLogsAtError(t *testing.T) {
	node := newAuthNode(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv := newAuthNodeHostServer(t, node, nil, logger)

	w := beginAnonymousRegistration(t, srv)
	require.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), "qrdb")

	assert.Contains(t, logs.String(), "level=ERROR")
	assert.Contains(t, logs.String(), "qrdb/auth: unauthenticated")
}

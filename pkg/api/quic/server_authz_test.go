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
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// errFakeDenied is the typed denial returned by recordingRBAC when configured
// to deny. The qrdb RBAC contract is: nil on allow, a non-nil error on deny —
// the *auth.Authorizer surfaces this verbatim to the QUIC authorize helper.
var errFakeDenied = errors.New("permission denied: viewer may not read backends")

// recordingRBAC is a test double for qrdbtransport.RBACClient. It records the
// last identity, resource, and action it was asked to authorize and returns
// either nil (allow) or errFakeDenied (deny) per the deny flag. It is wrapped
// with auth.NewAuthorizer to exercise the real authorization seam end to end.
type recordingRBAC struct {
	deny         bool
	lastIdentity *qrdbtransport.Identity
	lastResource string
	lastAction   string
}

func (r *recordingRBAC) Authorize(_ context.Context, id *qrdbtransport.Identity, resource, action string) error {
	r.lastIdentity = id
	r.lastResource = resource
	r.lastAction = action
	if r.deny {
		return errFakeDenied
	}
	return nil
}

func (r *recordingRBAC) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

// mockAuditLogger is a test double for audit.Logger.
type mockAuditLogger struct {
	events []*audit.Event
	err    error
}

func (m *mockAuditLogger) Log(_ context.Context, event *audit.Event) error {
	m.events = append(m.events, event)
	return m.err
}

func (m *mockAuditLogger) Close() error {
	return nil
}

// identityAuthenticator is a test authenticator that returns a configurable identity.
// This is needed because the authentication middleware always runs before handlers
// and overwrites any identity set directly on the request context.
type identityAuthenticator struct {
	identity *auth.Identity
}

func (a *identityAuthenticator) Name() string { return "identity-test" }

func (a *identityAuthenticator) AuthenticateHTTP(_ *http.Request) (*auth.Identity, error) {
	if a.identity != nil {
		return a.identity, nil
	}
	// Return anonymous identity when no identity is configured (simulates unauthenticated)
	return &auth.Identity{
		Subject: "anonymous",
	}, nil
}

func (a *identityAuthenticator) AuthenticateGRPC(_ context.Context, _ metadata.MD) (*auth.Identity, error) {
	return nil, errors.New("not implemented")
}

// createAuthzTestServer creates a test server with a configurable authorizer,
// audit logger, and identity. The identity is provided via a custom
// authenticator to properly flow through the authentication middleware.
func createAuthzTestServer(
	t *testing.T,
	authorizer *auth.Authorizer,
	auditLogger audit.Logger,
	identity *auth.Identity,
) (*Server, *xkmsmocks.MockKeyStore) {
	t.Helper()

	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	svc, _ := xkms.Get()

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: &identityAuthenticator{identity: identity},
		Authorizer:    authorizer,
		AuditLogger:   auditLogger,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		XKMSService:   svc,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	return server, mockKS
}

// TestAuthzAuthorize_AllowedRequest verifies that an allowed authorization
// decision lets the request proceed to the handler and forwards the correct
// identity, resource, and action to the qrdb RBAC client.
func TestAuthzAuthorize_AllowedRequest(t *testing.T) {
	rbac := &recordingRBAC{deny: false}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{
		Subject: "admin@example.com",
		Roles:   []string{"admin"},
	}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, identity)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify the RBAC client received the remapped qrdb vocabulary.
	require.NotNil(t, rbac.lastIdentity)
	assert.Equal(t, "admin@example.com", rbac.lastIdentity.Subject)
	assert.Equal(t, []string{"admin"}, rbac.lastIdentity.Roles)
	assert.Equal(t, "backends", rbac.lastResource)
	assert.Equal(t, "list", rbac.lastAction)
}

// TestAuthzAuthorize_DeniedRequest verifies that a denied authorization
// returns HTTP 403 Forbidden carrying the qrdb denial message.
func TestAuthzAuthorize_DeniedRequest(t *testing.T) {
	rbac := &recordingRBAC{deny: true}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{
		Subject: "viewer@example.com",
		Roles:   []string{"viewer"},
	}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, identity)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "permission denied")
}

// TestAuthzAuthorize_DisabledAllowsAll verifies that a nil-backed Authorizer
// (authorization disabled) admits every request.
func TestAuthzAuthorize_DisabledAllowsAll(t *testing.T) {
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "user@example.com"}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(nil), logger, identity)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestAuthzAuthorize_NoIdentityUnauthenticated verifies that an enabled
// authorizer rejects a request with no identity as 401 Unauthorized.
func TestAuthzAuthorize_NoIdentityUnauthenticated(t *testing.T) {
	rbac := &recordingRBAC{deny: false}
	logger := &mockAuditLogger{}
	// An authenticator that yields a nil identity forces the unauthenticated
	// path inside the authorize helper.
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, nil)
	defer xkms.Reset()
	// Replace the authenticator with one that returns a nil identity so the
	// authorize helper observes auth.ErrUnauthenticated.
	server.authenticator = &nilIdentityAuthenticator{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// nilIdentityAuthenticator authenticates successfully but yields no identity,
// exercising the authorize helper's ErrUnauthenticated branch.
type nilIdentityAuthenticator struct{}

func (a *nilIdentityAuthenticator) Name() string { return "nil-identity" }

func (a *nilIdentityAuthenticator) AuthenticateHTTP(_ *http.Request) (*auth.Identity, error) {
	return nil, nil
}

func (a *nilIdentityAuthenticator) AuthenticateGRPC(_ context.Context, _ metadata.MD) (*auth.Identity, error) {
	return nil, errors.New("not implemented")
}

// TestAuthzAuthorize_HealthEndpointSkipsAuthz verifies that the /health
// endpoint does not require authorization.
func TestAuthzAuthorize_HealthEndpointSkipsAuthz(t *testing.T) {
	rbac := &recordingRBAC{deny: true}
	logger := &mockAuditLogger{}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, nil)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	// Health endpoint should succeed regardless of authorizer denial.
	assert.Equal(t, http.StatusOK, w.Code)

	// The RBAC client should NOT have been called.
	assert.Nil(t, rbac.lastIdentity)
}

// TestAuthzAuditLogging verifies that audit events are logged correctly for
// both allowed and denied requests.
func TestAuthzAuditLogging(t *testing.T) {
	t.Run("logs allow event on authorized request", func(t *testing.T) {
		logger := &mockAuditLogger{}
		identity := &auth.Identity{
			Subject: "operator@example.com",
			Roles:   []string{"operator"},
		}
		server, _ := createAuthzTestServer(t, auth.NewAuthorizer(&recordingRBAC{deny: false}), logger, identity)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		req.RemoteAddr = "192.168.1.100:54321"
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		require.Len(t, logger.events, 1)
		event := logger.events[0]
		assert.Equal(t, "operator@example.com", event.Subject)
		assert.Equal(t, "list", event.Action)
		assert.Equal(t, "backends", event.Resource)
		assert.Equal(t, "/api/v1/backends", event.ResourceID)
		assert.Equal(t, audit.OutcomeAllow, event.Outcome)
		assert.Equal(t, http.MethodGet, event.Details["method"])
		assert.Equal(t, "192.168.1.100:54321", event.Details["remote_addr"])
		assert.Equal(t, "operator", event.Details["role"])
		assert.False(t, event.Timestamp.IsZero())
	})

	t.Run("logs deny event on unauthorized request", func(t *testing.T) {
		logger := &mockAuditLogger{}
		identity := &auth.Identity{
			Subject: "viewer@example.com",
			Roles:   []string{"viewer"},
		}
		server, _ := createAuthzTestServer(t, auth.NewAuthorizer(&recordingRBAC{deny: true}), logger, identity)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		req.RemoteAddr = "10.0.0.5:12345"
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		require.Len(t, logger.events, 1)
		event := logger.events[0]
		assert.Equal(t, "viewer@example.com", event.Subject)
		assert.Equal(t, "list", event.Action)
		assert.Equal(t, "backends", event.Resource)
		assert.Equal(t, "/api/v1/backends", event.ResourceID)
		assert.Equal(t, audit.OutcomeDeny, event.Outcome)
		assert.Equal(t, http.MethodGet, event.Details["method"])
		assert.Equal(t, "10.0.0.5:12345", event.Details["remote_addr"])
		assert.Equal(t, "viewer", event.Details["role"])
	})

	t.Run("omits role from details when empty", func(t *testing.T) {
		logger := &mockAuditLogger{}
		identity := &auth.Identity{
			Subject: "service-account",
			// No roles claim
		}
		server, _ := createAuthzTestServer(t, auth.NewAuthorizer(&recordingRBAC{deny: false}), logger, identity)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		require.Len(t, logger.events, 1)
		_, hasRole := logger.events[0].Details["role"]
		assert.False(t, hasRole)
	})

	t.Run("audit logger error does not affect request processing", func(t *testing.T) {
		logger := &mockAuditLogger{
			err: errors.New("audit log write failed"),
		}
		identity := &auth.Identity{Subject: "admin@example.com"}
		server, _ := createAuthzTestServer(t, auth.NewAuthorizer(&recordingRBAC{deny: false}), logger, identity)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		// Request should still succeed despite audit failure.
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestAuthzExtractRole_DirectFunction verifies the extractRole function
// handles edge cases correctly when called directly.
func TestAuthzExtractRole_DirectFunction(t *testing.T) {
	t.Run("nil identity returns empty", func(t *testing.T) {
		assert.Equal(t, "", extractRole(nil))
	})

	t.Run("nil roles returns empty", func(t *testing.T) {
		identity := &auth.Identity{Subject: "test"}
		assert.Equal(t, "", extractRole(identity))
	})

	t.Run("first of multiple roles", func(t *testing.T) {
		identity := &auth.Identity{Subject: "test", Roles: []string{"admin", "operator"}}
		assert.Equal(t, "admin", extractRole(identity))
	})
}

// TestAuthzNewServer_DefaultAuthorizerAndAuditLogger verifies that the server
// defaults to a disabled authorizer and NoOp audit logger when none provided.
func TestAuthzNewServer_DefaultAuthorizerAndAuditLogger(t *testing.T) {
	setupTestXKMS(t)
	defer cleanupXKMS()

	svc, _ := xkms.Get()

	cfg := &Config{
		Addr:        "localhost:8444",
		Logger:      testLogger(),
		XKMSService: svc,
		// No Authorizer or AuditLogger provided
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.NotNil(t, server.authorizer)
	assert.False(t, server.authorizer.Enabled())
	assert.NotNil(t, server.auditLogger)
}

// TestAuthzNewServer_WithCustomAuthorizerAndAuditLogger verifies that a custom
// authorizer and audit logger are properly set on the server.
func TestAuthzNewServer_WithCustomAuthorizerAndAuditLogger(t *testing.T) {
	setupTestXKMS(t)
	defer cleanupXKMS()

	authorizer := auth.NewAuthorizer(&recordingRBAC{})
	logger := &mockAuditLogger{}

	svc, _ := xkms.Get()

	cfg := &Config{
		Addr:        "localhost:8444",
		Logger:      testLogger(),
		Authorizer:  authorizer,
		AuditLogger: logger,
		XKMSService: svc,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, authorizer, server.authorizer)
	assert.Equal(t, logger, server.auditLogger)
}

// TestAuthzKeysDenied verifies authorization enforcement on key operations and
// confirms the remapped qrdb resource/action vocabulary at each route.
func TestAuthzKeysDenied(t *testing.T) {
	rbac := &recordingRBAC{deny: true}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "viewer@example.com"}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, identity)
	defer xkms.Reset()

	t.Run("list keys denied", func(t *testing.T) {
		rbac.lastIdentity = nil
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, rbac.lastIdentity)
		assert.Equal(t, "keys", rbac.lastResource)
		assert.Equal(t, "list", rbac.lastAction)
	})

	t.Run("generate key denied", func(t *testing.T) {
		rbac.lastIdentity = nil
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, rbac.lastIdentity)
		assert.Equal(t, "keys", rbac.lastResource)
		assert.Equal(t, "create", rbac.lastAction)
	})

	t.Run("delete key denied", func(t *testing.T) {
		rbac.lastIdentity = nil
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/my-key?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, rbac.lastIdentity)
		assert.Equal(t, "keys", rbac.lastResource)
		assert.Equal(t, "delete", rbac.lastAction)
	})
}

// TestAuthzCertsDenied verifies authorization enforcement on certificate
// operations and confirms the remapped qrdb resource/action vocabulary.
func TestAuthzCertsDenied(t *testing.T) {
	rbac := &recordingRBAC{deny: true}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "viewer@example.com"}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, identity)
	defer xkms.Reset()

	t.Run("list certs denied", func(t *testing.T) {
		rbac.lastIdentity = nil
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, rbac.lastIdentity)
		assert.Equal(t, "certs", rbac.lastResource)
		assert.Equal(t, "list", rbac.lastAction)
	})

	t.Run("save cert denied", func(t *testing.T) {
		rbac.lastIdentity = nil
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, rbac.lastIdentity)
		assert.Equal(t, "certs", rbac.lastResource)
		assert.Equal(t, "generate", rbac.lastAction)
	})

	t.Run("get cert denied", func(t *testing.T) {
		rbac.lastIdentity = nil
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/my-cert", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, rbac.lastIdentity)
		assert.Equal(t, "certs", rbac.lastResource)
		assert.Equal(t, "read", rbac.lastAction)
	})

	t.Run("delete cert denied", func(t *testing.T) {
		rbac.lastIdentity = nil
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/my-cert", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, rbac.lastIdentity)
		assert.Equal(t, "certs", rbac.lastResource)
		assert.Equal(t, "revoke", rbac.lastAction)
	})
}

// TestAuthzTypedErrors verifies the typed error values exist and have correct messages.
func TestAuthzTypedErrors(t *testing.T) {
	assert.Equal(t, "authorization error", ErrAuthorizationFailed.Error())
	assert.Equal(t, "access denied", ErrAccessDenied.Error())
	assert.True(t, errors.Is(ErrAuthorizationFailed, ErrAuthorizationFailed))
	assert.True(t, errors.Is(ErrAccessDenied, ErrAccessDenied))
	assert.False(t, errors.Is(ErrAuthorizationFailed, ErrAccessDenied))
}

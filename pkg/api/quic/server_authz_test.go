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

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/authz"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// mockAuthorizer is a test double for authz.Authorizer.
type mockAuthorizer struct {
	decision *authz.AuthorizationDecision
	err      error
	lastReq  *authz.AuthorizationRequest
}

func (m *mockAuthorizer) Authorize(_ context.Context, req *authz.AuthorizationRequest) (*authz.AuthorizationDecision, error) {
	m.lastReq = req
	return m.decision, m.err
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
		Claims:  make(map[string]interface{}),
	}, nil
}

func (a *identityAuthenticator) AuthenticateGRPC(_ context.Context, _ metadata.MD) (*auth.Identity, error) {
	return nil, errors.New("not implemented")
}

// createAuthzTestServer creates a test server with configurable authorizer, audit logger,
// and identity. The identity is provided via a custom authenticator to properly flow
// through the authentication middleware.
func createAuthzTestServer(
	t *testing.T,
	authorizer authz.Authorizer,
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

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: &identityAuthenticator{identity: identity},
		Authorizer:    authorizer,
		AuditLogger:   auditLogger,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	return server, mockKS
}

// TestAuthzAuthorize_AllowedRequest verifies that an allowed authorization
// decision lets the request proceed to the handler.
func TestAuthzAuthorize_AllowedRequest(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true, Reason: "admin"},
	}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{
		Subject: "admin@example.com",
		Claims: map[string]interface{}{
			"roles": []string{"admin"},
		},
	}
	server, _ := createAuthzTestServer(t, authorizer, logger, identity)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify authorizer received correct request
	require.NotNil(t, authorizer.lastReq)
	assert.Equal(t, "admin@example.com", authorizer.lastReq.Subject)
	assert.Equal(t, "admin", authorizer.lastReq.Role)
	assert.Equal(t, "backends", authorizer.lastReq.Resource)
	assert.Equal(t, "read", authorizer.lastReq.Action)
}

// TestAuthzAuthorize_DeniedRequest verifies that a denied authorization
// decision returns HTTP 403 Forbidden with the denial reason.
func TestAuthzAuthorize_DeniedRequest(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "insufficient permissions"},
	}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{
		Subject: "viewer@example.com",
		Claims: map[string]interface{}{
			"roles": "viewer",
		},
	}
	server, _ := createAuthzTestServer(t, authorizer, logger, identity)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions")
}

// TestAuthzAuthorize_DeniedRequestDefaultReason verifies that a denied
// authorization with an empty reason falls back to the default "access denied" message.
func TestAuthzAuthorize_DeniedRequestDefaultReason(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: ""},
	}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "user@example.com"}
	server, _ := createAuthzTestServer(t, authorizer, logger, identity)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied")
}

// TestAuthzAuthorize_AuthzError verifies that an authorization error returns
// HTTP 500 Internal Server Error.
func TestAuthzAuthorize_AuthzError(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: nil,
		err:      errors.New("database connection failed"),
	}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{
		Subject: "admin@example.com",
		Claims: map[string]interface{}{
			"roles": []string{"admin"},
		},
	}
	server, _ := createAuthzTestServer(t, authorizer, logger, identity)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "authorization error")
}

// TestAuthzAuthorize_NoIdentity verifies that requests without an identity
// in the context reach the authorizer with the "anonymous" subject from the
// NoOp authenticator (which is what the authentication middleware provides).
func TestAuthzAuthorize_NoIdentity(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	logger := &mockAuditLogger{}
	// nil identity -> identityAuthenticator returns anonymous
	server, _ := createAuthzTestServer(t, authorizer, logger, nil)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	// The authenticator returns "anonymous" when no identity is configured
	require.NotNil(t, authorizer.lastReq)
	assert.Equal(t, "anonymous", authorizer.lastReq.Subject)
	assert.Equal(t, "", authorizer.lastReq.Role)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestAuthzAuthorize_NoIdentityDenied verifies that anonymous requests can be
// denied by the authorizer.
func TestAuthzAuthorize_NoIdentityDenied(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "anonymous access denied"},
	}
	logger := &mockAuditLogger{}
	// nil identity -> identityAuthenticator returns anonymous
	server, _ := createAuthzTestServer(t, authorizer, logger, nil)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "anonymous access denied")

	// Verify audit event has "anonymous" subject (from authenticator)
	require.Len(t, logger.events, 1)
	assert.Equal(t, "anonymous", logger.events[0].Subject)
}

// TestAuthzAuthorize_NilDecisionAllowed verifies that a nil decision with
// no error is treated as allowed (permissive by default).
func TestAuthzAuthorize_NilDecisionAllowed(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: nil,
		err:      nil,
	}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "admin@example.com"}
	server, _ := createAuthzTestServer(t, authorizer, logger, identity)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestAuthzAuthorize_HealthEndpointSkipsAuthz verifies that the /health
// endpoint does not require authorization.
func TestAuthzAuthorize_HealthEndpointSkipsAuthz(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "deny everything"},
	}
	logger := &mockAuditLogger{}
	server, _ := createAuthzTestServer(t, authorizer, logger, nil)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	// Health endpoint should succeed regardless of authorizer denial
	assert.Equal(t, http.StatusOK, w.Code)

	// The authorizer should NOT have been called (no lastReq set)
	assert.Nil(t, authorizer.lastReq)
}

// TestAuthzAuditLogging verifies that audit events are logged correctly for
// both allowed and denied requests.
func TestAuthzAuditLogging(t *testing.T) {
	t.Run("logs allow event on authorized request", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			decision: &authz.AuthorizationDecision{Allowed: true},
		}
		logger := &mockAuditLogger{}
		identity := &auth.Identity{
			Subject: "operator@example.com",
			Claims: map[string]interface{}{
				"roles": "operator",
			},
		}
		server, _ := createAuthzTestServer(t, authorizer, logger, identity)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		req.RemoteAddr = "192.168.1.100:54321"
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		require.Len(t, logger.events, 1)
		event := logger.events[0]
		assert.Equal(t, "operator@example.com", event.Subject)
		assert.Equal(t, "read", event.Action)
		assert.Equal(t, "backends", event.Resource)
		assert.Equal(t, "/api/v1/backends", event.ResourceID)
		assert.Equal(t, audit.OutcomeAllow, event.Outcome)
		assert.Equal(t, http.MethodGet, event.Details["method"])
		assert.Equal(t, "192.168.1.100:54321", event.Details["remote_addr"])
		assert.Equal(t, "operator", event.Details["role"])
		assert.False(t, event.Timestamp.IsZero())
	})

	t.Run("logs deny event on unauthorized request", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			decision: &authz.AuthorizationDecision{Allowed: false, Reason: "no permission"},
		}
		logger := &mockAuditLogger{}
		identity := &auth.Identity{
			Subject: "viewer@example.com",
			Claims: map[string]interface{}{
				"roles": []string{"viewer"},
			},
		}
		server, _ := createAuthzTestServer(t, authorizer, logger, identity)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		req.RemoteAddr = "10.0.0.5:12345"
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		require.Len(t, logger.events, 1)
		event := logger.events[0]
		assert.Equal(t, "viewer@example.com", event.Subject)
		assert.Equal(t, "read", event.Action)
		assert.Equal(t, "backends", event.Resource)
		assert.Equal(t, "/api/v1/backends", event.ResourceID)
		assert.Equal(t, audit.OutcomeDeny, event.Outcome)
		assert.Equal(t, http.MethodGet, event.Details["method"])
		assert.Equal(t, "10.0.0.5:12345", event.Details["remote_addr"])
		assert.Equal(t, "viewer", event.Details["role"])
	})

	t.Run("logs deny event on authorizer error", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			err: errors.New("policy engine unavailable"),
		}
		logger := &mockAuditLogger{}
		identity := &auth.Identity{Subject: "admin@example.com"}
		server, _ := createAuthzTestServer(t, authorizer, logger, identity)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		require.Len(t, logger.events, 1)
		assert.Equal(t, audit.OutcomeDeny, logger.events[0].Outcome)
	})

	t.Run("omits role from details when empty", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			decision: &authz.AuthorizationDecision{Allowed: true},
		}
		logger := &mockAuditLogger{}
		identity := &auth.Identity{
			Subject: "service-account",
			// No roles claim
		}
		server, _ := createAuthzTestServer(t, authorizer, logger, identity)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		require.Len(t, logger.events, 1)
		_, hasRole := logger.events[0].Details["role"]
		assert.False(t, hasRole)
	})

	t.Run("audit logger error does not affect request processing", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			decision: &authz.AuthorizationDecision{Allowed: true},
		}
		logger := &mockAuditLogger{
			err: errors.New("audit log write failed"),
		}
		identity := &auth.Identity{Subject: "admin@example.com"}
		server, _ := createAuthzTestServer(t, authorizer, logger, identity)
		defer xkms.Reset()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		// Request should still succeed despite audit failure
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestAuthzRoleExtraction verifies that roles are correctly extracted from
// identity claims in various formats.
func TestAuthzRoleExtraction(t *testing.T) {
	tests := []struct {
		name         string
		claims       map[string]interface{}
		expectedRole string
	}{
		{
			name:         "extracts from []string",
			claims:       map[string]interface{}{"roles": []string{"admin", "operator"}},
			expectedRole: "admin",
		},
		{
			name:         "extracts from []interface{}",
			claims:       map[string]interface{}{"roles": []interface{}{"operator", "viewer"}},
			expectedRole: "operator",
		},
		{
			name:         "extracts from string",
			claims:       map[string]interface{}{"roles": "user"},
			expectedRole: "user",
		},
		{
			name:         "empty []string returns empty",
			claims:       map[string]interface{}{"roles": []string{}},
			expectedRole: "",
		},
		{
			name:         "empty []interface{} returns empty",
			claims:       map[string]interface{}{"roles": []interface{}{}},
			expectedRole: "",
		},
		{
			name:         "nil claims returns empty",
			claims:       nil,
			expectedRole: "",
		},
		{
			name:         "missing roles key returns empty",
			claims:       map[string]interface{}{"permissions": "read"},
			expectedRole: "",
		},
		{
			name:         "non-string in []interface{} returns empty",
			claims:       map[string]interface{}{"roles": []interface{}{42}},
			expectedRole: "",
		},
		{
			name:         "unsupported type returns empty",
			claims:       map[string]interface{}{"roles": 123},
			expectedRole: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorizer := &mockAuthorizer{
				decision: &authz.AuthorizationDecision{Allowed: true},
			}
			logger := &mockAuditLogger{}
			identity := &auth.Identity{
				Subject: "test@example.com",
				Claims:  tt.claims,
			}
			server, _ := createAuthzTestServer(t, authorizer, logger, identity)
			defer xkms.Reset()

			req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
			w := httptest.NewRecorder()

			server.handler.ServeHTTP(w, req)

			require.NotNil(t, authorizer.lastReq)
			assert.Equal(t, tt.expectedRole, authorizer.lastReq.Role)
		})
	}
}

// TestAuthzExtractRole_DirectFunction verifies the extractRole function
// handles edge cases correctly when called directly.
func TestAuthzExtractRole_DirectFunction(t *testing.T) {
	t.Run("nil identity returns empty", func(t *testing.T) {
		assert.Equal(t, "", extractRole(nil))
	})

	t.Run("nil claims returns empty", func(t *testing.T) {
		identity := &auth.Identity{Subject: "test", Claims: nil}
		assert.Equal(t, "", extractRole(identity))
	})
}

// TestAuthzAuthorize_ContextMapInitialized verifies that the Context map
// in the AuthorizationRequest is properly initialized.
func TestAuthzAuthorize_ContextMapInitialized(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "admin@example.com"}
	server, _ := createAuthzTestServer(t, authorizer, logger, identity)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	server.handler.ServeHTTP(w, req)

	require.NotNil(t, authorizer.lastReq)
	assert.NotNil(t, authorizer.lastReq.Context)
	assert.Equal(t, "backends", authorizer.lastReq.Resource)
	assert.Equal(t, "read", authorizer.lastReq.Action)
}

// TestAuthzNewServer_DefaultAuthorizerAndAuditLogger verifies that the server
// defaults to NoOp implementations when no authorizer/audit logger are provided.
func TestAuthzNewServer_DefaultAuthorizerAndAuditLogger(t *testing.T) {
	setupTestXKMS(t)
	defer cleanupXKMS()

	cfg := &Config{
		Addr:   "localhost:8444",
		Logger: testLogger(),
		// No Authorizer or AuditLogger provided
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.NotNil(t, server.authorizer)
	assert.NotNil(t, server.auditLogger)
}

// TestAuthzNewServer_WithCustomAuthorizerAndAuditLogger verifies that custom
// authorizer and audit logger are properly set on the server.
func TestAuthzNewServer_WithCustomAuthorizerAndAuditLogger(t *testing.T) {
	setupTestXKMS(t)
	defer cleanupXKMS()

	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	logger := &mockAuditLogger{}

	cfg := &Config{
		Addr:        "localhost:8444",
		Logger:      testLogger(),
		Authorizer:  authorizer,
		AuditLogger: logger,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, authorizer, server.authorizer)
	assert.Equal(t, logger, server.auditLogger)
}

// TestAuthzKeysDenied verifies authorization enforcement on key operations.
func TestAuthzKeysDenied(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "keys access denied"},
	}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "viewer@example.com"}
	server, _ := createAuthzTestServer(t, authorizer, logger, identity)
	defer xkms.Reset()

	t.Run("list keys denied", func(t *testing.T) {
		authorizer.lastReq = nil
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, authorizer.lastReq)
		assert.Equal(t, "keys", authorizer.lastReq.Resource)
		assert.Equal(t, "read", authorizer.lastReq.Action)
	})

	t.Run("generate key denied", func(t *testing.T) {
		authorizer.lastReq = nil
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, authorizer.lastReq)
		assert.Equal(t, "keys", authorizer.lastReq.Resource)
		assert.Equal(t, "write", authorizer.lastReq.Action)
	})

	t.Run("delete key denied", func(t *testing.T) {
		authorizer.lastReq = nil
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/my-key?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, authorizer.lastReq)
		assert.Equal(t, "keys", authorizer.lastReq.Resource)
		assert.Equal(t, "delete", authorizer.lastReq.Action)
	})
}

// TestAuthzCertsDenied verifies authorization enforcement on certificate operations.
func TestAuthzCertsDenied(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "certs access denied"},
	}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "viewer@example.com"}
	server, _ := createAuthzTestServer(t, authorizer, logger, identity)
	defer xkms.Reset()

	t.Run("list certs denied", func(t *testing.T) {
		authorizer.lastReq = nil
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, authorizer.lastReq)
		assert.Equal(t, "certs", authorizer.lastReq.Resource)
		assert.Equal(t, "read", authorizer.lastReq.Action)
	})

	t.Run("save cert denied", func(t *testing.T) {
		authorizer.lastReq = nil
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, authorizer.lastReq)
		assert.Equal(t, "certs", authorizer.lastReq.Resource)
		assert.Equal(t, "write", authorizer.lastReq.Action)
	})

	t.Run("get cert denied", func(t *testing.T) {
		authorizer.lastReq = nil
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/my-cert", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, authorizer.lastReq)
		assert.Equal(t, "certs", authorizer.lastReq.Resource)
		assert.Equal(t, "read", authorizer.lastReq.Action)
	})

	t.Run("delete cert denied", func(t *testing.T) {
		authorizer.lastReq = nil
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/my-cert", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		require.NotNil(t, authorizer.lastReq)
		assert.Equal(t, "certs", authorizer.lastReq.Resource)
		assert.Equal(t, "delete", authorizer.lastReq.Action)
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

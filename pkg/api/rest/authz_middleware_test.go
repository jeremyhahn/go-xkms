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

package rest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// okHandler is a simple handler that writes a 200 OK response.
func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func TestAuthzMiddleware_AllowedRequest(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true, Reason: "admin"},
	}
	logger := &mockAuditLogger{}
	middleware := NewAuthzMiddleware(authorizer, logger)

	handler := middleware.Wrap("keys", "read", okHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	identity := &auth.Identity{
		Subject: "admin@example.com",
		Claims: map[string]interface{}{
			"roles": []string{"admin"},
		},
	}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())

	// Verify authorizer received correct request
	require.NotNil(t, authorizer.lastReq)
	assert.Equal(t, "admin@example.com", authorizer.lastReq.Subject)
	assert.Equal(t, "admin", authorizer.lastReq.Role)
	assert.Equal(t, "keys", authorizer.lastReq.Resource)
	assert.Equal(t, "read", authorizer.lastReq.Action)
}

func TestAuthzMiddleware_DeniedRequest(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "insufficient permissions"},
	}
	logger := &mockAuditLogger{}
	middleware := NewAuthzMiddleware(authorizer, logger)

	handler := middleware.Wrap("keys", "delete", okHandler)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/my-key", nil)
	identity := &auth.Identity{
		Subject: "user@example.com",
		Claims: map[string]interface{}{
			"roles": "user",
		},
	}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions")
}

func TestAuthzMiddleware_DeniedRequestDefaultReason(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: ""},
	}
	logger := &mockAuditLogger{}
	middleware := NewAuthzMiddleware(authorizer, logger)

	handler := middleware.Wrap("keys", "delete", okHandler)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/my-key", nil)
	identity := &auth.Identity{
		Subject: "user@example.com",
	}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "access denied")
}

func TestAuthzMiddleware_AuthzError(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: nil,
		err:      errors.New("database connection failed"),
	}
	logger := &mockAuditLogger{}
	middleware := NewAuthzMiddleware(authorizer, logger)

	handler := middleware.Wrap("keys", "read", okHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	identity := &auth.Identity{
		Subject: "admin@example.com",
		Claims: map[string]interface{}{
			"roles": []string{"admin"},
		},
	}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "authorization error")
}

func TestAuthzMiddleware_NoIdentity(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	logger := &mockAuditLogger{}
	middleware := NewAuthzMiddleware(authorizer, logger)

	handler := middleware.Wrap("keys", "read", okHandler)

	// Request without identity in context
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should still reach the authorizer with empty subject/role
	require.NotNil(t, authorizer.lastReq)
	assert.Equal(t, "", authorizer.lastReq.Subject)
	assert.Equal(t, "", authorizer.lastReq.Role)

	// With NoOp authorizer allowing everything, request passes through
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthzMiddleware_NoIdentityDenied(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: false, Reason: "anonymous access denied"},
	}
	logger := &mockAuditLogger{}
	middleware := NewAuthzMiddleware(authorizer, logger)

	handler := middleware.Wrap("keys", "write", okHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", nil)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "anonymous access denied")

	// Verify audit event has empty subject
	require.Len(t, logger.events, 1)
	assert.Equal(t, "", logger.events[0].Subject)
}

func TestAuthzMiddleware_AuditLogging(t *testing.T) {
	t.Run("logs allow event on authorized request", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			decision: &authz.AuthorizationDecision{Allowed: true},
		}
		logger := &mockAuditLogger{}
		middleware := NewAuthzMiddleware(authorizer, logger)

		handler := middleware.Wrap("certs", "read", okHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/my-cert", nil)
		req.RemoteAddr = "192.168.1.100:54321"
		identity := &auth.Identity{
			Subject: "operator@example.com",
			Claims: map[string]interface{}{
				"roles": "operator",
			},
		}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Len(t, logger.events, 1)
		event := logger.events[0]
		assert.Equal(t, "operator@example.com", event.Subject)
		assert.Equal(t, "read", event.Action)
		assert.Equal(t, "certs", event.Resource)
		assert.Equal(t, "/api/v1/certs/my-cert", event.ResourceID)
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
		middleware := NewAuthzMiddleware(authorizer, logger)

		handler := middleware.Wrap("keys", "delete", okHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/secret-key", nil)
		req.RemoteAddr = "10.0.0.5:12345"
		identity := &auth.Identity{
			Subject: "viewer@example.com",
			Claims: map[string]interface{}{
				"roles": []string{"viewer"},
			},
		}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Len(t, logger.events, 1)
		event := logger.events[0]
		assert.Equal(t, "viewer@example.com", event.Subject)
		assert.Equal(t, "delete", event.Action)
		assert.Equal(t, "keys", event.Resource)
		assert.Equal(t, "/api/v1/keys/secret-key", event.ResourceID)
		assert.Equal(t, audit.OutcomeDeny, event.Outcome)
		assert.Equal(t, http.MethodDelete, event.Details["method"])
		assert.Equal(t, "10.0.0.5:12345", event.Details["remote_addr"])
		assert.Equal(t, "viewer", event.Details["role"])
	})

	t.Run("logs deny event on authorizer error", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			err: errors.New("policy engine unavailable"),
		}
		logger := &mockAuditLogger{}
		middleware := NewAuthzMiddleware(authorizer, logger)

		handler := middleware.Wrap("backends", "manage", okHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/backends", nil)
		identity := &auth.Identity{
			Subject: "admin@example.com",
		}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		require.Len(t, logger.events, 1)
		assert.Equal(t, audit.OutcomeDeny, logger.events[0].Outcome)
	})

	t.Run("omits role from details when empty", func(t *testing.T) {
		authorizer := &mockAuthorizer{
			decision: &authz.AuthorizationDecision{Allowed: true},
		}
		logger := &mockAuditLogger{}
		middleware := NewAuthzMiddleware(authorizer, logger)

		handler := middleware.Wrap("keys", "read", okHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		identity := &auth.Identity{
			Subject: "service-account",
			// No roles claim
		}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

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
		middleware := NewAuthzMiddleware(authorizer, logger)

		handler := middleware.Wrap("keys", "read", okHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		identity := &auth.Identity{Subject: "admin@example.com"}
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Request should still succeed despite audit failure
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestAuthzMiddleware_RoleExtraction(t *testing.T) {
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
			middleware := NewAuthzMiddleware(authorizer, logger)

			handler := middleware.Wrap("keys", "read", okHandler)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
			identity := &auth.Identity{
				Subject: "test@example.com",
				Claims:  tt.claims,
			}
			req = req.WithContext(auth.WithIdentity(req.Context(), identity))

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			require.NotNil(t, authorizer.lastReq)
			assert.Equal(t, tt.expectedRole, authorizer.lastReq.Role)
		})
	}
}

func TestAuthzMiddleware_NilDecisionAllowed(t *testing.T) {
	// When the authorizer returns nil decision and nil error,
	// the request should pass through (permissive by default).
	authorizer := &mockAuthorizer{
		decision: nil,
		err:      nil,
	}
	logger := &mockAuditLogger{}
	middleware := NewAuthzMiddleware(authorizer, logger)

	handler := middleware.Wrap("keys", "read", okHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	identity := &auth.Identity{Subject: "admin@example.com"}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthzMiddleware_ContextMapInitialized(t *testing.T) {
	authorizer := &mockAuthorizer{
		decision: &authz.AuthorizationDecision{Allowed: true},
	}
	logger := &mockAuditLogger{}
	middleware := NewAuthzMiddleware(authorizer, logger)

	handler := middleware.Wrap("piv", "use", okHandler)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/generate", nil)
	identity := &auth.Identity{Subject: "admin@example.com"}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.NotNil(t, authorizer.lastReq)
	assert.NotNil(t, authorizer.lastReq.Context)
	assert.Equal(t, "piv", authorizer.lastReq.Resource)
	assert.Equal(t, "use", authorizer.lastReq.Action)
}

func TestExtractRole(t *testing.T) {
	t.Run("nil identity returns empty", func(t *testing.T) {
		assert.Equal(t, "", extractRole(nil))
	})

	t.Run("nil claims returns empty", func(t *testing.T) {
		identity := &auth.Identity{Subject: "test", Claims: nil}
		assert.Equal(t, "", extractRole(identity))
	})
}

func TestNewAuthzMiddleware_Fields(t *testing.T) {
	authorizer := &mockAuthorizer{}
	logger := &mockAuditLogger{}

	middleware := NewAuthzMiddleware(authorizer, logger)

	require.NotNil(t, middleware)
	assert.Equal(t, authorizer, middleware.authorizer)
	assert.Equal(t, logger, middleware.auditLogger)
}

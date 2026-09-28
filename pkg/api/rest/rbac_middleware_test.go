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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/stretchr/testify/assert"
)

// fakeRBACClient is a stand-in for the qrdb RBAC client. It admits a request
// when the identity holds one of the allowRoles and the requested
// resource:action is in the allow set (or the allow set is nil, meaning the
// role may do anything). It mirrors the qrdb authorizer's contract: nil on
// allow, a non-nil error on deny.
type fakeRBACClient struct {
	// allowRoles maps a role name to the set of "resource:action" it may
	// perform. A nil set grants every action to that role.
	allowRoles map[string]map[string]bool
}

var errFakeDenied = errors.New("fake: permission denied")

func (f *fakeRBACClient) Authorize(_ context.Context, id *qrdbtransport.Identity, resource, action string) error {
	if id == nil {
		return errFakeDenied
	}
	want := resource + ":" + action
	for _, role := range id.Roles {
		set, ok := f.allowRoles[role]
		if !ok {
			continue
		}
		if set == nil || set[want] {
			return nil
		}
	}
	return errFakeDenied
}

func (f *fakeRBACClient) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestRBACMiddleware builds a middleware whose Authorizer admits the admin
// role for everything and grants the user role only key crypto + read.
func newTestRBACMiddleware(t *testing.T) *RBACMiddleware {
	t.Helper()
	client := &fakeRBACClient{
		allowRoles: map[string]map[string]bool{
			"admin": nil, // admin may do anything
			"user": {
				"keys:sign":    true,
				"keys:verify":  true,
				"keys:encrypt": true,
				"keys:decrypt": true,
				"keys:get":     true,
			},
		},
	}
	return NewRBACMiddleware(&RBACConfig{
		Authorizer: auth.NewAuthorizer(client),
		Logger:     discardLogger(),
		SkipPaths:  map[string]bool{"/health": true},
	})
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
}

func TestNewRBACMiddleware(t *testing.T) {
	t.Run("creates middleware with config", func(t *testing.T) {
		m := NewRBACMiddleware(&RBACConfig{
			Authorizer: auth.NewAuthorizer(&fakeRBACClient{}),
			Logger:     discardLogger(),
			SkipPaths:  map[string]bool{"/health": true},
		})
		assert.NotNil(t, m)
	})

	t.Run("initializes empty SkipPaths if nil", func(t *testing.T) {
		m := NewRBACMiddleware(&RBACConfig{
			Authorizer: auth.NewAuthorizer(&fakeRBACClient{}),
			Logger:     discardLogger(),
			SkipPaths:  nil,
		})
		assert.NotNil(t, m.skipPaths)
	})
}

func TestRBACMiddleware_RequirePermission(t *testing.T) {
	m := newTestRBACMiddleware(t)

	t.Run("grants access with valid permission", func(t *testing.T) {
		handler := m.RequirePermission(auth.ResourceKeys, auth.ActionCreate)(okHandler())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", nil)
		id := &auth.Identity{Subject: "admin@example.com", Roles: []string{"admin"}}
		req = req.WithContext(auth.WithIdentity(req.Context(), id))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "OK", w.Body.String())
	})

	t.Run("denies access without permission", func(t *testing.T) {
		// user role cannot delete keys.
		handler := m.RequirePermission(auth.ResourceKeys, auth.ActionDelete)(okHandler())
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/123", nil)
		id := &auth.Identity{Subject: "user@example.com", Roles: []string{"user"}}
		req = req.WithContext(auth.WithIdentity(req.Context(), id))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("returns 401 without identity", func(t *testing.T) {
		handler := m.RequirePermission(auth.ResourceKeys, auth.ActionGet)(okHandler())
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("returns 403 for identity without roles", func(t *testing.T) {
		handler := m.RequirePermission(auth.ResourceKeys, auth.ActionGet)(okHandler())
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		id := &auth.Identity{Subject: "nobody@example.com"}
		req = req.WithContext(auth.WithIdentity(req.Context(), id))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("allows everything when authorization disabled", func(t *testing.T) {
		// A nil RBAC client disables enforcement (allow all).
		disabled := NewRBACMiddleware(&RBACConfig{
			Authorizer: auth.NewAuthorizer(nil),
			Logger:     discardLogger(),
		})
		handler := disabled.RequirePermission(auth.ResourceKeys, auth.ActionDelete)(okHandler())
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/1", nil)
		id := &auth.Identity{Subject: "user@example.com", Roles: []string{"user"}}
		req = req.WithContext(auth.WithIdentity(req.Context(), id))

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestUserRoleContext(t *testing.T) {
	t.Run("stores and retrieves role", func(t *testing.T) {
		ctx := WithUserRole(context.Background(), "admin")
		assert.Equal(t, "admin", GetUserRole(ctx))
	})

	t.Run("returns empty string for missing role", func(t *testing.T) {
		assert.Equal(t, "", GetUserRole(context.Background()))
	})
}

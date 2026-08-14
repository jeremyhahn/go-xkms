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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newCapabilitiesTestServer builds a minimal REST server for the public
// capability discovery endpoint.
func newCapabilitiesTestServer(t *testing.T, mutate func(*Config)) *Server {
	t.Helper()

	cfg := &Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:        testLogger(),
		Version:       "9.9.9-test",
	}
	if mutate != nil {
		mutate(cfg)
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	return server
}

// getCapabilities hits GET /api/v1/capabilities without any credentials.
func getCapabilities(t *testing.T, s *Server) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	s.server.Handler.ServeHTTP(w, req)
	return w
}

func TestCapabilities_Defaults(t *testing.T) {
	server := newCapabilitiesTestServer(t, nil)

	w := getCapabilities(t, server)
	require.Equal(t, http.StatusOK, w.Code)

	var resp capabilitiesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "9.9.9-test", resp.Version)
	assert.False(t, resp.WebAuthnEnabled)
	assert.False(t, resp.PIVLoginEnabled)
	assert.False(t, resp.UIEnabled)
}

// TestCapabilities_NoDeploymentFingerprint pins the response to exactly the
// coarse login-page flags. A new field here is a deliberate decision, not an
// accident: the full capability map is authenticated-only on /auth/me.
func TestCapabilities_NoDeploymentFingerprint(t *testing.T) {
	server := newCapabilitiesTestServer(t, nil)

	w := getCapabilities(t, server)
	require.Equal(t, http.StatusOK, w.Code)

	var raw map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	assert.Len(t, raw, 4)
	for _, key := range []string{"version", "webauthn_enabled", "piv_login_enabled", "ui_enabled"} {
		assert.Contains(t, raw, key)
	}
}

func TestCapabilities_PIVLoginEnabled(t *testing.T) {
	server := newCapabilitiesTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true}
	})

	w := getCapabilities(t, server)
	require.Equal(t, http.StatusOK, w.Code)

	var resp capabilitiesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.PIVLoginEnabled)
	assert.False(t, resp.WebAuthnEnabled)
}

func TestCapabilities_PIVLoginConfiguredButDisabled(t *testing.T) {
	server := newCapabilitiesTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: false}
	})

	w := getCapabilities(t, server)
	require.Equal(t, http.StatusOK, w.Code)

	var resp capabilitiesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.PIVLoginEnabled)
}

func TestCapabilities_UIEnabled(t *testing.T) {
	server := newCapabilitiesTestServer(t, func(c *Config) {
		c.UI = &UIOptions{
			Enabled: true,
			Assets: fstest.MapFS{
				"index.html": &fstest.MapFile{Data: []byte("<html></html>")},
			},
		}
	})

	w := getCapabilities(t, server)
	require.Equal(t, http.StatusOK, w.Code)

	var resp capabilitiesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.UIEnabled)
}

func TestCapabilities_UIEnabledWithoutAssetsReportsDisabled(t *testing.T) {
	server := newCapabilitiesTestServer(t, func(c *Config) {
		c.UI = &UIOptions{Enabled: true}
	})

	w := getCapabilities(t, server)
	require.Equal(t, http.StatusOK, w.Code)

	var resp capabilitiesResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.UIEnabled)
}

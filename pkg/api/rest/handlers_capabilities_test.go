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
	"strings"
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

	// Only what a login screen needs. Which optional subsystems (CA, SSH,
	// tenants, passwords, ...) this deployment wired is reported to an
	// authenticated caller only, in /auth/me's capabilities map.
	keys := []string{"version", "webauthn_enabled", "piv_login_enabled", "ui_enabled"}
	var raw map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	assert.Len(t, raw, len(keys))
	for _, key := range keys {
		assert.Contains(t, raw, key)
	}
}

// TestCapabilities_GatedSubsystemsOffWithoutConfig: a server built without
// a CA, SSH client, barrier registry or password store reports each of those
// subsystems off in /auth/me's capabilities map, so the console never offers a control whose route answers
// 501 (ruling 972 (1)).
func TestCapabilities_GatedSubsystemsOffWithoutConfig(t *testing.T) {
	flags := newCapabilitiesTestServer(t, nil).capabilityFlags()
	for _, key := range []string{"ca", "ssh", "tenants", "passwords", "webauthn"} {
		assert.False(t, flags[key], key)
	}
}

// wireGatedSubsystems gives the server a handler for each gated subsystem,
// the state NewServer leaves when the matching config is present.
func wireGatedSubsystems(s *Server) {
	s.caHandlers = &CAHandlers{}
	s.sshHandlers = &SSHHandlers{}
	s.tenantHandlers = &TenantHandlers{}
	s.passwordHandlers = &PasswordHandlers{}
}

func TestCapabilities_GatedSubsystemsOnWhenWired(t *testing.T) {
	server := newCapabilitiesTestServer(t, nil)
	wireGatedSubsystems(server)
	flags := server.capabilityFlags()
	for _, key := range []string{"ca", "ssh", "tenants", "passwords"} {
		assert.True(t, flags[key], key)
	}
}

// capabilityForRoute names the capability flag that gates a route, or ""
// when the route is not one the console gates on a flag.
func capabilityForRoute(pattern string) string {
	switch {
	case pattern == "/api/v1/ca/bundle":
		// Served with or without the CA subsystem (bootstrap bundle).
		return ""
	case strings.HasPrefix(pattern, "/api/v1/ca/"):
		return "ca"
	case strings.HasPrefix(pattern, "/xkms/v1/ssh/"):
		return "ssh"
	case strings.HasPrefix(pattern, "/api/v1/tenants/") && !strings.Contains(pattern, "/tpm"):
		return "tenants"
	case strings.HasPrefix(pattern, "/api/v1/passwords/"), strings.HasPrefix(pattern, "/api/v1/password-vault"):
		return "passwords"
	case strings.HasPrefix(pattern, "/api/v1/webauthn/"):
		return "webauthn"
	}
	return ""
}

// TestCapabilities_FlagsAgreeWithRouteGuards: every gated route's Enabled
// guard and the capability flag the console reads give the same answer, on
// a server without the subsystems and on one with them: capabilities is
// never a second source of truth.
func TestCapabilities_FlagsAgreeWithRouteGuards(t *testing.T) {
	off := newCapabilitiesTestServer(t, nil)
	on := newCapabilitiesTestServer(t, nil)
	wireGatedSubsystems(on)

	for name, server := range map[string]*Server{"off": off, "on": on} {
		flags := server.capabilityFlags()
		checked := map[string]int{}
		for _, spec := range Routes() {
			flag := capabilityForRoute(spec.Pattern)
			if flag == "" || spec.Enabled == nil {
				continue
			}
			checked[flag]++
			assert.Equal(t, spec.Enabled(server), flags[flag], "%s: %s %s vs %s", name, spec.Method, spec.Pattern, flag)
		}
		for _, flag := range []string{"ca", "ssh", "tenants", "passwords", "webauthn"} {
			assert.Positive(t, checked[flag], "%s: no route gated by %s", name, flag)
		}
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

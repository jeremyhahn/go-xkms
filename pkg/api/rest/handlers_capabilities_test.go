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
	"reflect"
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
// gatedGuards names, per console capability flag, the one predicate both
// Routes() (each gated route's Enabled) and capabilityFlags (/auth/me) read.
var gatedGuards = map[string]func(*Server) bool{
	"ca":        (*Server).hasCA,
	"ssh":       (*Server).hasSSH,
	"tenants":   (*Server).hasTenants,
	"passwords": (*Server).hasPasswords,
	"webauthn":  (*Server).hasWebAuthn,
}

// routeServed reports whether the server's real router serves method+path:
// an unregistered route answers chi's bare 404 page.
func routeServed(t *testing.T, s *Server, method, pattern string) bool {
	t.Helper()
	path := pattern
	for strings.Contains(path, "{") {
		open := strings.Index(path, "{")
		end := strings.Index(path[open:], "}")
		require.Positive(t, end, pattern)
		path = path[:open] + "x" + path[open+end+1:]
	}
	w := httptest.NewRecorder()
	s.server.Handler.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return !(w.Code == http.StatusNotFound && w.Body.String() == "404 page not found\n")
}

func TestCapabilities_GatedSubsystemsOffWithoutConfig(t *testing.T) {
	server := newCapabilitiesTestServer(t, nil)
	flags := server.capabilityFlags()
	for key, guard := range gatedGuards {
		assert.False(t, guard(server), key)
		assert.False(t, flags[key], key)
	}
	// Each flag that reads false matches a route the server does not serve.
	for _, spec := range Routes() {
		if flag := capabilityForRoute(spec.Pattern); flag != "" && spec.Enabled != nil {
			assert.False(t, routeServed(t, server, spec.Method, spec.Pattern), "%s %s served with %s off", spec.Method, spec.Pattern, flag)
		}
	}
}

// wireGatedSubsystems gives the server a handler for each gated subsystem,
// the state NewServer leaves when the matching config is present, and
// rebuilds the router so the gated routes are mounted as NewServer would.
func wireGatedSubsystems(s *Server) {
	s.caHandlers = &CAHandlers{}
	s.sshHandlers = &SSHHandlers{}
	s.tenantHandlers = &TenantHandlers{}
	s.passwordHandlers = &PasswordHandlers{}
	s.server.Handler = s.setupRouter()
}

func TestCapabilities_GatedSubsystemsOnWhenWired(t *testing.T) {
	server := newCapabilitiesTestServer(t, nil)
	wireGatedSubsystems(server)
	flags := server.capabilityFlags()
	for _, key := range []string{"ca", "ssh", "tenants", "passwords"} {
		assert.True(t, gatedGuards[key](server), key)
		assert.True(t, flags[key], key)
	}
	// Each flag that reads true matches routes the server really serves.
	for _, spec := range Routes() {
		flag := capabilityForRoute(spec.Pattern)
		if flag == "" || flag == "webauthn" || spec.Enabled == nil {
			continue
		}
		assert.True(t, routeServed(t, server, spec.Method, spec.Pattern), "%s %s not served with %s on", spec.Method, spec.Pattern, flag)
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
			// The route is gated by the very predicate the flag reads.
			assert.Equal(t, reflect.ValueOf(gatedGuards[flag]).Pointer(), reflect.ValueOf(spec.Enabled).Pointer(),
				"%s %s is not gated by the %s guard", spec.Method, spec.Pattern, flag)
			assert.Equal(t, spec.Enabled(server), flags[flag], "%s: %s %s vs %s", name, spec.Method, spec.Pattern, flag)
			// And the real router agrees with the flag.
			assert.Equal(t, flags[flag], routeServed(t, server, spec.Method, spec.Pattern), "%s: %s %s served vs %s", name, spec.Method, spec.Pattern, flag)
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

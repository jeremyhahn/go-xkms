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
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// admitsAnonymousRequest reports whether the authenticator lets a request with
// no credentials through. Only the no-op authenticator does.
func admitsAnonymousRequest(t *testing.T, s *Server) bool {
	t.Helper()

	_, err := s.authenticator.AuthenticateHTTP(httptest.NewRequest("GET", "/api/v1/keys", nil))
	return err == nil
}

// A reload that changes auth.* must rebuild the authenticator; keeping the old
// one would leave an operator believing the new authentication was enforced
// when it was not.
func TestServer_Reload_RebuildsAuthenticator(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server, err := New(createMinimalConfig(t))
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	require.Equal(t, "jwt", server.authenticator.Name())
	previous := server.authenticator

	newCfg := createMinimalConfig(t)
	newCfg.Auth.JWT.Issuer = "rotated-issuer"

	require.NoError(t, server.Reload(newCfg))

	assert.Equal(t, "jwt", server.authenticator.Name())
	assert.NotSame(t, previous, server.authenticator, "the authenticator must be rebuilt")
	assert.False(t, admitsAnonymousRequest(t, server),
		"the rebuilt JWT authenticator must reject an anonymous request")
	assert.Equal(t, newCfg, server.config)
}

// A reload that disables authentication is refused: the server has no
// unauthenticated mode, so the previous authenticator and configuration stay
// in force.
func TestServer_Reload_RefusesDisabledAuthentication(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	previous := server.authenticator

	newCfg := createMinimalConfig(t)
	newCfg.Auth.Enabled = false

	err = server.Reload(newCfg)
	var disabled *ErrAuthenticationDisabled
	require.ErrorAs(t, err, &disabled)
	assert.Same(t, previous, server.authenticator)
	assert.Equal(t, cfg, server.config)
}

// An invalid auth configuration must fail the reload outright and leave the
// previous authenticator in force -- never a no-op, never nil.
func TestServer_Reload_InvalidAuthKeepsPreviousAuthenticator(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "jwt"
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: writeTestJWTPublicKey(t),
		Issuer:        "test-issuer",
		Audience:      []string{"test-audience"},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	previous := server.authenticator
	require.Equal(t, "jwt", previous.Name())

	// An unknown auth.type is a typo the server must fail closed on. (Adaptive
	// with no JWT key file is no longer invalid: the built-in token issuer
	// supplies the verification key.)
	badCfg := createMinimalConfig(t)
	badCfg.Auth.Enabled = true
	badCfg.Auth.Type = "bogus"

	err = server.Reload(badCfg)
	require.Error(t, err)

	var reloadErr *ErrConfigReload
	require.ErrorAs(t, err, &reloadErr)
	assert.Equal(t, "authentication", reloadErr.Component)

	// Previous authenticator retained, still enforcing, and the rejected
	// configuration was not installed.
	require.NotNil(t, server.authenticator)
	assert.Same(t, previous, server.authenticator)
	assert.Equal(t, "jwt", server.authenticator.Name())
	assert.False(t, admitsAnonymousRequest(t, server))
	assert.Equal(t, cfg, server.config)
}

// An unrecognized auth type is a typo, not a request for anonymous access: the
// reload fails and the previous authenticator survives.
func TestServer_Reload_UnknownAuthTypeKeepsPreviousAuthenticator(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "jwt"
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: writeTestJWTPublicKey(t),
		Issuer:        "test-issuer",
		Audience:      []string{"test-audience"},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	previous := server.authenticator

	badCfg := createMinimalConfig(t)
	badCfg.Auth.Enabled = true
	badCfg.Auth.Type = "jwtt"

	err = server.Reload(badCfg)
	require.Error(t, err)

	var unknown *ErrUnknownAuthType
	assert.ErrorAs(t, err, &unknown)
	assert.Same(t, previous, server.authenticator)
	assert.False(t, admitsAnonymousRequest(t, server))
}

// A JWT key that cannot be parsed must not degrade the running authenticator.
func TestServer_Reload_BrokenJWTKeyKeepsPreviousAuthenticator(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "jwt"
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: writeTestJWTPublicKey(t),
		Issuer:        "test-issuer",
		Audience:      []string{"test-audience"},
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	previous := server.authenticator

	brokenKey := filepath.Join(t.TempDir(), "broken.pem")
	require.NoError(t, os.WriteFile(brokenKey, []byte("not a key"), 0600))

	badCfg := createMinimalConfig(t)
	badCfg.Auth.Enabled = true
	badCfg.Auth.Type = "jwt"
	badCfg.Auth.JWT = &config.JWTConfig{PublicKeyFile: brokenKey}

	err = server.Reload(badCfg)
	require.Error(t, err)
	assert.Same(t, previous, server.authenticator)
	assert.Equal(t, cfg, server.config)
}

// Reload without a configuration is refused rather than nil-dereferenced.
func TestServer_Reload_NilConfig(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server, err := New(createMinimalConfig(t))
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	previous := server.authenticator

	err = server.Reload(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrReloadNilConfig)
	assert.Same(t, previous, server.authenticator)
}

// authConfigChanged drives the "restart required" warning, so it must notice
// every field that selects or configures an authenticator.
func TestAuthConfigChanged(t *testing.T) {
	base := config.AuthConfig{
		Enabled: true,
		Type:    "jwt",
		JWT: &config.JWTConfig{
			PublicKeyFile: "/etc/xkms/jwt.pem",
			Issuer:        "issuer",
			Audience:      []string{"xkms"},
		},
		Composite: &config.CompositeAuthConfig{Methods: []string{"jwt", "mtls"}},
	}

	tests := []struct {
		name    string
		mutate  func(cfg *config.AuthConfig)
		changed bool
	}{
		{"identical", func(*config.AuthConfig) {}, false},
		{"enabled", func(c *config.AuthConfig) { c.Enabled = false }, true},
		{"type", func(c *config.AuthConfig) { c.Type = "mtls" }, true},
		{"mtls", func(c *config.AuthConfig) { c.MTLS = true }, true},
		{"rbac", func(c *config.AuthConfig) { c.EnableRBAC = true }, true},
		{"jwt key", func(c *config.AuthConfig) { c.JWT.PublicKeyFile = "/other.pem" }, true},
		{"jwt issuer", func(c *config.AuthConfig) { c.JWT.Issuer = "other" }, true},
		{"jwt secret", func(c *config.AuthConfig) { c.JWT.Secret = "s" }, true},
		{"jwt algorithm", func(c *config.AuthConfig) { c.JWT.Algorithm = "RS512" }, true},
		{"jwt audience value", func(c *config.AuthConfig) { c.JWT.Audience = []string{"other"} }, true},
		{"jwt audience count", func(c *config.AuthConfig) { c.JWT.Audience = []string{"xkms", "b"} }, true},
		{"jwt removed", func(c *config.AuthConfig) { c.JWT = nil }, true},
		{"composite methods", func(c *config.AuthConfig) { c.Composite.Methods = []string{"mtls"} }, true},
		{"composite count", func(c *config.AuthConfig) { c.Composite.Methods = []string{"jwt"} }, true},
		{"composite removed", func(c *config.AuthConfig) { c.Composite = nil }, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			updated := base
			updated.JWT = &config.JWTConfig{
				Secret:        base.JWT.Secret,
				PublicKeyFile: base.JWT.PublicKeyFile,
				Issuer:        base.JWT.Issuer,
				Audience:      append([]string(nil), base.JWT.Audience...),
				Algorithm:     base.JWT.Algorithm,
			}
			updated.Composite = &config.CompositeAuthConfig{
				Methods: append([]string(nil), base.Composite.Methods...),
			}
			tc.mutate(&updated)

			assert.Equal(t, tc.changed, authConfigChanged(&base, &updated))
		})
	}
}

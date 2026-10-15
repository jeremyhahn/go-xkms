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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// capturedAuthenticator stands in for a protocol listener: it takes the
// Authenticator once, at construction, and never looks at the server again.
// That is exactly how the REST, gRPC, QUIC and MCP servers hold theirs, so
// what this value enforces is what live traffic gets.
type capturedAuthenticator struct {
	auth.Authenticator
}

func captureLikeTransport(s *Server) *capturedAuthenticator {
	return &capturedAuthenticator{Authenticator: s.liveAuthenticator}
}

func (c *capturedAuthenticator) admitsAnonymous() bool {
	_, err := c.AuthenticateHTTP(httptest.NewRequest("GET", "/api/v1/keys", nil))
	return err == nil
}

// compositeAuthConfig returns an explicit one-method composite chain verifying
// JWTs against a fresh test key: an authenticator distinguishable by name from
// the "jwt" one createMinimalConfig configures. The method list is explicit
// because a derived single-method chain collapses to the bare authenticator.
func compositeAuthConfig(t *testing.T) config.AuthConfig {
	t.Helper()
	cfg := testJWTAuthConfig(t)
	cfg.Type = "composite"
	cfg.Composite = &config.CompositeAuthConfig{Methods: []string{"jwt"}}
	return cfg
}

// TestReload_RunningListenerPicksUpNewAuthenticator is the property that makes
// SIGHUP meaningful for authentication.
//
// A transport captures its Authenticator at construction, so before the
// LiveAuthenticator indirection a reload rebuilt the authenticator but every
// already-running listener kept admitting traffic under the old one. An
// operator who changed authentication and reloaded would be told the reload
// succeeded while the server kept enforcing the old authenticator.
//
// The capture happens BEFORE the reload here, deliberately: capturing after
// would pass even with the bug present.
func TestReload_RunningListenerPicksUpNewAuthenticator(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server, err := New(createMinimalConfig(t))
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	listener := captureLikeTransport(server)
	require.NotNil(t, listener.Authenticator, "transports must be handed the live authenticator")
	require.Equal(t, "jwt", listener.Name(), "precondition: the JWT authenticator is in force")
	require.False(t, listener.admitsAnonymous(), "precondition: anonymous refused")

	changed := createMinimalConfig(t)
	changed.Auth = compositeAuthConfig(t)

	require.NoError(t, server.Reload(changed))

	assert.Equal(t, "composite", server.authenticator.Name())
	assert.Equal(t, server.authenticator.Name(), listener.Name(),
		"a listener constructed before the reload must enforce the authenticator installed by it")
	assert.False(t, listener.admitsAnonymous(), "the new authenticator must still refuse anonymous requests")
}

// TestReload_FailedReloadRestoresListenerAuthenticator covers the rollback
// half. A reload can install a new authenticator and then fail a later step;
// the listener must be put back on the authenticator that is actually in
// force, not left holding the one the reload rejected.
func TestReload_FailedReloadRestoresListenerAuthenticator(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server, err := New(createMinimalConfig(t))
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	listener := captureLikeTransport(server)
	previous := server.authenticator
	require.Equal(t, "jwt", listener.Name(), "precondition: the JWT authenticator is in force")

	// An auth type that cannot produce an authenticator fails the reload.
	broken := createMinimalConfig(t)
	broken.Auth.Type = "definitely-not-a-real-authenticator"

	require.Error(t, server.Reload(broken), "an unbuildable authenticator must fail the reload")

	assert.Same(t, previous, server.authenticator, "the previous authenticator must still be in force")
	assert.Same(t, previous, server.liveAuthenticator.Load(),
		"after a failed reload the listener must hold the authenticator actually in force")
	assert.False(t, listener.admitsAnonymous(), "the previous authenticator must still refuse anonymous requests")
}

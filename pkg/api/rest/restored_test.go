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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewServer_RBACAuthorizerConstructionAssert exercises the fail-closed
// construction contract: EnableRBAC demands a usable authorizer, while RBAC
// disabled is the documented open-gate configuration regardless of the
// authorizer field.
func TestNewServer_RBACAuthorizerConstructionAssert(t *testing.T) {
	newConfig := func() *Config {
		return &Config{
			Authenticator: auth.NewNoOpAuthenticator(),
			Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		}
	}

	t.Run("rbac enabled with nil authorizer is refused", func(t *testing.T) {
		cfg := newConfig()
		cfg.EnableRBAC = true

		server, err := NewServer(cfg)
		require.ErrorIs(t, err, ErrAuthorizerRequired)
		assert.Nil(t, server)
	})

	t.Run("rbac enabled with disabled authorizer is refused", func(t *testing.T) {
		cfg := newConfig()
		cfg.EnableRBAC = true
		// auth.NewAuthorizer(nil) is Enabled() == false: it has no backing
		// qrdb RBAC client and would allow every request.
		cfg.RBACAuthorizer = auth.NewAuthorizer(nil)

		server, err := NewServer(cfg)
		require.ErrorIs(t, err, ErrAuthorizerRequired)
		assert.Nil(t, server)
	})

	t.Run("rbac disabled with nil authorizer constructs open gate", func(t *testing.T) {
		cfg := newConfig()

		server, err := NewServer(cfg)
		require.NoError(t, err)
		require.NotNil(t, server)
		assert.Nil(t, server.rbacMiddleware)
	})

	t.Run("rbac enabled with usable authorizer wires middleware", func(t *testing.T) {
		cfg := newConfig()
		cfg.EnableRBAC = true
		cfg.RBACAuthorizer = auth.NewAuthorizer(&recordingRBACClient{})

		server, err := NewServer(cfg)
		require.NoError(t, err)
		require.NotNil(t, server)
		assert.NotNil(t, server.rbacMiddleware)
	})
}

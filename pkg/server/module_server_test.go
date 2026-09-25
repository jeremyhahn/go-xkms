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

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// moduleServerTestFixture builds a fully composed *Server via New(cfg) (the
// software backend, real *xkms.XKMSService, live authenticator, and the
// global default-backend registry all wired exactly as production does) --
// the state ModuleRESTServer/ModuleMCPServer/buildRESTConfig/buildMCPConfig
// read. mcp.NewServer independently resolves its default keystore through
// that global registry, so a hand-built *Server (as newMinimalServer builds)
// is not enough here; only the full New(cfg) pipeline populates it.
func moduleServerTestFixture(t *testing.T) *Server {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	cfg := createMinimalConfig(t)
	s, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Shutdown() })
	return s
}

// TestModuleRESTServer_ComposingReturnsNil proves the module surface answers
// "not ready" (nil) rather than blocking or panicking while the XKMSService
// is still composing.
func TestModuleRESTServer_ComposingReturnsNil(t *testing.T) {
	s := newMinimalServer(t, &config.Config{})
	assert.Nil(t, s.ModuleRESTServer())
}

// TestModuleRESTServer_PrefersRunningLegacyServer proves that when the
// legacy in-process REST listener is already running, ModuleRESTServer
// returns that exact instance rather than lazily building a second one.
func TestModuleRESTServer_PrefersRunningLegacyServer(t *testing.T) {
	s := moduleServerTestFixture(t)
	cfg, err := s.buildRESTConfig()
	require.NoError(t, err)
	legacy, err := rest.NewServer(cfg)
	require.NoError(t, err)
	s.restServer = legacy

	assert.Same(t, legacy, s.ModuleRESTServer())
}

// TestModuleRESTServer_LazilyBuildsAndCaches proves the lazy-construction
// path: with no running legacy server, the first call builds a non-listening
// rest.Server from buildRESTConfig, and a second call returns the identical
// cached instance (the sync.Once latch) rather than rebuilding.
func TestModuleRESTServer_LazilyBuildsAndCaches(t *testing.T) {
	s := moduleServerTestFixture(t)

	first := s.ModuleRESTServer()
	require.NotNil(t, first)

	second := s.ModuleRESTServer()
	assert.Same(t, first, second)
}

// TestModuleMCPServer_ComposingReturnsNil mirrors
// TestModuleRESTServer_ComposingReturnsNil for the MCP module surface.
func TestModuleMCPServer_ComposingReturnsNil(t *testing.T) {
	s := newMinimalServer(t, &config.Config{})
	assert.Nil(t, s.ModuleMCPServer())
}

// TestModuleMCPServer_LazilyBuildsAndCaches proves ModuleMCPServer builds a
// non-listening mcp.Server from buildMCPConfig once composition has
// finished, and caches it across calls via its own sync.Once.
func TestModuleMCPServer_LazilyBuildsAndCaches(t *testing.T) {
	s := moduleServerTestFixture(t)

	first := s.ModuleMCPServer()
	require.NotNil(t, first)

	second := s.ModuleMCPServer()
	assert.Same(t, first, second)
}

// TestModuleMCPServer_ConfigBuildFailureReturnsNil proves that when
// buildMCPConfig cannot resolve a default keystore (no backends
// registered), ModuleMCPServer logs and returns nil rather than panicking on
// the construction error -- and that the sync.Once still latches, so a
// second call does not retry (matching the documented "logs, returns" shape
// callers rely on to answer 503 instead of hanging).
func TestModuleMCPServer_ConfigBuildFailureReturnsNil(t *testing.T) {
	s := moduleServerTestFixture(t)
	s.backends = map[string]xkms.Backend{}
	s.config.Default = ""

	assert.Nil(t, s.ModuleMCPServer())
	assert.Nil(t, s.ModuleMCPServer(), "the sync.Once must latch even on failure")
}

// TestBuildMCPConfig_DefaultBackendSelected proves that config.Default,
// when set and present in s.backends, selects that backend as the MCP
// default keystore.
func TestBuildMCPConfig_DefaultBackendSelected(t *testing.T) {
	s := moduleServerTestFixture(t)

	cfg, err := s.buildMCPConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Same(t, s.xkmsService, cfg.XKMSService)
}

// TestBuildMCPConfig_FallsBackToAnyBackendWhenDefaultUnset proves the "no
// config.Default" branch: buildMCPConfig still resolves a keystore by
// picking any registered backend rather than failing.
func TestBuildMCPConfig_FallsBackToAnyBackendWhenDefaultUnset(t *testing.T) {
	s := moduleServerTestFixture(t)
	s.config.Default = ""

	cfg, err := s.buildMCPConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
}

// TestBuildMCPConfig_NoBackendsFailsClosed proves that with no backends
// registered at all, buildMCPConfig fails with a typed *MCPConfigError
// instead of constructing a server with no usable keystore.
func TestBuildMCPConfig_NoBackendsFailsClosed(t *testing.T) {
	s := moduleServerTestFixture(t)
	s.backends = map[string]xkms.Backend{}
	s.config.Default = ""

	cfg, err := s.buildMCPConfig()
	require.Error(t, err)
	assert.Nil(t, cfg)

	var mcpErr *MCPConfigError
	require.ErrorAs(t, err, &mcpErr)
	assert.Contains(t, mcpErr.Error(), "no keystore available")
}

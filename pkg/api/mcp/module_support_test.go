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

package mcp

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestModuleMethods_Surface proves the module method table covers the full
// dispatchable surface with valid tool names and correct permission data.
func TestModuleMethods_Surface(t *testing.T) {
	specs := ModuleMethods()
	require.NotEmpty(t, specs)

	// Sorted, unique, and covering every dispatch-table method.
	names := make([]string, 0, len(specs))
	byMethod := map[string]MethodSpec{}
	for _, spec := range specs {
		names = append(names, spec.Method)
		_, dup := byMethod[spec.Method]
		require.False(t, dup, "duplicate spec for %s", spec.Method)
		byMethod[spec.Method] = spec
	}
	assert.True(t, sort.StringsAreSorted(names))
	for method := range rpcMethodHandlers {
		_, ok := byMethod[method]
		assert.True(t, ok, "dispatchable method %s missing from ModuleMethods", method)
	}

	// The connection-bound subscription method must not become a tool.
	_, subscribed := byMethod["xkms.subscribe"]
	assert.False(t, subscribed)

	// Tool names use the MCP-safe charset and the xkms namespace.
	toolName := regexp.MustCompile(`^xkms_[A-Za-z0-9_-]+$`)
	toolSeen := map[string]struct{}{}
	for _, spec := range specs {
		assert.Regexp(t, toolName, spec.Tool, "tool name for %s", spec.Method)
		_, dup := toolSeen[spec.Tool]
		require.False(t, dup, "duplicate tool name %s", spec.Tool)
		toolSeen[spec.Tool] = struct{}{}
	}

	// Spot-check the permission classes.
	assert.True(t, byMethod["health"].Public)
	assert.True(t, byMethod["xkms.algorithms"].Public)
	gen := byMethod["xkms.generateKey"]
	assert.Equal(t, auth.ResourceKeys, gen.Resource)
	assert.Equal(t, auth.ActionCreate, gen.Action)
	assert.Equal(t, "xkms_generateKey", gen.Tool)
	frost, ok := byMethod["frost.signRound"]
	require.True(t, ok, "frost namespace must be enumerated regardless of build tags")
	assert.Equal(t, "xkms_frost_signRound", frost.Tool)
}

// TestModuleMethods_ExcludesWebAuthn proves the capability surface a client
// can discover without calling and failing (ModuleMethods) carries no
// WebAuthn/FIDO2 registration or authentication tool: that ceremony is a
// named exclusion from the MCP transport (issue #193), not an unlisted
// method a client could stumble onto and get ErrIdentityCeremonyExcluded
// from. See pkg/api/transport/mcp.ErrIdentityCeremonyExcluded.
func TestModuleMethods_ExcludesWebAuthn(t *testing.T) {
	specs := ModuleMethods()
	require.NotEmpty(t, specs)

	excludedTools := []string{
		"xkms_beginRegistration",
		"xkms_finishRegistration",
		"xkms_beginAuthentication",
		"xkms_finishAuthentication",
	}
	webauthnPattern := regexp.MustCompile(`(?i)webauthn|registration|authentication`)
	for _, spec := range specs {
		for _, excluded := range excludedTools {
			assert.NotEqual(t, excluded, spec.Tool)
		}
		assert.NotRegexp(t, webauthnPattern, spec.Method,
			"method %s (tool %s) looks like a WebAuthn ceremony method; "+
				"WebAuthn is a named exclusion from the MCP transport, not a tool",
			spec.Method, spec.Tool)
	}

	for _, method := range []string{
		"webauthn.beginRegistration",
		"webauthn.finishRegistration",
		"webauthn.beginAuthentication",
		"webauthn.finishAuthentication",
	} {
		_, dispatchable := rpcMethodHandlers[method]
		assert.False(t, dispatchable, "WebAuthn method %s must not be dispatchable over MCP", method)
	}
}

// TestInvokeMethod_HealthAndUnknown proves the connectionless dispatch path
// serves a real method and answers a typed method-not-found error.
func TestInvokeMethod_HealthAndUnknown(t *testing.T) {
	svc := setupTestXKMS(t)
	defer cleanupXKMS()
	server, err := NewServer(&Config{
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)

	result, err := server.InvokeMethod(context.Background(), "health", nil)
	require.NoError(t, err)
	out, err := json.Marshal(result)
	require.NoError(t, err)
	assert.Contains(t, string(out), "health")

	_, err = server.InvokeMethod(context.Background(), "no.such.method", nil)
	require.Error(t, err)
	var unknown *UnknownMethodError
	assert.ErrorAs(t, err, &unknown)
}

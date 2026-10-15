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
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestServer_Reload_LogsWhenListenersRunning proves a reload that changes
// authentication and finds a live protocol listener logs that the running
// listener picked up the rebuilt authenticator, so an operator watching logs
// knows the change is already live rather than pending a restart.
func TestServer_Reload_LogsWhenListenersRunning(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	// Simulate a live listener without actually binding a port: Reload's
	// listenersRunning() only checks that the field is non-nil.
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "correct-horse-battery-staple")
	defer func() { _ = node.Close() }()
	server.qrdbNode = node

	var logBuf bytes.Buffer
	server.logger = custodyCapturingLogger(&logBuf)

	newCfg := createMinimalConfig(t)
	newCfg.Auth.Enabled = true
	newCfg.Auth.Type = "jwt"
	newCfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: writeTestJWTPublicKey(t),
		Issuer:        "test-issuer",
		Audience:      []string{"test-audience"},
	}

	require.NoError(t, server.Reload(newCfg))
	require.Contains(t, logBuf.String(), "Running protocol listeners picked up the new authenticator")
}

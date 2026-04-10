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

//go:build integration && linux

// Package fido2 provides E2E integration tests for the xkey touch/pin IPC commands.
package fido2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Touch IPC CLI Tests
// =============================================================================

// TestIPC_TouchStatus verifies that running `xkey touch` against a running
// daemon reports no pending user presence request when none is active.
func TestIPC_TouchStatus(t *testing.T) {
	skipIfNoUHID(t)

	h := NewFIDO2TestHelper(t)
	h.StartDaemon()

	result := h.RunTouch()
	require.True(t, result.Success(),
		"touch with running daemon should succeed: %s", result.Combined())

	// When no UP request is pending, the daemon responds with "no pending".
	assert.True(t, result.OutputContains("No pending") || result.OutputContains("no pending") || result.OutputContains("noPending"),
		"Touch output should indicate no pending request: got %q", result.Combined())
}

// TestIPC_TouchNoSocket verifies that `xkey touch` fails gracefully when the
// daemon socket does not exist.
func TestIPC_TouchNoSocket(t *testing.T) {
	h := NewFIDO2TestHelper(t)

	result := h.RunCommand("touch", "--socket", "/nonexistent/path/xkey.sock")
	assert.False(t, result.Success(),
		"touch with nonexistent socket should fail")
	t.Logf("Expected failure output: %s", result.Combined())
}

// TestIPC_TouchHelp verifies that `xkey touch --help` prints usage information.
func TestIPC_TouchHelp(t *testing.T) {
	h := NewFIDO2TestHelper(t)

	result := h.RunCommand("touch", "--help")
	require.True(t, result.Success(),
		"touch --help should succeed: %s", result.Combined())

	assert.True(t, result.OutputContains("touch"),
		"Touch help output should mention 'touch'")
}

// =============================================================================
// PIN IPC CLI Tests
// =============================================================================

// TestIPC_PinHelp verifies that `xkey pin --help` prints usage information.
func TestIPC_PinHelp(t *testing.T) {
	h := NewFIDO2TestHelper(t)

	result := h.RunCommand("pin", "--help")
	require.True(t, result.Success(),
		"pin --help should succeed: %s", result.Combined())

	assert.True(t, result.OutputContains("pin") || result.OutputContains("PIN"),
		"PIN help output should mention 'pin' or 'PIN'")
}

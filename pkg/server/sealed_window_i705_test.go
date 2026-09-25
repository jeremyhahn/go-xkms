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

	"github.com/stretchr/testify/require"
)

// TestServeSealedWindow_InvalidTimeoutConfig proves an unparsable
// barrier.sealed_window_timeout is surfaced as an error immediately, before
// any listener is opened, rather than falling back to a default silently.
func TestServeSealedWindow_InvalidTimeoutConfig(t *testing.T) {
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "wrong-passphrase")
	defer func() { _ = node.Close() }()
	require.True(t, node.IsSealed(), "fixture: node must be sealed for this test")

	cfg := createMinimalConfig(t) // Server.Host is loopback
	cfg.Barrier.SealedWindowTimeout = "not-a-duration"
	s := testSealedWindowServer(t, cfg)

	err := s.serveSealedWindow(node)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a valid duration")
}

// TestSealedWindowBindError_RefusesNonLoopbackHost proves a non-loopback
// Server.Host with sealed_window_allow_remote unset is refused before the
// listener would ever bind, protecting the unauthenticated init-verb surface
// from unintended exposure.
func TestSealedWindowBindError_RefusesNonLoopbackHost(t *testing.T) {
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "wrong-passphrase")
	defer func() { _ = node.Close() }()
	require.True(t, node.IsSealed())

	cfg := createMinimalConfig(t)
	cfg.Server.Host = "0.0.0.0"
	s := testSealedWindowServer(t, cfg)

	err := s.serveSealedWindow(node)
	require.Error(t, err)
	var bindErr *SealedWindowBindError
	require.ErrorAs(t, err, &bindErr)
	require.Equal(t, "0.0.0.0", bindErr.Host)
}

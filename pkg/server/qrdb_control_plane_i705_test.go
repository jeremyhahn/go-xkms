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

	"google.golang.org/grpc"

	"github.com/stretchr/testify/require"
)

// TestRegisterQRDBControlPlane_NilNodeIsNoOp proves the guard against a
// not-yet-constructed node: registration must not panic or register
// anything when s.qrdbNode is nil.
func TestRegisterQRDBControlPlane_NilNodeIsNoOp(t *testing.T) {
	s := &Server{logger: custodyQuietLogger()}
	gs := grpc.NewServer()
	s.registerQRDBControlPlane(gs)
	require.Empty(t, gs.GetServiceInfo())
}

// TestRegisterQRDBControlPlane_NilServerIsNoOp proves a nil *grpc.Server
// argument is also guarded against, even with a real node.
func TestRegisterQRDBControlPlane_NilServerIsNoOp(t *testing.T) {
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "correct-horse-battery-staple")
	defer func() { _ = node.Close() }()

	s := &Server{logger: custodyQuietLogger(), qrdbNode: node}
	require.NotPanics(t, func() { s.registerQRDBControlPlane(nil) })
}

// TestRegisterQRDBControlPlane_RegistersAdminService proves a real node
// registers its control-plane services (at minimum Admin, which
// registerQRDBControlPlane always passes) onto the gRPC server.
func TestRegisterQRDBControlPlane_RegistersAdminService(t *testing.T) {
	dataDir := t.TempDir()
	node := newSealedTestNode(t, dataDir, "correct-horse-battery-staple", "correct-horse-battery-staple")
	defer func() { _ = node.Close() }()
	require.False(t, node.IsSealed())

	s := &Server{logger: custodyQuietLogger(), qrdbNode: node}
	gs := grpc.NewServer()

	s.registerQRDBControlPlane(gs)
	require.NotEmpty(t, gs.GetServiceInfo(), "the qrdb control plane must register at least the admin service")
}

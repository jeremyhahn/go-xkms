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

package main

import (
	"net"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/server"
)

// TestServe_RESTStartsWithAdminModule builds the server the way run() does,
// with the admin module mounted beside the xkms module, and with the REST
// transport on so both modules register their HTTP routes on the one router.
// The router refuses a second owner of a method and path, so a route both
// modules register (go-xkms#794: the /api/v1/tenants lifecycle) stops Start.
func TestServe_RESTStartsWithAdminModule(t *testing.T) {
	cfg := newServeTestConfig(t)
	cfg.Protocols.REST = true
	cfg.Server.RESTPort = freeLoopbackPort(t)

	adminModule, err := newAdminModule()
	if err != nil {
		t.Fatalf("newAdminModule: %v", err)
	}
	srv, err := server.New(cfg, server.WithExtraModules(adminModule))
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start with the admin module mounted: %v", err)
	}
	if err := srv.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// freeLoopbackPort returns a loopback TCP port that was free a moment ago.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on an ephemeral loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release the ephemeral port: %v", err)
	}
	return port
}

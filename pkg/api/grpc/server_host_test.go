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

package grpc

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// waitForListener polls until Start has bound the listener, which Port
// reports as the non-zero ephemeral port.
func waitForListener(t *testing.T, server *Server, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if server.Port() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("gRPC server did not bind within %v", timeout)
}

// TestServer_StartBindsConfiguredHost proves the listener binds the host the
// configuration names rather than every interface: with Host set to the
// loopback address the bound address is loopback, and the port is the
// ephemeral one the kernel chose (go-xkms#140, item 3).
func TestServer_StartBindsConfiguredHost(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	server, err := NewServer(&ServerConfig{
		Host:          "127.0.0.1",
		Port:          0,
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Start()
	}()
	defer func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	}()

	waitForListener(t, server, 5*time.Second)

	tcpAddr, ok := server.listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", server.listener.Addr())
	}
	if !tcpAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("listener bound %s, want the configured host 127.0.0.1", tcpAddr.IP)
	}
	if tcpAddr.Port == 0 || tcpAddr.Port != server.Port() {
		t.Fatalf("listener port %d, Port() %d: want the same non-zero ephemeral port", tcpAddr.Port, server.Port())
	}
}

// TestServer_StartRejectsUnbindableHost proves a host that cannot be bound
// surfaces as a typed listen error from Start instead of a silent fallback
// to the wildcard address.
func TestServer_StartRejectsUnbindableHost(t *testing.T) {
	setupXKMSForTest(t)
	defer xkms.Reset()

	server, err := NewServer(&ServerConfig{
		Host:          "192.0.2.1", // TEST-NET-1: never a local address, so bind fails without DNS
		Port:          0,
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}

	err = server.Start()
	if err == nil {
		t.Fatal("Start() error = nil, want a listen error for an unbindable host")
	}
	var wrapped *errs.Wrapped
	if !errors.As(err, &wrapped) {
		t.Fatalf("Start() error = %T (%v), want *errs.Wrapped", err, err)
	}
	if server.Port() != 0 {
		t.Fatalf("Port() = %d after a failed bind, want 0", server.Port())
	}
}

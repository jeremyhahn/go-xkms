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
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// TestBuildRESTConfig_TrustedProxies proves server.trusted_proxies reaches
// the REST rate limiters, and that the default trusts no proxy.
func TestBuildRESTConfig_TrustedProxies(t *testing.T) {
	restCfg, err := newTestServerForRESTConfig(t, config.ServerConfig{RESTPort: 8443}).buildRESTConfig()
	if err != nil {
		t.Fatalf("buildRESTConfig() error = %v", err)
	}
	if restCfg.TrustedProxies != nil {
		t.Fatalf("default TrustedProxies = %v, want nil (trust no proxy)", restCfg.TrustedProxies)
	}

	restCfg, err = newTestServerForRESTConfig(t, config.ServerConfig{
		RESTPort:       8443,
		TrustedProxies: []string{"10.0.0.0/8"},
	}).buildRESTConfig()
	if err != nil {
		t.Fatalf("buildRESTConfig() error = %v", err)
	}
	if !restCfg.TrustedProxies.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("configured proxy prefix did not reach rest.Config.TrustedProxies")
	}
}

// TestBuildRESTConfig_InvalidTrustedProxyFails proves a malformed entry fails
// composition instead of silently trusting nothing.
func TestBuildRESTConfig_InvalidTrustedProxyFails(t *testing.T) {
	_, err := newTestServerForRESTConfig(t, config.ServerConfig{
		RESTPort:       8443,
		TrustedProxies: []string{"lb.example.com"},
	}).buildRESTConfig()
	var invalid *ratelimit.InvalidTrustedProxyError
	if !errors.As(err, &invalid) {
		t.Fatalf("buildRESTConfig() error = %v, want *ratelimit.InvalidTrustedProxyError", err)
	}
}

// newSweeperTestServer builds the lifecycle state startWebAuthnSessionSweeper
// uses: the server context and wait group, and optionally a WebAuthn service.
func newSweeperTestServer(t *testing.T, withWebAuthn bool) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Server{ctx: ctx, cancel: cancel, logger: slog.Default()}
	if withWebAuthn {
		svc, err := webauthn.NewService(webauthn.ServiceParams{
			Config: &webauthn.Config{
				RPID:          "kms.example.com",
				RPDisplayName: "xkms",
				RPOrigins:     []string{"https://kms.example.com"},
			},
			UserStore:       webauthn.NewMemoryUserStore(),
			SessionStore:    webauthn.NewMemorySessionStore(),
			CredentialStore: webauthn.NewMemoryCredentialStore(),
		})
		if err != nil {
			t.Fatalf("webauthn.NewService: %v", err)
		}
		s.webauthnService = svc
	}
	return s
}

// joined reports whether s.wg drains within d.
func joined(s *Server, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// TestStartWebAuthnSessionSweeper_StopsOnShutdown proves the sweeper runs on
// a goroutine the server lifecycle owns: it is still running until the
// server context is cancelled, and then joins the wait group Shutdown waits
// on, so it does not leak.
func TestStartWebAuthnSessionSweeper_StopsOnShutdown(t *testing.T) {
	s := newSweeperTestServer(t, true)
	s.startWebAuthnSessionSweeper()

	if joined(s, 20*time.Millisecond) {
		t.Fatal("the sweeper exited before the server context was cancelled")
	}
	s.cancel()
	if !joined(s, 5*time.Second) {
		t.Fatal("the sweeper did not stop after the server context was cancelled")
	}
}

// TestStartWebAuthnSessionSweeper_NoWebAuthn proves no goroutine is started
// when WebAuthn is disabled.
func TestStartWebAuthnSessionSweeper_NoWebAuthn(t *testing.T) {
	s := newSweeperTestServer(t, false)
	s.startWebAuthnSessionSweeper()
	if !joined(s, time.Second) {
		t.Fatal("a sweeper was started without a WebAuthn service")
	}
}

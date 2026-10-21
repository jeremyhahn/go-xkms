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
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
)

// newTestServerForRESTConfig builds the minimal Server state buildRESTConfig
// reads, without the New() constructor's filesystem and backend setup.
func newTestServerForRESTConfig(t *testing.T, serverCfg config.ServerConfig) *Server {
	t.Helper()
	return &Server{
		config: &config.Config{
			Server: serverCfg,
		},
		logger: slog.Default(),
	}
}

// TestBuildRESTConfig_CarriesConfiguredHost proves the resolved server.host
// reaches the REST listener configuration. Before go-xkms#140 the field was
// never populated, so a configured host was discarded and the in-process
// REST listener bound every interface.
func TestBuildRESTConfig_CarriesConfiguredHost(t *testing.T) {
	srv := newTestServerForRESTConfig(t, config.ServerConfig{
		Host:     "10.0.0.5",
		RESTPort: 8443,
	})

	restCfg, err := srv.buildRESTConfig()
	if err != nil {
		t.Fatalf("buildRESTConfig() error = %v", err)
	}
	if restCfg.Host != "10.0.0.5" {
		t.Fatalf("rest.Config.Host = %q, want the configured server.host 10.0.0.5", restCfg.Host)
	}
	if restCfg.Port != 8443 {
		t.Fatalf("rest.Config.Port = %d, want 8443", restCfg.Port)
	}
}

// TestBuildRESTConfig_DefaultHostBindsAllInterfaces proves the defaults-layer
// host passes through unchanged: the REST listener then binds every
// interface because the configuration says so, not because a literal does.
func TestBuildRESTConfig_DefaultHostBindsAllInterfaces(t *testing.T) {
	srv := newTestServerForRESTConfig(t, config.ServerConfig{
		Host:     config.DefaultServerHost,
		RESTPort: 8443,
	})

	restCfg, err := srv.buildRESTConfig()
	if err != nil {
		t.Fatalf("buildRESTConfig() error = %v", err)
	}
	if restCfg.Host != config.DefaultServerHost {
		t.Fatalf("rest.Config.Host = %q, want the defaults-layer host %q", restCfg.Host, config.DefaultServerHost)
	}
}

// TestBuildRESTConfig_DisabledPIVLoginLeavesItsAnchorsUnloaded proves a
// disabled cert-login block is inert, as validation treats it: a stale or bad
// attestation_roots path under piv_login.enabled=false must not fail the
// daemon's composition, and an enabled block with a bad path must.
func TestBuildRESTConfig_DisabledPIVLoginLeavesItsAnchorsUnloaded(t *testing.T) {
	newServer := func(enabled bool) *Server {
		srv := newTestServerForRESTConfig(t, config.ServerConfig{Host: "127.0.0.1", RESTPort: 8443})
		srv.tokenIssuer = newTestTokenIssuer(t)
		srv.config.Auth.PIVLogin = &config.PIVLoginConfig{
			Enabled:          enabled,
			AttestationRoots: "/nonexistent/piv-attestation-root.pem",
		}
		return srv
	}

	restCfg, err := newServer(false).buildRESTConfig()
	if err != nil {
		t.Fatalf("buildRESTConfig() with piv_login disabled: %v", err)
	}
	if restCfg.PIVLogin == nil || restCfg.PIVLogin.Enabled || restCfg.PIVLogin.AttestationRoots != nil {
		t.Fatalf("disabled piv_login must be carried disabled with no anchors, got %+v", restCfg.PIVLogin)
	}

	if _, err := newServer(true).buildRESTConfig(); err == nil {
		t.Fatal("buildRESTConfig() with piv_login enabled and an unloadable bundle must fail")
	}
}

// TestBuildRESTConfig_PIVLoginPinsTheServerTrustDomain proves the cert-login
// exchange reads a certificate's tenant under the same SPIFFE trust domain
// the daemon issues under (go-xkms#1628), not an unpinned one.
func TestBuildRESTConfig_PIVLoginPinsTheServerTrustDomain(t *testing.T) {
	for _, tc := range []struct {
		name        string
		trustDomain string
		want        string
	}{
		{name: "configured", trustDomain: "corp.example", want: "corp.example"},
		{name: "default", trustDomain: "", want: embeddednode.DefaultTrustDomain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServerForRESTConfig(t, config.ServerConfig{Host: "127.0.0.1", RESTPort: 8443})
			srv.tokenIssuer = newTestTokenIssuer(t)
			srv.config.Cluster.RaftEnrollment.TrustDomain = tc.trustDomain
			srv.config.Auth.PIVLogin = &config.PIVLoginConfig{}

			restCfg, err := srv.buildRESTConfig()
			if err != nil {
				t.Fatalf("buildRESTConfig(): %v", err)
			}
			if restCfg.PIVLogin == nil || restCfg.PIVLogin.TrustDomain != tc.want {
				t.Fatalf("PIVLogin.TrustDomain = %+v, want %q", restCfg.PIVLogin, tc.want)
			}
		})
	}
}

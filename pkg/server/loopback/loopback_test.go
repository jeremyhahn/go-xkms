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

package loopback

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

func TestLaunch_RequiresConfig(t *testing.T) {
	_, err := Launch(context.Background(), Options{})
	if err == nil {
		t.Fatal("expected error when config is nil")
	}
	var le *LaunchError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LaunchError, got %T", err)
	}
}

func TestDesktopConfig_ForcesLoopbackRESTOnly(t *testing.T) {
	// desktopConfig is the pure transformation at the heart of the launcher;
	// verify it pins loopback + REST-only without mutating the source.
	src := &config.Config{}
	src.Server.Host = "0.0.0.0"
	src.Server.RESTPort = 8443
	src.Protocols.GRPC = true
	src.Protocols.QUIC = true
	src.Protocols.Unix = true

	cfg := desktopConfig(src, 54321)

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1", cfg.Server.Host)
	}
	if cfg.Server.RESTPort != 54321 {
		t.Errorf("port = %d, want 54321", cfg.Server.RESTPort)
	}
	if !cfg.Protocols.REST {
		t.Error("REST must be enabled")
	}
	if cfg.Protocols.GRPC || cfg.Protocols.QUIC || cfg.Protocols.Unix ||
		cfg.Protocols.MCP || cfg.Protocols.Noise {
		t.Errorf("only REST may be enabled, got %+v", cfg.Protocols)
	}
	// LoopbackDesktop must be set: it is the signal config.Config.Validate
	// reads to skip the storage.backend "qrdb" + tls.enabled requirement
	// NodeServing otherwise imposes now that Protocols.REST is true
	// (go-xkms#666).
	if !cfg.LoopbackDesktop {
		t.Error("LoopbackDesktop must be set so Validate exempts this launch shape")
	}
	// Source must be untouched.
	if src.Server.Host != "0.0.0.0" || !src.Protocols.GRPC {
		t.Error("desktopConfig mutated the source config")
	}
	if src.LoopbackDesktop {
		t.Error("desktopConfig must not set LoopbackDesktop on the source config")
	}
}

func TestItoa(t *testing.T) {
	cases := map[int]string{0: "0", 7: "7", 54321: "54321", 8443: "8443"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestDesktopOwnerIdentity_HoldsSystemAdminRoleID pins the token identity to
// go-qrdb's Admin@system role ID: Identity.Roles carries IDs, so a bare role
// name there would resolve to no role at all.
func TestDesktopOwnerIdentity_HoldsSystemAdminRoleID(t *testing.T) {
	id := desktopOwnerIdentity()

	if id.TenantID != qrdbsdk.SystemTenantID {
		t.Errorf("TenantID = %q, want %q", id.TenantID, qrdbsdk.SystemTenantID)
	}
	want := qrdbsdk.SystemRoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAdmin)
	if len(id.Roles) != 1 || id.Roles[0] != want {
		t.Fatalf("Roles = %v, want [%s]", id.Roles, want)
	}
}

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

package config

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/escrow"
)

// TestLoad_Escrow_NotDeclared proves that a config file with no escrow
// section leaves cfg.Escrow nil, exactly like every other optional pointer
// section (ACME, Trust, Backends.AWSKMS): escrow.NewRegistryFromConfig
// depends on this to no-op when the operator never configured escrow.
func TestLoad_Escrow_NotDeclared(t *testing.T) {
	cfg, err := Load(writeServerConfig(t, ""))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Escrow != nil {
		t.Fatalf("Escrow = %+v, want nil", cfg.Escrow)
	}
}

// TestLoad_Escrow_Enabled proves the escrow section round-trips through
// Load into escrow.Config, ready to hand to escrow.NewRegistryFromConfig.
func TestLoad_Escrow_Enabled(t *testing.T) {
	cfg, err := Load(writeConfigBody(t, "", `
escrow:
  enabled: true
  agents:
    - type: "xkms"
      name: "dr-site"
      endpoint: "https://dr-xkms.example.com:8443"
      client_cert: "/etc/xkms/certs/client.pem"
      client_key: "/etc/xkms/certs/client-key.pem"
      ca_cert: "/etc/xkms/certs/ca.pem"
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Escrow == nil || !cfg.Escrow.Enabled {
		t.Fatalf("Escrow = %+v, want Enabled true", cfg.Escrow)
	}
	if len(cfg.Escrow.Agents) != 1 {
		t.Fatalf("Escrow.Agents = %+v, want 1 entry", cfg.Escrow.Agents)
	}
	agent := cfg.Escrow.Agents[0]
	if agent.Type != escrow.AgentTypeXKMS || agent.Name != "dr-site" || agent.Endpoint != "https://dr-xkms.example.com:8443" {
		t.Fatalf("Escrow.Agents[0] = %+v, want type=xkms name=dr-site endpoint=https://dr-xkms.example.com:8443", agent)
	}
}

// TestConfig_Validate_EscrowEnabledNoAgents proves Validate rejects an
// escrow section that turns escrow on without configuring any agents,
// mirroring how ACMEConfig.Validate rejects an incomplete enabled section.
// Load runs Validate internally, so the error surfaces straight from Load.
func TestConfig_Validate_EscrowEnabledNoAgents(t *testing.T) {
	_, err := Load(writeConfigBody(t, "", `
escrow:
  enabled: true
`))
	if err == nil {
		t.Fatal("Load() error = nil, want ErrNoAgentsConfigured")
	}
	if !errors.Is(err, escrow.ErrNoAgentsConfigured) {
		t.Fatalf("Load() error = %v, want ErrNoAgentsConfigured", err)
	}
}

// TestConfig_Validate_EscrowDisabledIsNoop proves a disabled (or absent)
// escrow section never blocks Validate, regardless of its contents.
func TestConfig_Validate_EscrowDisabledIsNoop(t *testing.T) {
	cfg, err := Load(writeServerConfig(t, ""))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

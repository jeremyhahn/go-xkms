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

package config_test

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// sdkMCPPort is the port an SDK client with no MCP address dials.
func sdkMCPPort(t *testing.T) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(xkms.DefaultMCPAddress)
	if err != nil {
		t.Fatalf("split %q: %v", xkms.DefaultMCPAddress, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return port
}

func TestMCPPort_DefaultsMatchSDK(t *testing.T) {
	want := sdkMCPPort(t)
	if got := config.Defaults().Server.MCPPort; got != want {
		t.Fatalf("Defaults().Server.MCPPort = %d, want SDK default %d", got, want)
	}
}

func TestMCPPort_ShippedConfigsMatchSDK(t *testing.T) {
	want := sdkMCPPort(t)
	for _, name := range []string{
		"xkmsd.yaml",
		"xkmsd-dev.yaml",
		"xkmsd-local.yaml",
		"xkmsd-integration.yaml",
		"xkmsd.yaml.example",
	} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "configs", name))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var doc struct {
				Server struct {
					MCPPort int `yaml:"mcp_port"`
				} `yaml:"server"`
			}
			if err := yaml.Unmarshal(data, &doc); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if doc.Server.MCPPort != want {
				t.Fatalf("server.mcp_port = %d, want SDK default %d", doc.Server.MCPPort, want)
			}
		})
	}
}

func TestMCPPort_LoadOmittedUsesSDKDefault(t *testing.T) {
	content := `
server:
  rest_port: 8443
  grpc_port: 9443

protocols:
  rest: true
  grpc: true
  mcp: true

logging:
  level: "info"
  format: "json"

tls:
  enabled: true

auth:
  enabled: false

datastore:
  engine: "pebble"
  path: "/data"

default_backend: "pkcs8"

backends:
  pkcs8:
    enabled: true
    path: "/data/pkcs8"
`
	path := filepath.Join(t.TempDir(), "xkmsd.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if want := sdkMCPPort(t); cfg.Server.MCPPort != want {
		t.Fatalf("Server.MCPPort = %d, want SDK default %d", cfg.Server.MCPPort, want)
	}
}

func TestMCPPort_SDKDefaultDiffersFromNoiseDefault(t *testing.T) {
	if got := strconv.Itoa(sdkMCPPort(t)); got == bootstrap.DefaultNoisePort {
		t.Fatalf("SDK MCP default %s collides with bootstrap.DefaultNoisePort", got)
	}
}

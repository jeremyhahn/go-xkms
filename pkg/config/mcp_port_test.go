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
	"strings"
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

// TestMCPPort_DevcontainerComposeMatchesSDK checks the devcontainer stack: the
// xkms-server image runs configs/xkmsd-integration.yaml, so the clients' MCP
// address and the published MCP port must name the same port as the SDK.
func TestMCPPort_DevcontainerComposeMatchesSDK(t *testing.T) {
	want := strconv.Itoa(sdkMCPPort(t))
	data, err := os.ReadFile(filepath.Join("..", "..", "build", "docker", "devcontainer", "compose.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc struct {
		Services map[string]struct {
			// Services write environment as a list or a map; only the
			// devcontainer's list form is decoded below.
			Environment yaml.Node `yaml:"environment"`
			Ports       []string  `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var env []string
	devcontainer := doc.Services["devcontainer"].Environment
	if err := devcontainer.Decode(&env); err != nil {
		t.Fatalf("devcontainer environment: %v", err)
	}

	addr := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "KEYSTORE_MCP_ADDR="); ok {
			addr = v
		}
	}
	if addr == "" {
		t.Fatal("devcontainer: KEYSTORE_MCP_ADDR not set")
	}
	if _, port, err := net.SplitHostPort(addr); err != nil || port != want {
		t.Fatalf("devcontainer KEYSTORE_MCP_ADDR = %q, want port %s", addr, want)
	}

	published := false
	for _, p := range doc.Services["xkms-server"].Ports {
		if strings.Contains(p, "XKMS_HOST_MCP_PORT") {
			published = true
			if i := strings.LastIndex(p, ":"); i < 0 || p[i+1:] != want {
				t.Fatalf("xkms-server MCP port mapping = %q, want container port %s", p, want)
			}
		}
	}
	if !published {
		t.Fatal("xkms-server: no XKMS_HOST_MCP_PORT mapping")
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

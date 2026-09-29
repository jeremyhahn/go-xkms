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

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
)

// TestServerTrustedProxies_YAML pins the wire name and the secure default.
func TestServerTrustedProxies_YAML(t *testing.T) {
	if got := Defaults().Server.TrustedProxies; len(got) != 0 {
		t.Fatalf("server.trusted_proxies default = %v, want empty (trust no proxy)", got)
	}

	var c Config
	src := "server:\n  trusted_proxies:\n    - 10.0.0.1\n    - 10.1.0.0/16\n"
	if err := yaml.Unmarshal([]byte(src), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(c.Server.TrustedProxies) != 2 || c.Server.TrustedProxies[1] != "10.1.0.0/16" {
		t.Fatalf("server.trusted_proxies = %v", c.Server.TrustedProxies)
	}
}

// TestValidate_TrustedProxies accepts addresses and prefixes and refuses a
// malformed entry at load time rather than silently trusting nothing.
func TestValidate_TrustedProxies(t *testing.T) {
	c := Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
		TLS:       TLSConfig{Enabled: true},
		Default:   "pkcs8",
		Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
	}
	c.Server.TrustedProxies = []string{"10.0.0.1", "2001:db8::/32"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() with valid trusted proxies = %v", err)
	}

	c.Server.TrustedProxies = []string{"lb.example.com"}
	err := c.Validate()
	var invalid *ratelimit.InvalidTrustedProxyError
	if !errors.As(err, &invalid) || invalid.Entry != "lb.example.com" {
		t.Fatalf("Validate() with a hostname entry = %v, want *ratelimit.InvalidTrustedProxyError", err)
	}
}

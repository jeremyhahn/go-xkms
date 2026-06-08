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
)

func TestClusterConfig_Members(t *testing.T) {
	c := ClusterConfig{Peers: "1=10.0.0.1:63001, 2=10.0.0.2:63001 ,3=10.0.0.3:63001"}
	m, err := c.Members()
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(m) != 3 || m[1] != "10.0.0.1:63001" || m[2] != "10.0.0.2:63001" || m[3] != "10.0.0.3:63001" {
		t.Fatalf("Members = %v, want 3 entries", m)
	}
}

func TestClusterConfig_Members_Invalid(t *testing.T) {
	for _, peers := range []string{"badform", "0=10.0.0.1:63001", "1=", "x=10.0.0.1:63001"} {
		if _, err := (ClusterConfig{Peers: peers}).Members(); err == nil {
			t.Fatalf("Members(%q) = nil error, want error", peers)
		}
	}
}

// clusterBaseConfig returns a Config that passes Validate with clustering on.
func clusterBaseConfig() Config {
	return Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Storage:   StorageConfig{Backend: "qrdb", Path: "/data"},
		Default:   "pkcs8",
		Backends:  BackendsConfig{PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"}},
		Cluster: ClusterConfig{
			Enabled:     true,
			NodeID:      1,
			RaftAddress: "10.0.0.1:63001",
			Peers:       "1=10.0.0.1:63001,2=10.0.0.2:63001",
		},
	}
}

func TestValidate_ClusterValid(t *testing.T) {
	c := clusterBaseConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(valid cluster) = %v, want nil", err)
	}
	if c.Cluster.ShardID != 1 {
		t.Fatalf("ShardID defaulted to %d, want 1", c.Cluster.ShardID)
	}
}

func TestValidate_ClusterRequiresQRDB(t *testing.T) {
	c := clusterBaseConfig()
	c.Storage.Backend = "pebble"
	if err := c.Validate(); err == nil {
		t.Fatal("Validate(cluster + pebble) = nil, want error (requires qrdb)")
	}
}

func TestValidate_ClusterRequiresNodeIDAndAddress(t *testing.T) {
	c := clusterBaseConfig()
	c.Cluster.NodeID = 0
	if err := c.Validate(); err == nil {
		t.Fatal("Validate(cluster, node_id 0) = nil, want error")
	}
	c = clusterBaseConfig()
	c.Cluster.RaftAddress = ""
	if err := c.Validate(); err == nil {
		t.Fatal("Validate(cluster, no raft_address) = nil, want error")
	}
}

func TestValidate_ClusterBootstrapMustIncludeSelf(t *testing.T) {
	c := clusterBaseConfig()
	c.Cluster.Peers = "2=10.0.0.2:63001,3=10.0.0.3:63001" // missing node 1 (self)
	if err := c.Validate(); err == nil {
		t.Fatal("Validate(bootstrap without self in peers) = nil, want error")
	}
	// Join mode does not require self in the initial peer list.
	c.Cluster.Join = true
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(join without self) = %v, want nil", err)
	}
}

func TestApplyEnvOverrides_Cluster(t *testing.T) {
	t.Setenv("XKMS_CLUSTER_ENABLED", "true")
	t.Setenv("XKMS_CLUSTER_NODE_ID", "7")
	t.Setenv("XKMS_CLUSTER_RAFT_ADDRESS", "10.1.2.3:63001")
	t.Setenv("XKMS_CLUSTER_PEERS", "7=10.1.2.3:63001")
	t.Setenv("XKMS_CLUSTER_JOIN", "true")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	if !cfg.Cluster.Enabled || cfg.Cluster.NodeID != 7 ||
		cfg.Cluster.RaftAddress != "10.1.2.3:63001" || cfg.Cluster.Peers != "7=10.1.2.3:63001" || !cfg.Cluster.Join {
		t.Fatalf("env overrides not applied: %+v", cfg.Cluster)
	}
}

func TestRaftTLSConfig_EnabledAndComplete(t *testing.T) {
	tests := []struct {
		name     string
		cfg      RaftTLSConfig
		enabled  bool
		complete bool
	}{
		{
			name:     "all empty (disabled)",
			cfg:      RaftTLSConfig{},
			enabled:  false,
			complete: true,
		},
		{
			name:     "all set (enabled)",
			cfg:      RaftTLSConfig{CACertFile: "ca.pem", CertFile: "c.pem", KeyFile: "k.pem"},
			enabled:  true,
			complete: true,
		},
		{
			name:     "missing key",
			cfg:      RaftTLSConfig{CACertFile: "ca.pem", CertFile: "c.pem"},
			enabled:  false,
			complete: false,
		},
		{
			name:     "only ca",
			cfg:      RaftTLSConfig{CACertFile: "ca.pem"},
			enabled:  false,
			complete: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.Enabled(); got != tt.enabled {
				t.Errorf("Enabled() = %v, want %v", got, tt.enabled)
			}
			if got := tt.cfg.IsComplete(); got != tt.complete {
				t.Errorf("IsComplete() = %v, want %v", got, tt.complete)
			}
		})
	}
}

func TestValidate_ClusterRaftTLSComplete(t *testing.T) {
	c := clusterBaseConfig()
	c.Cluster.RaftTLS = RaftTLSConfig{
		CACertFile: "/etc/xkms/raft-ca.pem",
		CertFile:   "/etc/xkms/raft-cert.pem",
		KeyFile:    "/etc/xkms/raft-key.pem",
	}
	// Files need not exist at validation time; validation only checks completeness.
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(complete raft_tls) = %v, want nil", err)
	}
}

func TestValidate_ClusterRaftTLSPartial(t *testing.T) {
	c := clusterBaseConfig()
	c.Cluster.RaftTLS = RaftTLSConfig{
		CACertFile: "/etc/xkms/raft-ca.pem",
		CertFile:   "/etc/xkms/raft-cert.pem",
		// KeyFile intentionally omitted.
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate(partial raft_tls) = nil, want error")
	}
	if !errors.Is(err, ErrClusterRaftTLSIncomplete) {
		t.Fatalf("Validate(partial raft_tls) = %v, want ErrClusterRaftTLSIncomplete", err)
	}
}

func TestValidate_ClusterRaftTLSIgnoredWhenDisabled(t *testing.T) {
	// A partial raft_tls on a non-clustered config is never reached.
	c := clusterBaseConfig()
	c.Cluster.Enabled = false
	c.Cluster.RaftTLS = RaftTLSConfig{CACertFile: "only-ca.pem"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(disabled cluster, partial raft_tls) = %v, want nil", err)
	}
}

func TestApplyEnvOverrides_ClusterRaftTLS(t *testing.T) {
	t.Setenv("XKMS_CLUSTER_RAFT_CA_CERT", "/env/ca.pem")
	t.Setenv("XKMS_CLUSTER_RAFT_CERT", "/env/cert.pem")
	t.Setenv("XKMS_CLUSTER_RAFT_KEY", "/env/key.pem")

	cfg := &Config{}
	applyEnvOverrides(cfg)

	if cfg.Cluster.RaftTLS.CACertFile != "/env/ca.pem" ||
		cfg.Cluster.RaftTLS.CertFile != "/env/cert.pem" ||
		cfg.Cluster.RaftTLS.KeyFile != "/env/key.pem" {
		t.Fatalf("raft_tls env overrides not applied: %+v", cfg.Cluster.RaftTLS)
	}
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package qrdb

import (
	"time"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Protocol identifies the transport protocol used to connect to QRDB.
type Protocol string

const (
	// ProtocolEmbedded runs QRDB in-process via the embedded transport.
	ProtocolEmbedded Protocol = "embedded"
	// ProtocolGRPC connects to QRDB via gRPC.
	ProtocolGRPC Protocol = "grpc"
	// ProtocolREST connects to QRDB via HTTP/2 REST.
	ProtocolREST Protocol = "rest"
	// ProtocolQUIC connects to QRDB via QUIC.
	ProtocolQUIC Protocol = "quic"
	// ProtocolUnix connects to QRDB via a Unix domain socket.
	ProtocolUnix Protocol = "unix"
	// ProtocolMCP connects to QRDB via the MCP protocol.
	ProtocolMCP Protocol = "mcp"
)

// validProtocols provides O(1) lookup for protocol validation.
var validProtocols = map[Protocol]struct{}{
	ProtocolEmbedded: {},
	ProtocolGRPC:     {},
	ProtocolREST:     {},
	ProtocolQUIC:     {},
	ProtocolUnix:     {},
	ProtocolMCP:      {},
}

// Mode identifies the QRDB operating mode.
type Mode string

const (
	// ModeStandalone runs a single QRDB node without Raft consensus.
	ModeStandalone Mode = "standalone"
	// ModeRaft runs QRDB with Raft consensus for distributed replication.
	ModeRaft Mode = "raft"
)

// validModes provides O(1) lookup for mode validation.
var validModes = map[Mode]struct{}{
	ModeStandalone: {},
	ModeRaft:       {},
}

const (
	defaultTimeout      = 30 * time.Second
	defaultGracePeriod  = 15 * time.Second
	defaultDrainTimeout = 10 * time.Second
)

// Config holds the QRDB service configuration.
type Config struct {
	// Mode is the QRDB operating mode (standalone or raft).
	Mode Mode `json:"mode" yaml:"mode"`

	// Protocol is the transport protocol to use.
	Protocol Protocol `json:"protocol" yaml:"protocol"`

	// Address is the server address for remote protocols (e.g., "localhost:63002").
	Address string `json:"address" yaml:"address"`

	// UnixSocketPath is the path to the Unix domain socket for ProtocolUnix.
	UnixSocketPath string `json:"unix_socket_path" yaml:"unix_socket_path"`

	// DataDir is the directory for QRDB data storage in embedded mode.
	DataDir string `json:"data_dir" yaml:"data_dir"`

	// ClusterID is the Raft cluster identifier.
	ClusterID uint64 `json:"cluster_id" yaml:"cluster_id"`

	// NodeID is the Raft node identifier.
	NodeID uint64 `json:"node_id" yaml:"node_id"`

	// Raft holds Raft-specific configuration. Only used when Mode is ModeRaft.
	Raft *RaftConfig `json:"raft,omitempty" yaml:"raft,omitempty"`

	// ClientTLS holds TLS configuration for client connections.
	ClientTLS *TLSClientConfig `json:"client_tls,omitempty" yaml:"client_tls,omitempty"`

	// Timeout is the default request timeout.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`

	// Shutdown holds graceful shutdown configuration.
	Shutdown *ShutdownConfig `json:"shutdown,omitempty" yaml:"shutdown,omitempty"`

	// Barrier holds barrier/seal configuration for embedded mode.
	// Ignored in remote mode (barrier managed by the QRDB server).
	Barrier *BarrierConfig `json:"barrier,omitempty" yaml:"barrier,omitempty"`
}

// RaftConfig holds Raft consensus configuration.
type RaftConfig struct {
	// Members maps replica ID to Raft network address for initial cluster.
	Members map[uint64]string `json:"members" yaml:"members"`

	// ElectionRTT is the number of RTTs for election timeout.
	ElectionRTT uint64 `json:"election_rtt" yaml:"election_rtt"`

	// HeartbeatRTT is the number of RTTs for heartbeat interval.
	HeartbeatRTT uint64 `json:"heartbeat_rtt" yaml:"heartbeat_rtt"`

	// SnapshotEntries is the number of log entries between snapshots.
	SnapshotEntries uint64 `json:"snapshot_entries" yaml:"snapshot_entries"`

	// CompactionOverhead is the number of entries to keep after compaction.
	CompactionOverhead uint64 `json:"compaction_overhead" yaml:"compaction_overhead"`
}

// TLSClientConfig holds TLS configuration for client connections.
type TLSClientConfig struct {
	// CertFile is the path to the client TLS certificate.
	CertFile string `json:"cert_file" yaml:"cert_file"`

	// KeyFile is the path to the client TLS private key.
	KeyFile string `json:"key_file" yaml:"key_file"`

	// CAFile is the path to the CA certificate for server verification.
	CAFile string `json:"ca_file" yaml:"ca_file"`

	// ServerName is the expected server name for TLS verification.
	ServerName string `json:"server_name" yaml:"server_name"`
}

// ShutdownConfig holds graceful shutdown configuration.
type ShutdownConfig struct {
	// GracePeriod is the maximum time to wait for in-flight requests.
	GracePeriod time.Duration `json:"grace_period" yaml:"grace_period"`

	// DrainTimeout is the maximum time to wait for drain completion.
	DrainTimeout time.Duration `json:"drain_timeout" yaml:"drain_timeout"`

	// TransferLeader enables leader transfer during shutdown.
	TransferLeader bool `json:"transfer_leader" yaml:"transfer_leader"`
}

// BarrierConfig controls the encryption barrier for embedded QRDB mode.
type BarrierConfig struct {
	// Enabled controls whether the barrier is active.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Strategy identifies the sealing strategy.
	Strategy xkmssdk.QRDBStrategyID `json:"strategy" yaml:"strategy"`

	// Shamir holds M-of-N secret sharing configuration.
	// Required when Strategy is seal.StrategyShamir.
	Shamir *ShamirConfig `json:"shamir,omitempty" yaml:"shamir,omitempty"`
}

// ShamirConfig controls M-of-N secret sharing parameters.
type ShamirConfig struct {
	// Threshold is the minimum number of shares needed to unseal (M).
	Threshold int `json:"threshold" yaml:"threshold"`

	// Total is the total number of shares generated (N).
	Total int `json:"total" yaml:"total"`
}

// DefaultConfig returns a Config with sensible defaults for embedded
// standalone mode.
func DefaultConfig() *Config {
	return &Config{
		Mode:     ModeStandalone,
		Protocol: ProtocolEmbedded,
		DataDir:  "data/qrdb",
		Timeout:  defaultTimeout,
		Shutdown: &ShutdownConfig{
			GracePeriod:    defaultGracePeriod,
			DrainTimeout:   defaultDrainTimeout,
			TransferLeader: true,
		},
	}
}

// Validate checks the configuration for consistency and returns an error
// if the configuration is invalid.
func (c *Config) Validate() error {
	if _, ok := validModes[c.Mode]; !ok {
		return NewError(ErrorCodeInvalidConfig, "invalid mode").
			WithContext("mode", string(c.Mode))
	}
	if _, ok := validProtocols[c.Protocol]; !ok {
		return NewError(ErrorCodeInvalidConfig, "invalid protocol").
			WithContext("protocol", string(c.Protocol))
	}

	// Remote protocols require an address.
	if c.Protocol != ProtocolEmbedded {
		if c.Protocol == ProtocolUnix {
			if c.UnixSocketPath == "" {
				return NewError(ErrorCodeInvalidConfig, "unix_socket_path is required for unix protocol")
			}
		} else if c.Address == "" {
			return NewError(ErrorCodeInvalidConfig, "address is required for remote protocols").
				WithContext("protocol", string(c.Protocol))
		}
	}

	// Embedded mode requires a data directory.
	if c.Protocol == ProtocolEmbedded && c.DataDir == "" {
		return NewError(ErrorCodeInvalidConfig, "data_dir is required for embedded protocol")
	}

	// TLS validation: cert and key must be provided together.
	if c.ClientTLS != nil {
		if c.ClientTLS.CertFile != "" && c.ClientTLS.KeyFile == "" {
			return NewError(ErrorCodeInvalidConfig, "key_file is required when cert_file is specified")
		}
		if c.ClientTLS.KeyFile != "" && c.ClientTLS.CertFile == "" {
			return NewError(ErrorCodeInvalidConfig, "cert_file is required when key_file is specified")
		}
	}

	// Raft mode requires node and cluster IDs.
	if c.Mode == ModeRaft {
		if c.NodeID == 0 {
			return NewError(ErrorCodeInvalidConfig, "node_id is required for raft mode")
		}
		if c.ClusterID == 0 {
			return NewError(ErrorCodeInvalidConfig, "cluster_id is required for raft mode")
		}
	}

	return nil
}

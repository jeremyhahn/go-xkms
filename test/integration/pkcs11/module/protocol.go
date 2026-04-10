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

//go:build integration
// +build integration

// Package module provides multi-protocol integration tests for the PKCS#11 module.
//
// This file defines the protocol abstraction layer that enables testing the PKCS#11
// module against multiple transport protocols (Unix gRPC over UDS, gRPC over TCP).
// All tests use a common set of operations tested consistently across protocols.
package module

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// ProtocolType represents the transport protocol for PKCS#11 module communication.
type ProtocolType string

// Supported PKCS#11 module protocols.
// The module uses gRPC for both protocols - only the transport layer differs.
const (
	// ProtocolUnix represents gRPC over Unix Domain Socket.
	// Target format: unix:///path/to/socket.sock
	ProtocolUnix ProtocolType = "unix"

	// ProtocolGRPC represents gRPC over TCP.
	// Target format: host:port or dns:///host:port
	ProtocolGRPC ProtocolType = "grpc"
)

// String returns the string representation of the protocol.
func (p ProtocolType) String() string {
	return string(p)
}

// AllProtocols returns all supported PKCS#11 module protocols.
func AllProtocols() []ProtocolType {
	return []ProtocolType{
		ProtocolUnix,
		ProtocolGRPC,
	}
}

// RemoteProtocols returns protocols that require a remote server.
// Both Unix and gRPC require a running xkmsd server.
func RemoteProtocols() []ProtocolType {
	return []ProtocolType{
		ProtocolUnix,
		ProtocolGRPC,
	}
}

// ProtocolConfig holds configuration for a specific protocol.
type ProtocolConfig struct {
	// Protocol is the transport protocol type.
	Protocol ProtocolType

	// Target is the gRPC target address.
	// For Unix: unix:///path/to/socket.sock
	// For gRPC: host:port or dns:///host:port
	Target string

	// TLSEnabled indicates if TLS should be used (gRPC only).
	TLSEnabled bool

	// TLSCertFile is the client certificate path for mTLS.
	TLSCertFile string

	// TLSKeyFile is the client key path for mTLS.
	TLSKeyFile string

	// TLSCAFile is the CA certificate path.
	TLSCAFile string

	// Timeout is the operation timeout.
	Timeout time.Duration
}

// DefaultProtocolConfig returns a default configuration for the specified protocol.
func DefaultProtocolConfig(protocol ProtocolType) *ProtocolConfig {
	cfg := &ProtocolConfig{
		Protocol: protocol,
		Timeout:  30 * time.Second,
	}

	switch protocol {
	case ProtocolUnix:
		cfg.Target = getEnvOrDefault("XKMS_UNIX_SOCKET", "/var/run/xkms/xkms.sock")
		if !hasPrefix(cfg.Target, "unix://") {
			cfg.Target = "unix://" + cfg.Target
		}
	case ProtocolGRPC:
		cfg.Target = getEnvOrDefault("XKMS_GRPC_ADDR", "localhost:9443")
		cfg.TLSEnabled = getEnvBool("XKMS_GRPC_TLS_ENABLED", false)
		cfg.TLSCAFile = getEnvOrDefault("XKMS_GRPC_TLS_CA", "/etc/xkms/certs/ca.crt")
		cfg.TLSCertFile = os.Getenv("XKMS_GRPC_TLS_CERT")
		cfg.TLSKeyFile = os.Getenv("XKMS_GRPC_TLS_KEY")
		cfg.TLSCAFile = os.Getenv("XKMS_GRPC_TLS_CA")
	}

	return cfg
}

// ToModuleConfig converts the protocol config to a PKCS#11 module config.
func (pc *ProtocolConfig) ToModuleConfig() *module.Config {
	return &module.Config{
		Target:  pc.Target,
		Timeout: pc.Timeout,
		TLS: module.TLSConfig{
			Enabled:  pc.TLSEnabled,
			CertFile: pc.TLSCertFile,
			KeyFile:  pc.TLSKeyFile,
			CAFile:   pc.TLSCAFile,
		},
	}
}

// IsAvailable checks if the protocol endpoint is available.
func (pc *ProtocolConfig) IsAvailable() bool {
	switch pc.Protocol {
	case ProtocolUnix:
		return isUnixSocketAvailable(pc.Target)
	case ProtocolGRPC:
		return isTCPAvailable(pc.Target)
	default:
		return false
	}
}

// isUnixSocketAvailable checks if a Unix socket exists and is accessible.
func isUnixSocketAvailable(target string) bool {
	socketPath := target
	if hasPrefix(socketPath, "unix://") {
		socketPath = socketPath[7:]
	}

	info, err := os.Stat(socketPath)
	if err != nil {
		return false
	}

	// Check if it's a socket
	return info.Mode()&os.ModeSocket != 0
}

// isTCPAvailable checks if a TCP endpoint is reachable.
func isTCPAvailable(target string) bool {
	// Strip dns:// prefix if present
	addr := target
	if hasPrefix(addr, "dns://") {
		addr = addr[6:]
		if hasPrefix(addr, "/") {
			addr = addr[1:]
		}
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ProtocolTestCase represents a test case that runs across protocols.
type ProtocolTestCase struct {
	// Name is the test case name.
	Name string

	// Protocols specifies which protocols to test (nil = all).
	Protocols []ProtocolType

	// Backend specifies the backend to use (empty = default).
	Backend string

	// Skip indicates the test should be skipped.
	Skip bool

	// SkipReason explains why the test is skipped.
	SkipReason string
}

// MultiProtocolTestSuite manages multi-protocol test execution.
type MultiProtocolTestSuite struct {
	// Protocols holds configurations for all protocols to test.
	Protocols map[ProtocolType]*ProtocolConfig

	// AvailableProtocols lists protocols with available endpoints.
	AvailableProtocols []ProtocolType

	// Backends lists backends to test against.
	Backends []module.BackendType
}

// NewMultiProtocolTestSuite creates a new test suite for multi-protocol testing.
func NewMultiProtocolTestSuite() *MultiProtocolTestSuite {
	suite := &MultiProtocolTestSuite{
		Protocols: make(map[ProtocolType]*ProtocolConfig),
	}

	// Configure all protocols
	for _, p := range AllProtocols() {
		cfg := DefaultProtocolConfig(p)
		suite.Protocols[p] = cfg

		// Check availability
		if cfg.IsAvailable() {
			suite.AvailableProtocols = append(suite.AvailableProtocols, p)
		}
	}

	// Get available backends from server
	// By default, only test 'software' backend which is always available.
	// Other backends require specific server-side configuration (HSM, TPM, etc.)
	// and are enabled via environment variables.
	suite.Backends = getServerAvailableBackends()

	return suite
}

// getServerAvailableBackends returns backends that are available and configured
// on the xkms server. The software backend is always included. Other backends
// are included based on environment variable configuration.
func getServerAvailableBackends() []module.BackendType {
	backends := []module.BackendType{module.BackendSoftware}

	// Add pkcs11 backend if explicitly enabled
	// This requires the server to have SoftHSM or other PKCS#11 provider configured
	if getEnvBool("XKMS_TEST_PKCS11_BACKEND", false) {
		backends = append(backends, module.BackendPKCS11)
	}

	// Add tpm2 backend if explicitly enabled
	// This requires the server to have TPM 2.0 access configured
	if getEnvBool("XKMS_TEST_TPM2_BACKEND", false) {
		backends = append(backends, module.BackendTPM2)
	}

	return backends
}

// GetProtocolConfig returns the configuration for a specific protocol.
func (s *MultiProtocolTestSuite) GetProtocolConfig(protocol ProtocolType) *ProtocolConfig {
	return s.Protocols[protocol]
}

// IsProtocolAvailable checks if a protocol's endpoint is available.
func (s *MultiProtocolTestSuite) IsProtocolAvailable(protocol ProtocolType) bool {
	for _, p := range s.AvailableProtocols {
		if p == protocol {
			return true
		}
	}
	return false
}

// Helper functions

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	switch value {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return defaultValue
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// ProtocolTestMatrix generates test combinations for protocols and backends.
type ProtocolTestMatrix struct {
	Protocol ProtocolType
	Backend  module.BackendType
}

// String returns a descriptive name for the test combination.
func (m ProtocolTestMatrix) String() string {
	return fmt.Sprintf("%s/%s", m.Protocol, m.Backend)
}

// GenerateTestMatrix creates all combinations of protocols and backends for testing.
func GenerateTestMatrix(protocols []ProtocolType, backends []module.BackendType) []ProtocolTestMatrix {
	var matrix []ProtocolTestMatrix

	for _, protocol := range protocols {
		for _, backend := range backends {
			matrix = append(matrix, ProtocolTestMatrix{
				Protocol: protocol,
				Backend:  backend,
			})
		}
	}

	return matrix
}

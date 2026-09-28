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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfig_Validate_NetworkServingRequiresQRDBBackend proves the unified
// API server contract: enabling any network protocol (REST/gRPC/QUIC/MCP)
// with a non-qrdb storage backend must fail validation, since only the
// embedded qrdb node serves those protocols now.
func TestConfig_Validate_NetworkServingRequiresQRDBBackend(t *testing.T) {
	cfg := createMinimalConfig(t)
	cfg.Protocols.REST = true
	cfg.TLS.Enabled = true
	cfg.Storage.Backend = "file"

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `storage.backend "qrdb"`)
}

// TestConfig_Validate_NetworkServingRequiresTLS proves that qrdb storage
// alone is not enough: the unified API server's transports are TLS-only, so
// enabling a network protocol without tls.enabled must also fail validation.
func TestConfig_Validate_NetworkServingRequiresTLS(t *testing.T) {
	cfg := createMinimalConfig(t)
	cfg.Protocols.GRPC = true
	cfg.Storage.Backend = "qrdb"
	cfg.TLS.Enabled = false

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls.enabled")
}

// TestConfig_Validate_NetworkServingWithQRDBAndTLSIsValid proves the
// positive case: qrdb storage plus tls.enabled with explicit cert/key
// material satisfies the unified API server contract and Validate accepts
// it, matching the pattern unified_api_e2e_test.go exercises end to end.
func TestConfig_Validate_NetworkServingWithQRDBAndTLSIsValid(t *testing.T) {
	certFile, keyFile, _ := createTestTLSFiles(t)

	cfg := createMinimalConfig(t)
	cfg.Protocols.REST = true
	cfg.Storage.Backend = "qrdb"
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile

	assert.NoError(t, cfg.Validate())
}

// TestConfig_Validate_LoopbackDesktopExemptsNetworkServingRequirements
// proves the go-xkms#666 exemption: a config with Protocols.REST enabled
// (as pkg/server/loopback.desktopConfig forces for the 127.0.0.1-only
// desktop listener) but neither qrdb storage nor TLS passes Validate when
// LoopbackDesktop is set, exactly as NetworkServing's doc comment says the
// loopback desktop engine is exempt.
func TestConfig_Validate_LoopbackDesktopExemptsNetworkServingRequirements(t *testing.T) {
	cfg := createMinimalConfig(t)
	cfg.Protocols.REST = true
	cfg.Storage.Backend = "file"
	cfg.TLS.Enabled = false
	cfg.LoopbackDesktop = true

	assert.NoError(t, cfg.Validate())
}

// TestConfig_Validate_LoopbackDesktopDoesNotExemptOtherRESTConfigs proves
// the exemption is scoped to LoopbackDesktop alone: a config with
// Protocols.REST enabled, no TLS, and LoopbackDesktop left unset (the shape
// of a real network deployment that merely forgot TLS) is still refused --
// setting LoopbackDesktop is not a general escape hatch from the
// storage.backend "qrdb" + tls.enabled requirement.
func TestConfig_Validate_LoopbackDesktopDoesNotExemptOtherRESTConfigs(t *testing.T) {
	cfg := createMinimalConfig(t)
	cfg.Protocols.REST = true
	cfg.Storage.Backend = "file"
	cfg.TLS.Enabled = false
	// cfg.LoopbackDesktop intentionally left false.

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `storage.backend "qrdb"`)
}

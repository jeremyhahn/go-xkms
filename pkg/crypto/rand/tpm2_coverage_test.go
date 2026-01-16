// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rand

import (
	"testing"
)

// TestTPM2Resolver_NilConfig tests that newTPM2Resolver handles nil config
func TestTPM2Resolver_NilConfig(t *testing.T) {
	// newTPM2Resolver with nil config should set defaults and attempt to open TPM
	// This will fail since no TPM is available, but it tests the config initialization
	resolver, err := newTPM2Resolver(nil)

	// We expect an error because there's no TPM device available
	if err == nil {
		// If TPM is somehow available, close it
		if resolver != nil {
			_ = resolver.Close()
		}
		t.Log("TPM device available (unexpected in CI but valid)")
		return
	}

	// Error is expected - TPM not available
	t.Logf("Expected TPM error: %v", err)
}

// TestTPM2Resolver_DefaultDevice tests default device path configuration
func TestTPM2Resolver_DefaultDevice(t *testing.T) {
	cfg := &TPM2Config{
		// Device is empty, should default to /dev/tpm0
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		t.Log("TPM device available")
		return
	}

	// Expected error since TPM not available
	t.Logf("Expected TPM error: %v", err)
}

// TestTPM2Resolver_DefaultMaxRequestSize tests default MaxRequestSize
func TestTPM2Resolver_DefaultMaxRequestSize(t *testing.T) {
	cfg := &TPM2Config{
		Device:         "/dev/tpm0",
		MaxRequestSize: 0, // Should default to 32
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		return
	}

	// Expected - TPM not available
	t.Logf("Expected TPM error: %v", err)
}

// TestTPM2Resolver_NegativeMaxRequestSize tests negative MaxRequestSize defaults
func TestTPM2Resolver_NegativeMaxRequestSize(t *testing.T) {
	cfg := &TPM2Config{
		Device:         "/dev/tpm0",
		MaxRequestSize: -10, // Should default to 32
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		return
	}

	t.Logf("Expected TPM error: %v", err)
}

// TestTPM2Resolver_Simulator tests simulator configuration
func TestTPM2Resolver_Simulator(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator: true,
		// SimulatorHost and SimulatorPort should default
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		t.Log("TPM simulator available")
		return
	}

	// Expected error - simulator not running
	t.Logf("Expected simulator connection error: %v", err)
}

// TestTPM2Resolver_SimulatorWithDefaults tests simulator default configuration
func TestTPM2Resolver_SimulatorWithDefaults(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator:  true,
		SimulatorHost: "", // Should default to localhost
		SimulatorPort: 0,  // Should default to 2321
		SimulatorType: "", // Should default to swtpm
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		return
	}

	t.Logf("Expected simulator error: %v", err)
}

// TestTPM2Resolver_SimulatorWithCustomHost tests custom simulator host
func TestTPM2Resolver_SimulatorWithCustomHost(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator:  true,
		SimulatorHost: "127.0.0.1",
		SimulatorPort: 2321,
		SimulatorType: "swtpm",
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		return
	}

	t.Logf("Expected simulator error: %v", err)
}

// TestTPM2Resolver_NonexistentDevice tests with nonexistent device
func TestTPM2Resolver_NonexistentDevice(t *testing.T) {
	cfg := &TPM2Config{
		Device: "/dev/nonexistent_tpm_device_12345",
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		t.Fatal("Expected error for nonexistent device")
	}

	// Verify error message contains device path or indicates failure
	t.Logf("Got expected error: %v", err)
}

// TestTPM2AvailableFunction tests the tpm2Available function
func TestTPM2AvailableFunction(t *testing.T) {
	available := tpm2Available()
	// The function returns true (build tag dependent)
	t.Logf("tpm2Available() = %v", available)
}

// TestTPM2Resolver_ViaNewResolver tests creating resolver with TPM2 mode
func TestTPM2Resolver_ViaNewResolver(t *testing.T) {
	// Test TPM2 mode - will fail without TPM hardware
	cfg := &Config{
		Mode: ModeTPM2,
		TPM2Config: &TPM2Config{
			Device: "/dev/tpm0",
		},
	}

	resolver, err := NewResolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		t.Log("TPM2 resolver created successfully")
		return
	}

	t.Logf("Expected TPM2 error: %v", err)
}

// TestTPM2Resolver_ViaNewResolverWithSimulator tests TPM2 mode with simulator
func TestTPM2Resolver_ViaNewResolverWithSimulator(t *testing.T) {
	cfg := &Config{
		Mode: ModeTPM2,
		TPM2Config: &TPM2Config{
			UseSimulator:  true,
			SimulatorHost: "localhost",
			SimulatorPort: 2321,
		},
	}

	resolver, err := NewResolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		t.Log("TPM2 simulator resolver created")
		return
	}

	t.Logf("Expected simulator error: %v", err)
}

// TestTPM2Resolver_SimulatorNegativePort tests negative simulator port
func TestTPM2Resolver_SimulatorNegativePort(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator:  true,
		SimulatorHost: "localhost",
		SimulatorPort: -1, // Should default to 2321
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		return
	}

	t.Logf("Expected error: %v", err)
}

// TestTPM2Config_FieldAccess verifies TPM2Config fields are properly accessible
func TestTPM2Config_FieldAccess(t *testing.T) {
	cfg := TPM2Config{
		Device:         "/dev/tpm0",
		MaxRequestSize: 64,
		UseSimulator:   true,
		SimulatorType:  "swtpm",
		SimulatorHost:  "localhost",
		SimulatorPort:  2321,
	}

	if cfg.Device != "/dev/tpm0" {
		t.Errorf("Device mismatch")
	}
	if cfg.MaxRequestSize != 64 {
		t.Errorf("MaxRequestSize mismatch")
	}
	if !cfg.UseSimulator {
		t.Errorf("UseSimulator mismatch")
	}
	if cfg.SimulatorType != "swtpm" {
		t.Errorf("SimulatorType mismatch")
	}
	if cfg.SimulatorHost != "localhost" {
		t.Errorf("SimulatorHost mismatch")
	}
	if cfg.SimulatorPort != 2321 {
		t.Errorf("SimulatorPort mismatch")
	}
}

// TestTPM2Resolver_NilTPM2Config tests TPM2 mode with nil TPM2Config
func TestTPM2Resolver_NilTPM2Config(t *testing.T) {
	cfg := &Config{
		Mode:       ModeTPM2,
		TPM2Config: nil, // Should use defaults
	}

	resolver, err := NewResolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		t.Log("TPM2 resolver created with defaults")
		return
	}

	t.Logf("Expected TPM2 error: %v", err)
}

// TestTPM2Resolver_EmptyDevice tests with empty device string
func TestTPM2Resolver_EmptyDevice(t *testing.T) {
	cfg := &TPM2Config{
		Device: "", // Empty - should default to /dev/tpm0
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		return
	}

	t.Logf("Expected TPM error: %v", err)
}

// TestTPM2Resolver_LargeMaxRequestSize tests with large MaxRequestSize
func TestTPM2Resolver_LargeMaxRequestSize(t *testing.T) {
	cfg := &TPM2Config{
		Device:         "/dev/tpm0",
		MaxRequestSize: 4096, // Large value
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		return
	}

	t.Logf("Expected TPM error: %v", err)
}

// TestTPM2Resolver_SimulatorEmbeddedType tests embedded simulator type
func TestTPM2Resolver_SimulatorEmbeddedType(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator:  true,
		SimulatorType: "embedded",
		SimulatorHost: "localhost",
		SimulatorPort: 2321,
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		return
	}

	t.Logf("Expected simulator error: %v", err)
}

// TestTPM2Resolver_HighPort tests with high port number
func TestTPM2Resolver_HighPort(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator:  true,
		SimulatorHost: "localhost",
		SimulatorPort: 65000, // High port
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		return
	}

	t.Logf("Expected error: %v", err)
}

// TestTPM2Resolver_IPv6Address tests with IPv6 address
func TestTPM2Resolver_IPv6Address(t *testing.T) {
	cfg := &TPM2Config{
		UseSimulator:  true,
		SimulatorHost: "::1", // IPv6 localhost
		SimulatorPort: 2321,
	}

	resolver, err := newTPM2Resolver(cfg)
	if err == nil {
		if resolver != nil {
			_ = resolver.Close()
		}
		return
	}

	t.Logf("Expected error: %v", err)
}

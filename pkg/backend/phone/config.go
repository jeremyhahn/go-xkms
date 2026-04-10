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

package phone

import (
	"log/slog"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

const (
	// TransportBLE specifies Bluetooth Low Energy as the transport.
	TransportBLE = "ble"

	// TransportTCP specifies TCP as the transport (for ADB USB forwarding).
	TransportTCP = "tcp"

	// DefaultScanTimeout is the default duration for BLE device scanning.
	DefaultScanTimeout = 30 * time.Second

	// DefaultConnectTimeout is the default timeout for establishing a connection.
	DefaultConnectTimeout = 15 * time.Second

	// DefaultRequestTimeout is the default per-operation timeout for JSON-RPC requests.
	DefaultRequestTimeout = 30 * time.Second

	// DefaultPlatform is the default phone platform when not explicitly configured.
	DefaultPlatform = "android"
)

// transportTypes provides O(1) constant-time validation of transport types.
var transportTypes = map[string]struct{}{
	TransportBLE: {},
	TransportTCP: {},
}

// AttestationConfig holds the configuration for attestation verification
// in the phone backend. When present, the backend verifies the attestation
// certificate chain returned by the phone during AttestKey calls using the
// registered platform verifier.
type AttestationConfig struct {
	// Platform identifies the phone platform for attestation verification.
	// Valid values: "android" (default), "ios" (future).
	// The platform determines which verifier is used to validate the
	// attestation certificate chain.
	Platform string `yaml:"platform" json:"platform"`

	// TrustStore configures which root certificates to trust for chain verification.
	TrustStore *truststore.Config `yaml:"trust_store" json:"trust_store"`

	// MinSecurityLevel is the minimum acceptable security level for attestation.
	// The interpretation is platform-specific (e.g., "software", "tee", "strongbox"
	// for Android). Defaults to the platform's lowest level.
	MinSecurityLevel string `yaml:"min_security_level" json:"min_security_level"`

	// VerifyBootState enables verification that the device boot state is "verified".
	// When true, attestations from devices with unlocked bootloaders are rejected.
	VerifyBootState bool `yaml:"verify_boot_state" json:"verify_boot_state"`
}

// Config holds the configuration for the phone backend, which proxies key
// operations to a phone via BLE or TCP (ADB USB forwarding) using
// Noise-encrypted JSON-RPC.
type Config struct {
	// Transport specifies the transport type: "ble" or "tcp" (for ADB USB forwarding).
	Transport string `yaml:"transport" json:"transport"`

	// DeviceAddress is the BLE MAC address or TCP address (host:port) of the phone.
	DeviceAddress string `yaml:"device_address" json:"device_address"`

	// NoiseStaticKey is the hex-encoded Noise static private key for this laptop.
	NoiseStaticKey string `yaml:"noise_static_key" json:"noise_static_key"`

	// PhoneStaticKey is the hex-encoded Noise static public key of the paired phone.
	PhoneStaticKey string `yaml:"phone_static_key" json:"phone_static_key"`

	// ScanTimeout is how long to scan for BLE devices.
	ScanTimeout time.Duration `yaml:"scan_timeout" json:"scan_timeout"`

	// ConnectTimeout is the timeout for establishing a connection.
	ConnectTimeout time.Duration `yaml:"connect_timeout" json:"connect_timeout"`

	// RequestTimeout is the per-operation timeout for JSON-RPC requests.
	RequestTimeout time.Duration `yaml:"request_timeout" json:"request_timeout"`

	// Attestation configures attestation verification. When nil, attestation
	// verification is skipped (the raw certificate chain is returned without
	// chain validation or security level checks). This is suitable for
	// development and testing environments.
	Attestation *AttestationConfig `yaml:"attestation" json:"attestation"`

	// Logger is the structured logger.
	Logger *slog.Logger `yaml:"-" json:"-"`
}

// DefaultConfig returns a Config with reasonable defaults for the phone backend.
func DefaultConfig() *Config {
	return &Config{
		Transport:      TransportBLE,
		ScanTimeout:    DefaultScanTimeout,
		ConnectTimeout: DefaultConnectTimeout,
		RequestTimeout: DefaultRequestTimeout,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
}

// Validate validates the phone backend configuration, applying defaults for
// zero-valued timeouts and a nil logger.
func (c *Config) Validate() error {
	if _, ok := transportTypes[c.Transport]; !ok {
		return ErrInvalidTransport
	}

	if c.DeviceAddress == "" {
		return ErrMissingDeviceAddress
	}

	if c.NoiseStaticKey == "" {
		return ErrMissingNoiseStaticKey
	}

	if c.PhoneStaticKey == "" {
		return ErrMissingPhoneStaticKey
	}

	if c.ScanTimeout == 0 {
		c.ScanTimeout = DefaultScanTimeout
	}

	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = DefaultConnectTimeout
	}

	if c.RequestTimeout == 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}

	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}

	// Default attestation platform to Android for backward compatibility.
	if c.Attestation != nil && c.Attestation.Platform == "" {
		c.Attestation.Platform = DefaultPlatform
	}

	return nil
}

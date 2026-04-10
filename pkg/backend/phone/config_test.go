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
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Transport != TransportBLE {
		t.Errorf("expected transport %s, got %s", TransportBLE, cfg.Transport)
	}
	if cfg.ScanTimeout != DefaultScanTimeout {
		t.Errorf("expected scan timeout %v, got %v", DefaultScanTimeout, cfg.ScanTimeout)
	}
	if cfg.ConnectTimeout != DefaultConnectTimeout {
		t.Errorf("expected connect timeout %v, got %v", DefaultConnectTimeout, cfg.ConnectTimeout)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("expected request timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
	}
	if cfg.Logger == nil {
		t.Error("expected non-nil logger")
	}
}

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
		ScanTimeout:    10 * time.Second,
		ConnectTimeout: 5 * time.Second,
		RequestTimeout: 15 * time.Second,
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	if cfg.Logger == nil {
		t.Error("expected Validate to set a default logger for nil Logger")
	}
}

func TestConfig_Validate_ValidTCP(t *testing.T) {
	cfg := &Config{
		Transport:      TransportTCP,
		DeviceAddress:  "192.168.1.100:9876",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("expected nil error for TCP transport, got %v", err)
	}
}

func TestConfig_Validate_InvalidTransport(t *testing.T) {
	cfg := &Config{
		Transport:      "wifi",
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
	}

	err := cfg.Validate()
	if err != ErrInvalidTransport {
		t.Errorf("expected ErrInvalidTransport, got %v", err)
	}
}

func TestConfig_Validate_EmptyTransport(t *testing.T) {
	cfg := &Config{
		Transport:      "",
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
	}

	err := cfg.Validate()
	if err != ErrInvalidTransport {
		t.Errorf("expected ErrInvalidTransport for empty transport, got %v", err)
	}
}

func TestConfig_Validate_MissingNoiseKey(t *testing.T) {
	cfg := &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "",
		PhoneStaticKey: "cafebabe05060708",
	}

	err := cfg.Validate()
	if err != ErrMissingNoiseStaticKey {
		t.Errorf("expected ErrMissingNoiseStaticKey, got %v", err)
	}
}

func TestConfig_Validate_MissingPhoneKey(t *testing.T) {
	cfg := &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "",
	}

	err := cfg.Validate()
	if err != ErrMissingPhoneStaticKey {
		t.Errorf("expected ErrMissingPhoneStaticKey, got %v", err)
	}
}

func TestConfig_Validate_MissingDeviceAddress(t *testing.T) {
	cfg := &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
	}

	err := cfg.Validate()
	if err != ErrMissingDeviceAddress {
		t.Errorf("expected ErrMissingDeviceAddress, got %v", err)
	}
}

func TestConfig_Validate_DefaultTimeouts(t *testing.T) {
	cfg := &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
		ScanTimeout:    0,
		ConnectTimeout: 0,
		RequestTimeout: 0,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ScanTimeout != DefaultScanTimeout {
		t.Errorf("expected default scan timeout %v, got %v", DefaultScanTimeout, cfg.ScanTimeout)
	}
	if cfg.ConnectTimeout != DefaultConnectTimeout {
		t.Errorf("expected default connect timeout %v, got %v", DefaultConnectTimeout, cfg.ConnectTimeout)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("expected default request timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
	}
}

func TestConfig_Validate_DefaultLogger(t *testing.T) {
	cfg := &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
		Logger:         nil,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Logger == nil {
		t.Error("expected Validate to assign a default logger when Logger is nil")
	}
}

func TestTransportTypes(t *testing.T) {
	if _, ok := transportTypes[TransportBLE]; !ok {
		t.Errorf("expected transportTypes to contain %q", TransportBLE)
	}
	if _, ok := transportTypes[TransportTCP]; !ok {
		t.Errorf("expected transportTypes to contain %q", TransportTCP)
	}
	if _, ok := transportTypes["wifi"]; ok {
		t.Error("expected transportTypes to NOT contain \"wifi\"")
	}
	if len(transportTypes) != 2 {
		t.Errorf("expected 2 transport types, got %d", len(transportTypes))
	}
}

func TestConfig_Validate_CustomTimeoutsPreserved(t *testing.T) {
	cfg := &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
		ScanTimeout:    5 * time.Second,
		ConnectTimeout: 3 * time.Second,
		RequestTimeout: 10 * time.Second,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ScanTimeout != 5*time.Second {
		t.Errorf("expected custom scan timeout 5s, got %v", cfg.ScanTimeout)
	}
	if cfg.ConnectTimeout != 3*time.Second {
		t.Errorf("expected custom connect timeout 3s, got %v", cfg.ConnectTimeout)
	}
	if cfg.RequestTimeout != 10*time.Second {
		t.Errorf("expected custom request timeout 10s, got %v", cfg.RequestTimeout)
	}
}

func TestConfig_Validate_ValidationOrder(t *testing.T) {
	// Verify that transport is validated before device address,
	// which is validated before noise key, which is before phone key.
	cfg := &Config{
		Transport:      "invalid",
		DeviceAddress:  "",
		NoiseStaticKey: "",
		PhoneStaticKey: "",
	}

	err := cfg.Validate()
	if err != ErrInvalidTransport {
		t.Errorf("expected ErrInvalidTransport first, got %v", err)
	}

	cfg.Transport = TransportBLE

	err = cfg.Validate()
	if err != ErrMissingDeviceAddress {
		t.Errorf("expected ErrMissingDeviceAddress second, got %v", err)
	}

	cfg.DeviceAddress = "AA:BB:CC:DD:EE:FF"

	err = cfg.Validate()
	if err != ErrMissingNoiseStaticKey {
		t.Errorf("expected ErrMissingNoiseStaticKey third, got %v", err)
	}

	cfg.NoiseStaticKey = "deadbeef"

	err = cfg.Validate()
	if err != ErrMissingPhoneStaticKey {
		t.Errorf("expected ErrMissingPhoneStaticKey fourth, got %v", err)
	}
}

func TestConfig_Validate_DefaultPlatform(t *testing.T) {
	cfg := &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
		Attestation: &AttestationConfig{
			MinSecurityLevel: "tee",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Attestation.Platform != DefaultPlatform {
		t.Errorf("expected default platform %q, got %q", DefaultPlatform, cfg.Attestation.Platform)
	}
}

func TestConfig_Validate_ExplicitPlatformPreserved(t *testing.T) {
	cfg := &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
		Attestation: &AttestationConfig{
			Platform:         "ios",
			MinSecurityLevel: "tee",
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Attestation.Platform != "ios" {
		t.Errorf("expected platform ios, got %q", cfg.Attestation.Platform)
	}
}

func TestConfig_Validate_NilAttestationNoPlatformDefault(t *testing.T) {
	cfg := &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Attestation != nil {
		t.Error("expected nil Attestation to remain nil")
	}
}

func TestDefaultPlatformConstant(t *testing.T) {
	if DefaultPlatform != "android" {
		t.Errorf("expected DefaultPlatform to be 'android', got %q", DefaultPlatform)
	}
}

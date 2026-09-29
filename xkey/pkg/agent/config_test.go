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

package agent

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ListenAddress != ":9443" {
		t.Errorf("expected listen address :9443, got %q", cfg.ListenAddress)
	}
	if cfg.CertValidityDays != 365 {
		t.Errorf("expected cert validity 365, got %d", cfg.CertValidityDays)
	}
	if cfg.OneTimeCodeLength != 8 {
		t.Errorf("expected code length 8, got %d", cfg.OneTimeCodeLength)
	}
	if cfg.OneTimeCodeValidity != 15*time.Minute {
		t.Errorf("expected code validity 15m, got %v", cfg.OneTimeCodeValidity)
	}
	if len(cfg.EnrollmentMethods) != 1 {
		t.Fatalf("expected 1 enrollment method, got %d", len(cfg.EnrollmentMethods))
	}
	if cfg.EnrollmentMethods[0] != EnrollOneTimeCode {
		t.Errorf("expected one_time_code, got %v", cfg.EnrollmentMethods[0])
	}
	if cfg.MaxAgents != 0 {
		t.Errorf("expected max agents 0 (unlimited), got %d", cfg.MaxAgents)
	}
	if cfg.MaxRecvMsgSize != defaultMaxRecvMsgSize {
		t.Errorf("expected max recv msg size %d, got %d", defaultMaxRecvMsgSize, cfg.MaxRecvMsgSize)
	}
	if cfg.MaxSendMsgSize != defaultMaxSendMsgSize {
		t.Errorf("expected max send msg size %d, got %d", defaultMaxSendMsgSize, cfg.MaxSendMsgSize)
	}
	if cfg.ConnectionTimeout != defaultConnectionTimeout {
		t.Errorf("expected connection timeout %v, got %v", defaultConnectionTimeout, cfg.ConnectionTimeout)
	}
	if cfg.MaxConcurrentStreams != defaultMaxConcurrentStreams {
		t.Errorf("expected max concurrent streams %d, got %d", defaultMaxConcurrentStreams, cfg.MaxConcurrentStreams)
	}
}

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
}

func TestConfig_Validate_EmptyAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenAddress = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty listen address")
	}
	if !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("expected ErrInvalidAddress, got %v", err)
	}
}

func TestConfig_Validate_InvalidMethod(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{"invalid_method"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid enrollment method")
	}
	if !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("expected ErrPolicyViolation, got %v", err)
	}
}

func TestConfig_Validate_FixesDefaults(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CertValidityDays = 0
	cfg.OneTimeCodeLength = -1
	cfg.OneTimeCodeValidity = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate should fix defaults: %v", err)
	}
	if cfg.CertValidityDays != 365 {
		t.Errorf("expected cert validity to be fixed to 365, got %d", cfg.CertValidityDays)
	}
	if cfg.OneTimeCodeLength != 8 {
		t.Errorf("expected code length to be fixed to 8, got %d", cfg.OneTimeCodeLength)
	}
	if cfg.OneTimeCodeValidity != 15*time.Minute {
		t.Errorf("expected code validity to be fixed to 15m, got %v", cfg.OneTimeCodeValidity)
	}
}

func TestConfig_Validate_FixesGRPCHardeningDefaults(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxRecvMsgSize = 0
	cfg.MaxSendMsgSize = -1
	cfg.ConnectionTimeout = 0
	cfg.MaxConcurrentStreams = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate should fix gRPC hardening defaults: %v", err)
	}
	if cfg.MaxRecvMsgSize != defaultMaxRecvMsgSize {
		t.Errorf("expected max recv msg size fixed to %d, got %d", defaultMaxRecvMsgSize, cfg.MaxRecvMsgSize)
	}
	if cfg.MaxSendMsgSize != defaultMaxSendMsgSize {
		t.Errorf("expected max send msg size fixed to %d, got %d", defaultMaxSendMsgSize, cfg.MaxSendMsgSize)
	}
	if cfg.ConnectionTimeout != defaultConnectionTimeout {
		t.Errorf("expected connection timeout fixed to %v, got %v", defaultConnectionTimeout, cfg.ConnectionTimeout)
	}
	if cfg.MaxConcurrentStreams != defaultMaxConcurrentStreams {
		t.Errorf("expected max concurrent streams fixed to %d, got %d", defaultMaxConcurrentStreams, cfg.MaxConcurrentStreams)
	}
}

func TestConfig_Validate_PreservesCustomGRPCHardening(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxRecvMsgSize = 8 * 1024 * 1024
	cfg.MaxSendMsgSize = 8 * 1024 * 1024
	cfg.ConnectionTimeout = 60 * time.Second
	cfg.MaxConcurrentStreams = 200

	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate should accept custom gRPC hardening values: %v", err)
	}
	if cfg.MaxRecvMsgSize != 8*1024*1024 {
		t.Errorf("expected custom max recv msg size preserved, got %d", cfg.MaxRecvMsgSize)
	}
	if cfg.MaxConcurrentStreams != 200 {
		t.Errorf("expected custom max concurrent streams preserved, got %d", cfg.MaxConcurrentStreams)
	}
}

func TestIsValidEnrollmentMethod(t *testing.T) {
	tests := []struct {
		name   string
		method EnrollmentMethod
		want   bool
	}{
		{"one_time_code", EnrollOneTimeCode, true},
		{"admin_approval", EnrollAdminApproval, true},
		{"enterprise_ca", EnrollEnterpriseCA, true},
		{"noise_direct", EnrollNoiseDirect, true},
		{"invalid", EnrollmentMethod("invalid"), false},
		{"empty", EnrollmentMethod(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidEnrollmentMethod(tt.method)
			if got != tt.want {
				t.Errorf("IsValidEnrollmentMethod(%q) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestDefaultClientConfig(t *testing.T) {
	cfg := DefaultClientConfig()

	if cfg.ReconnectBackoffMax != 2*time.Minute {
		t.Errorf("expected reconnect backoff max 2m, got %v", cfg.ReconnectBackoffMax)
	}
}

func TestClientConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.MasterAddress = "localhost:9443"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid client config should pass: %v", err)
	}
}

func TestClientConfig_Validate_EmptyMasterAddress(t *testing.T) {
	cfg := DefaultClientConfig()
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty master address")
	}
	if !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("expected ErrInvalidAddress, got %v", err)
	}
}

func TestConfig_Validate_AllMethods(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = []EnrollmentMethod{
		EnrollOneTimeCode,
		EnrollAdminApproval,
		EnrollEnterpriseCA,
		EnrollNoiseDirect,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("all valid methods should pass: %v", err)
	}
}

func TestConfig_Validate_EmptyMethods(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnrollmentMethods = nil
	// Empty methods is allowed (policy may not permit enrollment).
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty methods should be valid: %v", err)
	}
}

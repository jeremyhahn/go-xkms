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

package pin

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultLockoutConfig(t *testing.T) {
	cfg := DefaultLockoutConfig()
	if cfg.MaxAttempts != 5 {
		t.Errorf("MaxAttempts = %d, want 5", cfg.MaxAttempts)
	}
	if cfg.LockoutDuration != 5*time.Minute {
		t.Errorf("LockoutDuration = %v, want %v", cfg.LockoutDuration, 5*time.Minute)
	}
	if !cfg.Backoff {
		t.Error("Backoff should be true")
	}
}

func TestDefaultLockoutConfig_Consistent(t *testing.T) {
	cfg1 := DefaultLockoutConfig()
	cfg2 := DefaultLockoutConfig()
	if cfg1.MaxAttempts != cfg2.MaxAttempts ||
		cfg1.LockoutDuration != cfg2.LockoutDuration ||
		cfg1.Backoff != cfg2.Backoff {
		t.Error("consecutive calls should return identical configs")
	}
}

func TestPINManagerAdapter_SetMaxAttempts_NoOp(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	adapter := &PINManagerAdapter{PINBackend: backend}

	// SetMaxAttempts should not panic and is a no-op.
	adapter.SetMaxAttempts(10)
	adapter.SetMaxAttempts(0)

	// Verify the adapter still delegates to the backend.
	if adapter.Strategy() != StrategySoftware {
		t.Errorf("Strategy() = %s, want %s", adapter.Strategy(), StrategySoftware)
	}
}

func TestPINManagerAdapter_DelegatesToBackend(t *testing.T) {
	backend := newMockBackend(StrategySoftware)
	adapter := &PINManagerAdapter{PINBackend: backend}

	// SetSOPIN should delegate.
	if err := adapter.SetSOPIN("", "sopin123456"); err != nil {
		t.Fatalf("SetSOPIN: %v", err)
	}
	if !adapter.SOPINSet() {
		t.Error("SOPINSet should be true")
	}
	if !adapter.IsInitialized() {
		t.Error("IsInitialized should be true")
	}

	// SetUserPIN should delegate.
	if err := adapter.SetUserPIN("sopin123456", "userpin123456"); err != nil {
		t.Fatalf("SetUserPIN: %v", err)
	}
	if !adapter.UserPINSet() {
		t.Error("UserPINSet should be true")
	}

	// Verify should delegate.
	if err := adapter.VerifySOPIN("sopin123456"); err != nil {
		t.Errorf("VerifySOPIN: %v", err)
	}
	if err := adapter.VerifyUserPIN("userpin123456"); err != nil {
		t.Errorf("VerifyUserPIN: %v", err)
	}
}

func TestPINManagerAdapter_CompileTimeCheck(t *testing.T) {
	// The compile-time check is in pin.go, but verify it at runtime too.
	var _ PINManager = (*PINManagerAdapter)(nil)
}

func TestValidatePINLength_Valid(t *testing.T) {
	if err := validatePINLength("123456"); err != nil {
		t.Errorf("6-char PIN should be valid: %v", err)
	}
	if err := validatePINLength("1234567890"); err != nil {
		t.Errorf("10-char PIN should be valid: %v", err)
	}
}

func TestValidatePINLength_TooShort(t *testing.T) {
	tests := []struct {
		pin string
	}{
		{""},
		{"1"},
		{"12345"},
	}
	for _, tc := range tests {
		if err := validatePINLength(tc.pin); !errors.Is(err, ErrPINTooShort) {
			t.Errorf("validatePINLength(%q) = %v, want ErrPINTooShort", tc.pin, err)
		}
	}
}

func TestStrategyIDConstants(t *testing.T) {
	if StrategySoftware != "software" {
		t.Errorf("StrategySoftware = %q, want %q", StrategySoftware, "software")
	}
	if StrategyTPM2 != "tpm2" {
		t.Errorf("StrategyTPM2 = %q, want %q", StrategyTPM2, "tpm2")
	}
}

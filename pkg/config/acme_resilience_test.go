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
	"testing"
	"time"
)

// TestACMECircuitBreakerConfig_Validate verifies that negative durations are
// rejected and every other combination, including the zero value, is valid.
func TestACMECircuitBreakerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ACMECircuitBreakerConfig
		wantErr error
	}{
		{name: "zero value is valid", cfg: ACMECircuitBreakerConfig{}},
		{name: "positive values are valid", cfg: ACMECircuitBreakerConfig{MaxFailures: 3, ResetTimeoutSeconds: 10, TimeoutSeconds: 5}},
		{name: "negative reset timeout", cfg: ACMECircuitBreakerConfig{ResetTimeoutSeconds: -1}, wantErr: ErrACMEResilienceNegativeValue},
		{name: "negative timeout", cfg: ACMECircuitBreakerConfig{TimeoutSeconds: -1}, wantErr: ErrACMEResilienceNegativeValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err != tt.wantErr {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestACMECircuitBreakerConfig_CircuitBreakerConfig verifies the mapping to
// circuitbreaker.Config: defaults are substituted for zero fields, and
// operator-supplied values are carried through untouched.
func TestACMECircuitBreakerConfig_CircuitBreakerConfig(t *testing.T) {
	t.Run("defaults are substituted", func(t *testing.T) {
		got := ACMECircuitBreakerConfig{}.CircuitBreakerConfig("http01")

		if got.Name != "http01" {
			t.Fatalf("Name = %q", got.Name)
		}
		if got.MaxFailures != DefaultACMEBreakerMaxFailures {
			t.Fatalf("MaxFailures = %d", got.MaxFailures)
		}
		if got.ResetTimeout != DefaultACMEBreakerResetTimeoutSeconds*time.Second {
			t.Fatalf("ResetTimeout = %v", got.ResetTimeout)
		}
		if got.HalfOpenMaxRequests != DefaultACMEBreakerHalfOpenMaxRequests {
			t.Fatalf("HalfOpenMaxRequests = %d", got.HalfOpenMaxRequests)
		}
		if got.SuccessThreshold != DefaultACMEBreakerSuccessThreshold {
			t.Fatalf("SuccessThreshold = %d", got.SuccessThreshold)
		}
		if got.Timeout != DefaultACMEBreakerTimeoutSeconds*time.Second {
			t.Fatalf("Timeout = %v", got.Timeout)
		}
	})

	t.Run("operator values are preserved", func(t *testing.T) {
		cfg := ACMECircuitBreakerConfig{
			MaxFailures:         9,
			ResetTimeoutSeconds: 42,
			HalfOpenMaxRequests: 3,
			SuccessThreshold:    4,
			TimeoutSeconds:      7,
		}
		got := cfg.CircuitBreakerConfig("dns01")

		if got.MaxFailures != 9 || got.ResetTimeout != 42*time.Second ||
			got.HalfOpenMaxRequests != 3 || got.SuccessThreshold != 4 || got.Timeout != 7*time.Second {
			t.Fatalf("mapped config did not preserve operator values: %+v", got)
		}
	})
}

// TestACMEDegradationConfig_Validate verifies that negative values are
// rejected.
func TestACMEDegradationConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ACMEDegradationConfig
		wantErr error
	}{
		{name: "zero value is valid", cfg: ACMEDegradationConfig{}},
		{name: "negative cache ttl", cfg: ACMEDegradationConfig{CacheTTLSeconds: -1}, wantErr: ErrACMEResilienceNegativeValue},
		{name: "negative stale ttl", cfg: ACMEDegradationConfig{StaleTTLSeconds: -1}, wantErr: ErrACMEResilienceNegativeValue},
		{name: "negative max cache size", cfg: ACMEDegradationConfig{MaxCacheSize: -1}, wantErr: ErrACMEResilienceNegativeValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err != tt.wantErr {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestACMEDegradationConfig_Resolve verifies defaults are substituted for
// unset fields and operator values are preserved otherwise.
func TestACMEDegradationConfig_Resolve(t *testing.T) {
	defaults := ACMEDegradationConfig{}
	if got := defaults.ResolveCacheTTL(); got != DefaultACMEDegradationCacheTTLSeconds*time.Second {
		t.Fatalf("ResolveCacheTTL() = %v", got)
	}
	if got := defaults.ResolveStaleTTL(); got != DefaultACMEDegradationStaleTTLSeconds*time.Second {
		t.Fatalf("ResolveStaleTTL() = %v", got)
	}
	if got := defaults.ResolveMaxCacheSize(); got != DefaultACMEDegradationMaxCacheSize {
		t.Fatalf("ResolveMaxCacheSize() = %d", got)
	}

	explicit := ACMEDegradationConfig{CacheTTLSeconds: 5, StaleTTLSeconds: 30, MaxCacheSize: 100}
	if got := explicit.ResolveCacheTTL(); got != 5*time.Second {
		t.Fatalf("ResolveCacheTTL() = %v", got)
	}
	if got := explicit.ResolveStaleTTL(); got != 30*time.Second {
		t.Fatalf("ResolveStaleTTL() = %v", got)
	}
	if got := explicit.ResolveMaxCacheSize(); got != 100 {
		t.Fatalf("ResolveMaxCacheSize() = %d", got)
	}
}

// TestACMEResilienceConfig_Validate verifies that a failure in any breaker
// section or the degradation section fails the whole resilience section, and
// that the zero value validates cleanly.
func TestACMEResilienceConfig_Validate(t *testing.T) {
	if err := (ACMEResilienceConfig{}).Validate(); err != nil {
		t.Fatalf("zero value Validate() = %v, want nil", err)
	}

	tests := []struct {
		name string
		cfg  ACMEResilienceConfig
	}{
		{name: "bad http01", cfg: ACMEResilienceConfig{HTTP01: ACMECircuitBreakerConfig{TimeoutSeconds: -1}}},
		{name: "bad dns01", cfg: ACMEResilienceConfig{DNS01: ACMECircuitBreakerConfig{TimeoutSeconds: -1}}},
		{name: "bad ct_submitter", cfg: ACMEResilienceConfig{CTSubmitter: ACMECircuitBreakerConfig{TimeoutSeconds: -1}}},
		{name: "bad kms", cfg: ACMEResilienceConfig{KMS: ACMECircuitBreakerConfig{TimeoutSeconds: -1}}},
		{name: "bad storage", cfg: ACMEResilienceConfig{Storage: ACMECircuitBreakerConfig{TimeoutSeconds: -1}}},
		{name: "bad degradation", cfg: ACMEResilienceConfig{Degradation: ACMEDegradationConfig{MaxCacheSize: -1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); err != ErrACMEResilienceNegativeValue {
				t.Fatalf("Validate() = %v, want %v", err, ErrACMEResilienceNegativeValue)
			}
		})
	}
}

// TestACMEConfig_ValidateRejectsBadResilience verifies that the resilience
// section is checked as part of ACMEConfig.Validate, the same way the audit
// section is.
func TestACMEConfig_ValidateRejectsBadResilience(t *testing.T) {
	cfg := enabledACME()
	cfg.Resilience.Storage.TimeoutSeconds = -1

	if err := cfg.Validate(); err != ErrACMEResilienceNegativeValue {
		t.Fatalf("Validate() = %v, want %v", err, ErrACMEResilienceNegativeValue)
	}

	cfg.Resilience.Storage.TimeoutSeconds = 0
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

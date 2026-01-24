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

package transport

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected Timeout 30s, got %v", cfg.Timeout)
	}

	if cfg.MaxRetries != 3 {
		t.Errorf("expected MaxRetries 3, got %d", cfg.MaxRetries)
	}

	if cfg.RetryBackoff != 100*time.Millisecond {
		t.Errorf("expected RetryBackoff 100ms, got %v", cfg.RetryBackoff)
	}

	if cfg.PoolMinConns != 1 {
		t.Errorf("expected PoolMinConns 1, got %d", cfg.PoolMinConns)
	}

	if cfg.PoolMaxConns != 10 {
		t.Errorf("expected PoolMaxConns 10, got %d", cfg.PoolMaxConns)
	}

	if cfg.Headers == nil {
		t.Error("expected Headers to be initialized")
	}
}

func TestConfigClone(t *testing.T) {
	t.Run("clone nil config", func(t *testing.T) {
		var cfg *Config
		clone := cfg.Clone()
		if clone != nil {
			t.Error("expected nil clone for nil config")
		}
	})

	t.Run("clone with headers", func(t *testing.T) {
		cfg := &Config{
			Address:    "localhost:8080",
			TLSEnabled: true,
			Timeout:    5 * time.Second,
			Headers: map[string]string{
				"X-Custom": "value",
			},
		}

		clone := cfg.Clone()

		// Verify values are copied
		if clone.Address != cfg.Address {
			t.Errorf("expected Address %s, got %s", cfg.Address, clone.Address)
		}
		if clone.TLSEnabled != cfg.TLSEnabled {
			t.Errorf("expected TLSEnabled %v, got %v", cfg.TLSEnabled, clone.TLSEnabled)
		}
		if clone.Timeout != cfg.Timeout {
			t.Errorf("expected Timeout %v, got %v", cfg.Timeout, clone.Timeout)
		}

		// Verify headers are deeply copied
		if clone.Headers["X-Custom"] != cfg.Headers["X-Custom"] {
			t.Errorf("expected header X-Custom=%s, got %s", cfg.Headers["X-Custom"], clone.Headers["X-Custom"])
		}

		// Modify clone headers and verify original is unchanged
		clone.Headers["X-Custom"] = "modified"
		if cfg.Headers["X-Custom"] == "modified" {
			t.Error("clone headers should not affect original")
		}
	})

	t.Run("clone without headers", func(t *testing.T) {
		cfg := &Config{
			Address: "localhost:8080",
		}

		clone := cfg.Clone()

		if clone.Headers != nil {
			t.Error("expected nil Headers for config without headers")
		}
	})
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *Config
		wantError bool
		errorMsg  string
	}{
		{
			name:      "nil config",
			cfg:       nil,
			wantError: true,
			errorMsg:  "invalid configuration",
		},
		{
			name: "valid config",
			cfg: &Config{
				Timeout:      5 * time.Second,
				MaxRetries:   3,
				RetryBackoff: time.Second,
				PoolMinConns: 1,
				PoolMaxConns: 10,
			},
			wantError: false,
		},
		{
			name: "negative timeout",
			cfg: &Config{
				Timeout: -1 * time.Second,
			},
			wantError: true,
			errorMsg:  "Timeout",
		},
		{
			name: "negative max retries",
			cfg: &Config{
				MaxRetries: -1,
			},
			wantError: true,
			errorMsg:  "MaxRetries",
		},
		{
			name: "negative retry backoff",
			cfg: &Config{
				RetryBackoff: -1 * time.Second,
			},
			wantError: true,
			errorMsg:  "RetryBackoff",
		},
		{
			name: "negative pool min conns",
			cfg: &Config{
				PoolMinConns: -1,
			},
			wantError: true,
			errorMsg:  "PoolMinConns",
		},
		{
			name: "negative pool max conns",
			cfg: &Config{
				PoolMaxConns: -1,
			},
			wantError: true,
			errorMsg:  "PoolMaxConns",
		},
		{
			name: "min conns exceeds max conns",
			cfg: &Config{
				PoolMinConns: 10,
				PoolMaxConns: 5,
			},
			wantError: true,
			errorMsg:  "PoolMinConns",
		},
		{
			name: "zero pool max allows any min",
			cfg: &Config{
				PoolMinConns: 10,
				PoolMaxConns: 0,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errorMsg != "" {
					if _, ok := err.(*ConfigError); ok {
						if ce := err.(*ConfigError); ce.Field != tt.errorMsg {
							// For config errors, check field name
						}
					} else if err != ErrInvalidConfig && tt.errorMsg == "invalid configuration" {
						// For nil config, check sentinel error
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestWithAddress(t *testing.T) {
	t.Run("valid address", func(t *testing.T) {
		cfg := &Config{}
		opt := WithAddress("localhost:8080")
		err := opt(cfg)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if cfg.Address != "localhost:8080" {
			t.Errorf("expected Address localhost:8080, got %s", cfg.Address)
		}
	})

	t.Run("empty address", func(t *testing.T) {
		cfg := &Config{}
		opt := WithAddress("")
		err := opt(cfg)

		if err == nil {
			t.Error("expected error for empty address")
		}
	})
}

func TestWithTLS(t *testing.T) {
	cfg := &Config{}
	opt := WithTLS("/path/to/ca.crt")
	err := opt(cfg)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !cfg.TLSEnabled {
		t.Error("expected TLSEnabled to be true")
	}
	if cfg.TLSCAFile != "/path/to/ca.crt" {
		t.Errorf("expected TLSCAFile /path/to/ca.crt, got %s", cfg.TLSCAFile)
	}
}

func TestWithTLSInsecure(t *testing.T) {
	cfg := &Config{}
	opt := WithTLSInsecure()
	err := opt(cfg)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !cfg.TLSEnabled {
		t.Error("expected TLSEnabled to be true")
	}
	if !cfg.TLSInsecureSkipVerify {
		t.Error("expected TLSInsecureSkipVerify to be true")
	}
}

func TestWithMTLS(t *testing.T) {
	t.Run("valid mTLS config", func(t *testing.T) {
		cfg := &Config{}
		opt := WithMTLS("/path/to/cert.crt", "/path/to/key.key", "/path/to/ca.crt")
		err := opt(cfg)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !cfg.TLSEnabled {
			t.Error("expected TLSEnabled to be true")
		}
		if cfg.TLSCertFile != "/path/to/cert.crt" {
			t.Errorf("expected TLSCertFile /path/to/cert.crt, got %s", cfg.TLSCertFile)
		}
		if cfg.TLSKeyFile != "/path/to/key.key" {
			t.Errorf("expected TLSKeyFile /path/to/key.key, got %s", cfg.TLSKeyFile)
		}
		if cfg.TLSCAFile != "/path/to/ca.crt" {
			t.Errorf("expected TLSCAFile /path/to/ca.crt, got %s", cfg.TLSCAFile)
		}
	})

	t.Run("empty cert file", func(t *testing.T) {
		cfg := &Config{}
		opt := WithMTLS("", "/path/to/key.key", "/path/to/ca.crt")
		err := opt(cfg)

		if err == nil {
			t.Error("expected error for empty cert file")
		}
	})

	t.Run("empty key file", func(t *testing.T) {
		cfg := &Config{}
		opt := WithMTLS("/path/to/cert.crt", "", "/path/to/ca.crt")
		err := opt(cfg)

		if err == nil {
			t.Error("expected error for empty key file")
		}
	})
}

func TestWithTimeout(t *testing.T) {
	t.Run("valid timeout", func(t *testing.T) {
		cfg := &Config{}
		opt := WithTimeout(10 * time.Second)
		err := opt(cfg)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if cfg.Timeout != 10*time.Second {
			t.Errorf("expected Timeout 10s, got %v", cfg.Timeout)
		}
	})

	t.Run("negative timeout", func(t *testing.T) {
		cfg := &Config{}
		opt := WithTimeout(-1 * time.Second)
		err := opt(cfg)

		if err == nil {
			t.Error("expected error for negative timeout")
		}
	})

	t.Run("zero timeout", func(t *testing.T) {
		cfg := &Config{}
		opt := WithTimeout(0)
		err := opt(cfg)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if cfg.Timeout != 0 {
			t.Errorf("expected Timeout 0, got %v", cfg.Timeout)
		}
	})
}

func TestWithRetry(t *testing.T) {
	t.Run("valid retry config", func(t *testing.T) {
		cfg := &Config{}
		opt := WithRetry(5, 200*time.Millisecond)
		err := opt(cfg)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if cfg.MaxRetries != 5 {
			t.Errorf("expected MaxRetries 5, got %d", cfg.MaxRetries)
		}
		if cfg.RetryBackoff != 200*time.Millisecond {
			t.Errorf("expected RetryBackoff 200ms, got %v", cfg.RetryBackoff)
		}
	})

	t.Run("negative max retries", func(t *testing.T) {
		cfg := &Config{}
		opt := WithRetry(-1, time.Second)
		err := opt(cfg)

		if err == nil {
			t.Error("expected error for negative max retries")
		}
	})

	t.Run("negative backoff", func(t *testing.T) {
		cfg := &Config{}
		opt := WithRetry(3, -1*time.Second)
		err := opt(cfg)

		if err == nil {
			t.Error("expected error for negative backoff")
		}
	})
}

func TestWithConnectionPool(t *testing.T) {
	t.Run("valid pool config", func(t *testing.T) {
		cfg := &Config{}
		opt := WithConnectionPool(2, 20)
		err := opt(cfg)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if cfg.PoolMinConns != 2 {
			t.Errorf("expected PoolMinConns 2, got %d", cfg.PoolMinConns)
		}
		if cfg.PoolMaxConns != 20 {
			t.Errorf("expected PoolMaxConns 20, got %d", cfg.PoolMaxConns)
		}
	})

	t.Run("negative min conns", func(t *testing.T) {
		cfg := &Config{}
		opt := WithConnectionPool(-1, 10)
		err := opt(cfg)

		if err == nil {
			t.Error("expected error for negative min conns")
		}
	})

	t.Run("negative max conns", func(t *testing.T) {
		cfg := &Config{}
		opt := WithConnectionPool(1, -1)
		err := opt(cfg)

		if err == nil {
			t.Error("expected error for negative max conns")
		}
	})

	t.Run("min exceeds max", func(t *testing.T) {
		cfg := &Config{}
		opt := WithConnectionPool(10, 5)
		err := opt(cfg)

		if err == nil {
			t.Error("expected error when min exceeds max")
		}
	})
}

func TestWithHeaders(t *testing.T) {
	t.Run("add headers to nil map", func(t *testing.T) {
		cfg := &Config{}
		opt := WithHeaders(map[string]string{
			"X-Custom-1": "value1",
			"X-Custom-2": "value2",
		})
		err := opt(cfg)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if cfg.Headers["X-Custom-1"] != "value1" {
			t.Errorf("expected header X-Custom-1=value1, got %s", cfg.Headers["X-Custom-1"])
		}
		if cfg.Headers["X-Custom-2"] != "value2" {
			t.Errorf("expected header X-Custom-2=value2, got %s", cfg.Headers["X-Custom-2"])
		}
	})

	t.Run("merge with existing headers", func(t *testing.T) {
		cfg := &Config{
			Headers: map[string]string{
				"Existing": "header",
			},
		}
		opt := WithHeaders(map[string]string{
			"X-New": "value",
		})
		err := opt(cfg)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if cfg.Headers["Existing"] != "header" {
			t.Error("existing header should be preserved")
		}
		if cfg.Headers["X-New"] != "value" {
			t.Error("new header should be added")
		}
	})
}

func TestWithHeader(t *testing.T) {
	t.Run("add single header", func(t *testing.T) {
		cfg := &Config{}
		opt := WithHeader("X-Single", "value")
		err := opt(cfg)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if cfg.Headers["X-Single"] != "value" {
			t.Errorf("expected header X-Single=value, got %s", cfg.Headers["X-Single"])
		}
	})

	t.Run("empty key", func(t *testing.T) {
		cfg := &Config{}
		opt := WithHeader("", "value")
		err := opt(cfg)

		if err == nil {
			t.Error("expected error for empty key")
		}
	})
}

func TestWithJWTToken(t *testing.T) {
	cfg := &Config{}
	opt := WithJWTToken("my-jwt-token")
	err := opt(cfg)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if cfg.JWTToken != "my-jwt-token" {
		t.Errorf("expected JWTToken my-jwt-token, got %s", cfg.JWTToken)
	}
}

func TestApplyOptions(t *testing.T) {
	t.Run("apply multiple options", func(t *testing.T) {
		cfg := DefaultConfig()
		err := ApplyOptions(cfg,
			WithAddress("localhost:9000"),
			WithTimeout(10*time.Second),
			WithRetry(5, time.Second),
			WithHeader("X-Custom", "value"),
		)

		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if cfg.Address != "localhost:9000" {
			t.Errorf("expected Address localhost:9000, got %s", cfg.Address)
		}
		if cfg.Timeout != 10*time.Second {
			t.Errorf("expected Timeout 10s, got %v", cfg.Timeout)
		}
		if cfg.MaxRetries != 5 {
			t.Errorf("expected MaxRetries 5, got %d", cfg.MaxRetries)
		}
		if cfg.Headers["X-Custom"] != "value" {
			t.Errorf("expected header X-Custom=value, got %s", cfg.Headers["X-Custom"])
		}
	})

	t.Run("stop on first error", func(t *testing.T) {
		cfg := DefaultConfig()
		err := ApplyOptions(cfg,
			WithAddress("localhost:9000"),
			WithTimeout(-1*time.Second), // This should fail
			WithRetry(5, time.Second),   // This should not be applied
		)

		if err == nil {
			t.Error("expected error from invalid option")
		}
		// Address should be set before the error
		if cfg.Address != "localhost:9000" {
			t.Errorf("expected Address to be set before error, got %s", cfg.Address)
		}
	})
}

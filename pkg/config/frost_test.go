// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"strings"
	"testing"
)

// TestFrostConfig_Validate_Success covers the configurations FrostConfig.Validate
// must accept, including default-filling for Algorithm, DefaultThreshold, and
// DefaultTotal.
func TestFrostConfig_Validate_Success(t *testing.T) {
	tests := []struct {
		name          string
		cfg           FrostConfig
		wantAlgorithm string
		wantThreshold int
		wantTotal     int
	}{
		{
			name:          "disabled backend is a no-op regardless of other fields",
			cfg:           FrostConfig{Enabled: false},
			wantAlgorithm: "",
			wantThreshold: 0,
			wantTotal:     0,
		},
		{
			name: "fully specified",
			cfg: FrostConfig{
				Enabled:          true,
				PublicPath:       "/data/frost/public",
				SecretBackend:    "tpm2",
				Algorithm:        "FROST-P256-SHA256",
				DefaultThreshold: 3,
				DefaultTotal:     5,
			},
			wantAlgorithm: "FROST-P256-SHA256",
			wantThreshold: 3,
			wantTotal:     5,
		},
		{
			name: "defaults fill algorithm, threshold, and total",
			cfg: FrostConfig{
				Enabled:       true,
				PublicPath:    "/data/frost/public",
				SecretBackend: "software",
			},
			wantAlgorithm: "FROST-Ed25519-SHA512",
			wantThreshold: 2,
			wantTotal:     3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}
			if cfg.Algorithm != tt.wantAlgorithm {
				t.Errorf("Algorithm = %q, want %q", cfg.Algorithm, tt.wantAlgorithm)
			}
			if cfg.DefaultThreshold != tt.wantThreshold {
				t.Errorf("DefaultThreshold = %d, want %d", cfg.DefaultThreshold, tt.wantThreshold)
			}
			if cfg.DefaultTotal != tt.wantTotal {
				t.Errorf("DefaultTotal = %d, want %d", cfg.DefaultTotal, tt.wantTotal)
			}
		})
	}
}

// TestFrostConfig_Validate_Errors covers every invalid backends.frost
// configuration FrostConfig.Validate must reject, and that it reports the
// typed *FrostConfigError with the offending field.
func TestFrostConfig_Validate_Errors(t *testing.T) {
	tests := []struct {
		name      string
		cfg       FrostConfig
		wantField string
	}{
		{
			name:      "missing public_path",
			cfg:       FrostConfig{Enabled: true, SecretBackend: "tpm2"},
			wantField: "public_path",
		},
		{
			name:      "missing secret_backend",
			cfg:       FrostConfig{Enabled: true, PublicPath: "/data/frost/public"},
			wantField: "secret_backend",
		},
		{
			name: "unknown secret_backend name",
			cfg: FrostConfig{
				Enabled:       true,
				PublicPath:    "/data/frost/public",
				SecretBackend: "phone",
			},
			wantField: "secret_backend",
		},
		{
			name: "unrecognized algorithm",
			cfg: FrostConfig{
				Enabled:       true,
				PublicPath:    "/data/frost/public",
				SecretBackend: "tpm2",
				Algorithm:     "FROST-not-a-real-suite",
			},
			wantField: "algorithm",
		},
		{
			name: "threshold below minimum",
			cfg: FrostConfig{
				Enabled:          true,
				PublicPath:       "/data/frost/public",
				SecretBackend:    "tpm2",
				DefaultThreshold: 1,
			},
			wantField: "default_threshold",
		},
		{
			name: "threshold exceeds 255",
			cfg: FrostConfig{
				Enabled:          true,
				PublicPath:       "/data/frost/public",
				SecretBackend:    "tpm2",
				DefaultThreshold: 256,
				DefaultTotal:     256,
			},
			wantField: "default_threshold",
		},
		{
			name: "total exceeds 255",
			cfg: FrostConfig{
				Enabled:          true,
				PublicPath:       "/data/frost/public",
				SecretBackend:    "tpm2",
				DefaultThreshold: 2,
				DefaultTotal:     256,
			},
			wantField: "default_total",
		},
		{
			name: "total below threshold",
			cfg: FrostConfig{
				Enabled:          true,
				PublicPath:       "/data/frost/public",
				SecretBackend:    "tpm2",
				DefaultThreshold: 4,
				DefaultTotal:     3,
			},
			wantField: "default_total",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
			var fcErr *FrostConfigError
			if !errors.As(err, &fcErr) {
				t.Fatalf("Validate() error = %v (%T), want *FrostConfigError", err, err)
			}
			if fcErr.Field != tt.wantField {
				t.Errorf("FrostConfigError.Field = %q, want %q", fcErr.Field, tt.wantField)
			}
		})
	}
}

// baseFrostTestConfig returns a Config that passes every unrelated Validate
// check, so tests can focus on the backends.frost section alone.
func baseFrostTestConfig() Config {
	return Config{
		Protocols: ProtocolsConfig{REST: true},
		Server:    ServerConfig{RESTPort: 8443},
		Logging:   LoggingConfig{Level: "info", Format: "json"},
		Datastore: DatastoreConfig{Path: "/data"},
		TLS:       TLSConfig{Enabled: true},
		Default:   "frost",
	}
}

// TestValidate_FrostBackend covers Config.Validate's cross-section checks for
// backends.frost: that secret_backend must name another backend section that
// is itself present and enabled, which FrostConfig.Validate cannot check on
// its own since it never sees the sibling BackendsConfig.
func TestValidate_FrostBackend(t *testing.T) {
	t.Run("valid frost backend referencing an enabled tpm2 backend", func(t *testing.T) {
		cfg := baseFrostTestConfig()
		cfg.Backends = BackendsConfig{
			TPM2: &TPM2Config{Enabled: true, DevicePath: "/dev/tpmrm0"},
			Frost: &FrostConfig{
				Enabled:       true,
				PublicPath:    "/data/frost/public",
				SecretBackend: "tpm2",
			},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("secret_backend names a backend section that is not configured", func(t *testing.T) {
		cfg := baseFrostTestConfig()
		cfg.Backends = BackendsConfig{
			Frost: &FrostConfig{
				Enabled:       true,
				PublicPath:    "/data/frost/public",
				SecretBackend: "tpm2",
			},
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("Validate() error = nil, want error")
		}
		if !strings.Contains(err.Error(), "not configured and enabled") {
			t.Errorf("Validate() error = %v, want error about the backend not being configured and enabled", err)
		}
	})

	t.Run("secret_backend names a backend section that is configured but disabled", func(t *testing.T) {
		cfg := baseFrostTestConfig()
		cfg.Backends = BackendsConfig{
			TPM2: &TPM2Config{Enabled: false, DevicePath: "/dev/tpmrm0"},
			Frost: &FrostConfig{
				Enabled:       true,
				PublicPath:    "/data/frost/public",
				SecretBackend: "tpm2",
			},
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatal("Validate() error = nil, want error")
		}
		var fcErr *FrostConfigError
		if !errors.As(err, &fcErr) || fcErr.Field != "secret_backend" {
			t.Errorf("Validate() error = %v, want *FrostConfigError{Field: \"secret_backend\"}", err)
		}
	})

	t.Run("disabled frost backend skips validation entirely", func(t *testing.T) {
		cfg := baseFrostTestConfig()
		cfg.Default = "pkcs8"
		cfg.Backends = BackendsConfig{
			PKCS8: &PKCS8Config{Enabled: true, Path: "/data/pkcs8"},
			Frost: &FrostConfig{Enabled: false, SecretBackend: "does-not-exist"},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})
}

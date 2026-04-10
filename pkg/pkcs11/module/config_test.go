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

package module

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if cfg.Target != DefaultTarget {
		t.Errorf("DefaultConfig().Target = %q, want %q", cfg.Target, DefaultTarget)
	}

	if cfg.Timeout != DefaultTimeout {
		t.Errorf("DefaultConfig().Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}

	if cfg.TLS.Enabled {
		t.Error("DefaultConfig().TLS.Enabled = true, want false")
	}
}

func TestConfig_SetDefaults(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		check  func(*testing.T, *Config)
	}{
		{
			name:   "empty config gets defaults",
			config: &Config{},
			check: func(t *testing.T, c *Config) {
				if c.Target != DefaultTarget {
					t.Errorf("Target = %q, want %q", c.Target, DefaultTarget)
				}
				if c.Timeout != DefaultTimeout {
					t.Errorf("Timeout = %v, want %v", c.Timeout, DefaultTimeout)
				}
			},
		},
		{
			name: "existing values preserved",
			config: &Config{
				Target:  "dns:///custom:8080",
				Timeout: 60 * time.Second,
			},
			check: func(t *testing.T, c *Config) {
				if c.Target != "dns:///custom:8080" {
					t.Errorf("Target = %q, want %q", c.Target, "dns:///custom:8080")
				}
				if c.Timeout != 60*time.Second {
					t.Errorf("Timeout = %v, want %v", c.Timeout, 60*time.Second)
				}
			},
		},
		{
			name: "partial config gets remaining defaults",
			config: &Config{
				Target: "localhost:9000",
			},
			check: func(t *testing.T, c *Config) {
				if c.Target != "localhost:9000" {
					t.Errorf("Target = %q, want %q", c.Target, "localhost:9000")
				}
				if c.Timeout != DefaultTimeout {
					t.Errorf("Timeout = %v, want %v", c.Timeout, DefaultTimeout)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.SetDefaults()
			tt.check(t, tt.config)
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	// Create temporary files for TLS testing
	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	caFile := filepath.Join(tempDir, "ca.pem")

	if err := os.WriteFile(certFile, []byte("cert"), 0600); err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("key"), 0600); err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	if err := os.WriteFile(caFile, []byte("ca"), 0600); err != nil {
		t.Fatalf("failed to create ca file: %v", err)
	}

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errType error
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errType: ErrNilConfig,
		},
		{
			name: "valid unix socket target",
			config: &Config{
				Target:  "unix:///var/run/xkms.sock",
				Timeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "valid dns target",
			config: &Config{
				Target:  "dns:///localhost:9000",
				Timeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "valid host:port target",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "empty target",
			config: &Config{
				Target:  "",
				Timeout: 30 * time.Second,
			},
			wantErr: true,
			errType: ErrEmptyTarget,
		},
		{
			name: "invalid target format",
			config: &Config{
				Target:  "invalid",
				Timeout: 30 * time.Second,
			},
			wantErr: true,
			errType: ErrInvalidTarget,
		},
		{
			name: "invalid port in target",
			config: &Config{
				Target:  "localhost:99999",
				Timeout: 30 * time.Second,
			},
			wantErr: true,
			errType: ErrInvalidTarget,
		},
		{
			name: "invalid port not a number",
			config: &Config{
				Target:  "localhost:abc",
				Timeout: 30 * time.Second,
			},
			wantErr: true,
			errType: ErrInvalidTarget,
		},
		{
			name: "empty host in target",
			config: &Config{
				Target:  ":9000",
				Timeout: 30 * time.Second,
			},
			wantErr: true,
			errType: ErrInvalidTarget,
		},
		{
			name: "negative timeout",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: -1 * time.Second,
			},
			wantErr: true,
			errType: ErrInvalidTimeout,
		},
		{
			name: "zero timeout is valid",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: 0,
			},
			wantErr: false,
		},
		{
			name: "TLS enabled with valid files",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: 30 * time.Second,
				TLS: TLSConfig{
					Enabled:  true,
					CertFile: certFile,
					KeyFile:  keyFile,
					CAFile:   caFile,
				},
			},
			wantErr: false,
		},
		{
			name: "TLS enabled with cert but no key",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: 30 * time.Second,
				TLS: TLSConfig{
					Enabled:  true,
					CertFile: certFile,
				},
			},
			wantErr: true,
			errType: ErrMissingTLSKey,
		},
		{
			name: "TLS enabled with key but no cert",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: 30 * time.Second,
				TLS: TLSConfig{
					Enabled: true,
					KeyFile: keyFile,
				},
			},
			wantErr: true,
			errType: ErrMissingTLSCert,
		},
		{
			name: "TLS enabled with non-existent cert",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: 30 * time.Second,
				TLS: TLSConfig{
					Enabled:  true,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  keyFile,
				},
			},
			wantErr: true,
			errType: ErrTLSCertNotFound,
		},
		{
			name: "TLS enabled with non-existent key",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: 30 * time.Second,
				TLS: TLSConfig{
					Enabled:  true,
					CertFile: certFile,
					KeyFile:  "/nonexistent/key.pem",
				},
			},
			wantErr: true,
			errType: ErrTLSKeyNotFound,
		},
		{
			name: "TLS enabled with non-existent CA",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: 30 * time.Second,
				TLS: TLSConfig{
					Enabled:  true,
					CertFile: certFile,
					KeyFile:  keyFile,
					CAFile:   "/nonexistent/ca.pem",
				},
			},
			wantErr: true,
			errType: ErrTLSCANotFound,
		},
		{
			name: "TLS disabled ignores missing files",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: 30 * time.Second,
				TLS: TLSConfig{
					Enabled:  false,
					CertFile: "/nonexistent/cert.pem",
					KeyFile:  "/nonexistent/key.pem",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errType != nil {
				if !errors.Is(err, tt.errType) {
					t.Errorf("Config.Validate() error = %v, want %v", err, tt.errType)
				}
			}
		})
	}
}

func TestConfig_Validate_TargetFormats(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"unix socket", "unix:///var/run/xkms.sock", false},
		{"unix socket short path", "unix:///k.sock", false},
		{"empty unix socket path", "unix://", true},
		{"dns with host and port", "dns:///localhost:9000", false},
		{"dns with domain", "dns:///xkms.example.com:443", false},
		{"empty dns address", "dns://", true},
		{"host:port", "localhost:9000", false},
		{"ip:port", "127.0.0.1:9000", false},
		{"port 1", "localhost:1", false},
		{"port 65535", "localhost:65535", false},
		{"port 0", "localhost:0", true},
		{"port too high", "localhost:65536", true},
		{"multiple colons", "local:host:9000", true},
		{"no scheme or port", "localhost", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Target:  tt.target,
				Timeout: 30 * time.Second,
			}
			err := cfg.Validate()
			// Handle empty target special case
			if tt.target == "" {
				if !errors.Is(err, ErrEmptyTarget) {
					t.Errorf("expected ErrEmptyTarget for empty target, got %v", err)
				}
				return
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() with target %q: error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Save and restore environment
	saveEnv := func(keys ...string) func() {
		saved := make(map[string]string)
		for _, k := range keys {
			saved[k] = os.Getenv(k)
		}
		return func() {
			for k, v := range saved {
				if v == "" {
					_ = os.Unsetenv(k)
				} else {
					_ = os.Setenv(k, v)
				}
			}
		}
	}

	t.Run("all environment variables", func(t *testing.T) {
		restore := saveEnv(EnvTarget, EnvTLSEnabled, EnvTLSCert, EnvTLSKey, EnvTLSCA, EnvTimeout)
		defer restore()

		_ = os.Setenv(EnvTarget, "dns:///test:8080")
		_ = os.Setenv(EnvTLSEnabled, "true")
		_ = os.Setenv(EnvTLSCert, "/path/to/cert.pem")
		_ = os.Setenv(EnvTLSKey, "/path/to/key.pem")
		_ = os.Setenv(EnvTLSCA, "/path/to/ca.pem")
		_ = os.Setenv(EnvTimeout, "60s")

		cfg := LoadFromEnv()

		if cfg.Target != "dns:///test:8080" {
			t.Errorf("Target = %q, want %q", cfg.Target, "dns:///test:8080")
		}
		if !cfg.TLS.Enabled {
			t.Error("TLS.Enabled = false, want true")
		}
		if cfg.TLS.CertFile != "/path/to/cert.pem" {
			t.Errorf("TLS.CertFile = %q, want %q", cfg.TLS.CertFile, "/path/to/cert.pem")
		}
		if cfg.TLS.KeyFile != "/path/to/key.pem" {
			t.Errorf("TLS.KeyFile = %q, want %q", cfg.TLS.KeyFile, "/path/to/key.pem")
		}
		if cfg.TLS.CAFile != "/path/to/ca.pem" {
			t.Errorf("TLS.CAFile = %q, want %q", cfg.TLS.CAFile, "/path/to/ca.pem")
		}
		if cfg.Timeout != 60*time.Second {
			t.Errorf("Timeout = %v, want %v", cfg.Timeout, 60*time.Second)
		}
	})

	t.Run("no environment variables uses defaults", func(t *testing.T) {
		restore := saveEnv(EnvTarget, EnvTLSEnabled, EnvTLSCert, EnvTLSKey, EnvTLSCA, EnvTimeout)
		defer restore()

		_ = os.Unsetenv(EnvTarget)
		_ = os.Unsetenv(EnvTLSEnabled)
		_ = os.Unsetenv(EnvTLSCert)
		_ = os.Unsetenv(EnvTLSKey)
		_ = os.Unsetenv(EnvTLSCA)
		_ = os.Unsetenv(EnvTimeout)

		cfg := LoadFromEnv()

		if cfg.Target != DefaultTarget {
			t.Errorf("Target = %q, want %q", cfg.Target, DefaultTarget)
		}
		if cfg.Timeout != DefaultTimeout {
			t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
		}
	})

	t.Run("boolean parsing variations", func(t *testing.T) {
		restore := saveEnv(EnvTLSEnabled)
		defer restore()

		boolTests := []struct {
			value string
			want  bool
		}{
			{"true", true},
			{"TRUE", true},
			{"True", true},
			{"1", true},
			{"yes", true},
			{"YES", true},
			{"on", true},
			{"ON", true},
			{"false", false},
			{"FALSE", false},
			{"0", false},
			{"no", false},
			{"off", false},
			{"invalid", false},
			{"", false},
		}

		for _, bt := range boolTests {
			_ = os.Setenv(EnvTLSEnabled, bt.value)
			cfg := LoadFromEnv()
			if cfg.TLS.Enabled != bt.want {
				t.Errorf("TLS.Enabled with %q = %v, want %v", bt.value, cfg.TLS.Enabled, bt.want)
			}
		}
	})

	t.Run("invalid timeout uses default", func(t *testing.T) {
		restore := saveEnv(EnvTimeout)
		defer restore()

		_ = os.Setenv(EnvTimeout, "invalid")
		cfg := LoadFromEnv()

		if cfg.Timeout != DefaultTimeout {
			t.Errorf("Timeout = %v, want %v (default)", cfg.Timeout, DefaultTimeout)
		}
	})
}

func TestLoadFromFile(t *testing.T) {
	t.Run("valid config file", func(t *testing.T) {
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "pkcs11.conf")

		content := `# PKCS#11 Module Configuration
target = dns:///xkms.local:9000
tls_enabled = true
tls_cert = /etc/xkms/client.crt
tls_key = /etc/xkms/client.key
tls_ca = /etc/xkms/ca.crt
timeout = 45s
`
		if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		cfg, err := LoadFromFile(configFile)
		if err != nil {
			t.Fatalf("LoadFromFile() error = %v", err)
		}

		if cfg.Target != "dns:///xkms.local:9000" {
			t.Errorf("Target = %q, want %q", cfg.Target, "dns:///xkms.local:9000")
		}
		if !cfg.TLS.Enabled {
			t.Error("TLS.Enabled = false, want true")
		}
		if cfg.TLS.CertFile != "/etc/xkms/client.crt" {
			t.Errorf("TLS.CertFile = %q, want %q", cfg.TLS.CertFile, "/etc/xkms/client.crt")
		}
		if cfg.TLS.KeyFile != "/etc/xkms/client.key" {
			t.Errorf("TLS.KeyFile = %q, want %q", cfg.TLS.KeyFile, "/etc/xkms/client.key")
		}
		if cfg.TLS.CAFile != "/etc/xkms/ca.crt" {
			t.Errorf("TLS.CAFile = %q, want %q", cfg.TLS.CAFile, "/etc/xkms/ca.crt")
		}
		if cfg.Timeout != 45*time.Second {
			t.Errorf("Timeout = %v, want %v", cfg.Timeout, 45*time.Second)
		}
	})

	t.Run("config file with comments and empty lines", func(t *testing.T) {
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "pkcs11.conf")

		content := `# This is a comment
; This is also a comment

target = localhost:9000

# Another comment
timeout = 10s
`
		if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		cfg, err := LoadFromFile(configFile)
		if err != nil {
			t.Fatalf("LoadFromFile() error = %v", err)
		}

		if cfg.Target != "localhost:9000" {
			t.Errorf("Target = %q, want %q", cfg.Target, "localhost:9000")
		}
		if cfg.Timeout != 10*time.Second {
			t.Errorf("Timeout = %v, want %v", cfg.Timeout, 10*time.Second)
		}
	})

	t.Run("config file with quoted values", func(t *testing.T) {
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "pkcs11.conf")

		content := `target = "dns:///host:9000"
tls_cert = '/path/with spaces/cert.pem'
`
		if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		cfg, err := LoadFromFile(configFile)
		if err != nil {
			t.Fatalf("LoadFromFile() error = %v", err)
		}

		if cfg.Target != "dns:///host:9000" {
			t.Errorf("Target = %q, want %q", cfg.Target, "dns:///host:9000")
		}
		if cfg.TLS.CertFile != "/path/with spaces/cert.pem" {
			t.Errorf("TLS.CertFile = %q, want %q", cfg.TLS.CertFile, "/path/with spaces/cert.pem")
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := LoadFromFile("/nonexistent/config.conf")
		if err == nil {
			t.Error("LoadFromFile() expected error for non-existent file")
		}
		if !errors.Is(err, ErrConfigFileOpen) {
			t.Errorf("LoadFromFile() error = %v, want ErrConfigFileOpen", err)
		}
	})

	t.Run("invalid line format", func(t *testing.T) {
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "pkcs11.conf")

		content := `target = localhost:9000
invalid line without equals
`
		if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		_, err := LoadFromFile(configFile)
		if err == nil {
			t.Error("LoadFromFile() expected error for invalid format")
		}
		if !errors.Is(err, ErrConfigFileParse) {
			t.Errorf("LoadFromFile() error = %v, want ErrConfigFileParse", err)
		}
	})

	t.Run("unknown key", func(t *testing.T) {
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "pkcs11.conf")

		content := `target = localhost:9000
unknown_key = value
`
		if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		_, err := LoadFromFile(configFile)
		if err == nil {
			t.Error("LoadFromFile() expected error for unknown key")
		}
		if !errors.Is(err, ErrConfigFileParse) {
			t.Errorf("LoadFromFile() error = %v, want ErrConfigFileParse", err)
		}
	})

	t.Run("invalid timeout duration", func(t *testing.T) {
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "pkcs11.conf")

		content := `target = localhost:9000
timeout = invalid
`
		if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		_, err := LoadFromFile(configFile)
		if err == nil {
			t.Error("LoadFromFile() expected error for invalid timeout")
		}
		if !errors.Is(err, ErrConfigFileParse) {
			t.Errorf("LoadFromFile() error = %v, want ErrConfigFileParse", err)
		}
	})
}

func TestLoadWithPath(t *testing.T) {
	// Save and restore environment
	envVars := []string{EnvTarget, EnvTLSEnabled, EnvTLSCert, EnvTLSKey, EnvTLSCA, EnvTimeout}
	saved := make(map[string]string)
	for _, k := range envVars {
		saved[k] = os.Getenv(k)
		_ = os.Unsetenv(k)
	}
	defer func() {
		for k, v := range saved {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	}()

	t.Run("file exists with env override", func(t *testing.T) {
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "pkcs11.conf")

		content := `target = localhost:8000
timeout = 20s
`
		if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		// Environment override
		_ = os.Setenv(EnvTarget, "localhost:9000")

		cfg, err := LoadWithPath(configFile)
		if err != nil {
			t.Fatalf("LoadWithPath() error = %v", err)
		}

		// Environment should override file
		if cfg.Target != "localhost:9000" {
			t.Errorf("Target = %q, want %q (from env)", cfg.Target, "localhost:9000")
		}
		// File value should be used for non-overridden
		if cfg.Timeout != 20*time.Second {
			t.Errorf("Timeout = %v, want %v (from file)", cfg.Timeout, 20*time.Second)
		}

		_ = os.Unsetenv(EnvTarget)
	})

	t.Run("file does not exist uses defaults and env", func(t *testing.T) {
		_ = os.Setenv(EnvTarget, "localhost:7000")

		cfg, err := LoadWithPath("/nonexistent/config.conf")
		if err != nil {
			t.Fatalf("LoadWithPath() error = %v", err)
		}

		if cfg.Target != "localhost:7000" {
			t.Errorf("Target = %q, want %q (from env)", cfg.Target, "localhost:7000")
		}
		if cfg.Timeout != DefaultTimeout {
			t.Errorf("Timeout = %v, want %v (default)", cfg.Timeout, DefaultTimeout)
		}

		_ = os.Unsetenv(EnvTarget)
	})

	t.Run("validation error", func(t *testing.T) {
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "pkcs11.conf")

		content := `target = invalid
`
		if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		_, err := LoadWithPath(configFile)
		if err == nil {
			t.Error("LoadWithPath() expected validation error")
		}
	})
}

func TestConfig_String(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   []string
	}{
		{
			name: "basic config",
			config: &Config{
				Target:  "localhost:9000",
				Timeout: 30 * time.Second,
				TLS: TLSConfig{
					Enabled: false,
				},
			},
			want: []string{"localhost:9000", "disabled", "30s"},
		},
		{
			name: "TLS enabled",
			config: &Config{
				Target:  "dns:///secure:443",
				Timeout: 60 * time.Second,
				TLS: TLSConfig{
					Enabled:  true,
					CertFile: "/secret/cert.pem",
					KeyFile:  "/secret/key.pem",
				},
			},
			want: []string{"dns:///secure:443", "enabled", "1m0s"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.String()
			for _, w := range tt.want {
				if !strings.Contains(result, w) {
					t.Errorf("Config.String() = %q, missing %q", result, w)
				}
			}
			// Ensure sensitive paths are not exposed (just the status)
			if strings.Contains(result, "/secret/") {
				t.Error("Config.String() should not expose file paths")
			}
		})
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"  true  ", true},
		{"1", true},
		{"yes", true},
		{"YES", true},
		{"on", true},
		{"ON", true},
		{"false", false},
		{"FALSE", false},
		{"False", false},
		{"0", false},
		{"no", false},
		{"NO", false},
		{"off", false},
		{"OFF", false},
		{"", false},
		{"invalid", false},
		{"maybe", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseBool(tt.input)
			if got != tt.want {
				t.Errorf("parseBool(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTrimQuotes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"quoted"`, "quoted"},
		{`'single quoted'`, "single quoted"},
		{`no quotes`, "no quotes"},
		{`"`, `"`},
		{`""`, ""},
		{`''`, ""},
		{`"mismatched'`, `"mismatched'`},
		{`'mismatched"`, `'mismatched"`},
		{``, ``},
		{`"partial`, `"partial`},
		{`partial"`, `partial"`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := trimQuotes(tt.input)
			if got != tt.want {
				t.Errorf("trimQuotes(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"unix socket valid", "unix:///var/run/sock", false},
		{"unix socket root", "unix:///sock", false},
		{"unix socket empty path", "unix://", true},
		{"dns valid", "dns:///host:9000", false},
		{"dns with slash", "dns:///service:443", false},
		{"dns empty", "dns://", true},
		{"host:port valid", "localhost:9000", false},
		{"ip:port valid", "192.168.1.1:8080", false},
		{"port 1", "host:1", false},
		{"port 65535", "host:65535", false},
		{"port 0 invalid", "host:0", true},
		{"port too high", "host:65536", true},
		{"port negative via wrap", "host:-1", true},
		{"no port", "hostname", true},
		{"empty host", ":9000", true},
		{"multiple colons", "a:b:c", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTarget(tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTarget(%q) error = %v, wantErr %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

func TestLoadFromEnv_AutoInitToken(t *testing.T) {
	// Save and restore environment
	envVars := []string{EnvAutoInitToken, EnvSOPIN, EnvUserPIN, EnvTokenLabel}
	saved := make(map[string]string)
	for _, k := range envVars {
		saved[k] = os.Getenv(k)
	}
	defer func() {
		for k, v := range saved {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	}()

	t.Run("auto init token environment variables", func(t *testing.T) {
		_ = os.Setenv(EnvAutoInitToken, "true")
		_ = os.Setenv(EnvSOPIN, "12345678")
		_ = os.Setenv(EnvUserPIN, "87654321")
		_ = os.Setenv(EnvTokenLabel, "TestToken")

		cfg := LoadFromEnv()

		if !cfg.AutoInitToken {
			t.Error("AutoInitToken = false, want true")
		}
		if cfg.SOPIN != "12345678" {
			t.Errorf("SOPIN = %q, want %q", cfg.SOPIN, "12345678")
		}
		if cfg.UserPIN != "87654321" {
			t.Errorf("UserPIN = %q, want %q", cfg.UserPIN, "87654321")
		}
		if cfg.TokenLabel != "TestToken" {
			t.Errorf("TokenLabel = %q, want %q", cfg.TokenLabel, "TestToken")
		}
	})

	t.Run("auto init token defaults to false", func(t *testing.T) {
		_ = os.Unsetenv(EnvAutoInitToken)
		_ = os.Unsetenv(EnvSOPIN)
		_ = os.Unsetenv(EnvUserPIN)
		_ = os.Unsetenv(EnvTokenLabel)

		cfg := LoadFromEnv()

		if cfg.AutoInitToken {
			t.Error("AutoInitToken = true, want false (default)")
		}
		if cfg.SOPIN != "" {
			t.Errorf("SOPIN = %q, want empty", cfg.SOPIN)
		}
		if cfg.UserPIN != "" {
			t.Errorf("UserPIN = %q, want empty", cfg.UserPIN)
		}
		if cfg.TokenLabel != "" {
			t.Errorf("TokenLabel = %q, want empty", cfg.TokenLabel)
		}
	})
}

func TestLoadFromFile_AutoInitToken(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "pkcs11.conf")

	content := `target = localhost:9000
auto_init_token = true
so_pin = 12345678
user_pin = 87654321
token_label = TestToken
`
	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadFromFile(configFile)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if !cfg.AutoInitToken {
		t.Error("AutoInitToken = false, want true")
	}
	if cfg.SOPIN != "12345678" {
		t.Errorf("SOPIN = %q, want %q", cfg.SOPIN, "12345678")
	}
	if cfg.UserPIN != "87654321" {
		t.Errorf("UserPIN = %q, want %q", cfg.UserPIN, "87654321")
	}
	if cfg.TokenLabel != "TestToken" {
		t.Errorf("TokenLabel = %q, want %q", cfg.TokenLabel, "TestToken")
	}
}

func TestApplyEnvOverrides_AutoInitToken(t *testing.T) {
	// Save and restore environment
	envVars := []string{EnvAutoInitToken, EnvSOPIN, EnvUserPIN, EnvTokenLabel}
	saved := make(map[string]string)
	for _, k := range envVars {
		saved[k] = os.Getenv(k)
	}
	defer func() {
		for k, v := range saved {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	}()

	// Set environment variables
	_ = os.Setenv(EnvAutoInitToken, "true")
	_ = os.Setenv(EnvSOPIN, "overrideSO")
	_ = os.Setenv(EnvUserPIN, "overrideUser")
	_ = os.Setenv(EnvTokenLabel, "OverrideToken")

	// Start with a config with different values
	cfg := &Config{
		Target:        "localhost:9000",
		AutoInitToken: false,
		SOPIN:         "originalSO",
		UserPIN:       "originalUser",
		TokenLabel:    "OriginalToken",
	}

	applyEnvOverrides(cfg)

	if !cfg.AutoInitToken {
		t.Error("AutoInitToken = false, want true (from env)")
	}
	if cfg.SOPIN != "overrideSO" {
		t.Errorf("SOPIN = %q, want %q", cfg.SOPIN, "overrideSO")
	}
	if cfg.UserPIN != "overrideUser" {
		t.Errorf("UserPIN = %q, want %q", cfg.UserPIN, "overrideUser")
	}
	if cfg.TokenLabel != "OverrideToken" {
		t.Errorf("TokenLabel = %q, want %q", cfg.TokenLabel, "OverrideToken")
	}
}

func TestConfig_StorageDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.StorageType != StorageTypeMemory {
		t.Errorf("DefaultConfig().StorageType = %q, want %q", cfg.StorageType, StorageTypeMemory)
	}

	if cfg.StoragePath != "" {
		t.Errorf("DefaultConfig().StoragePath = %q, want empty", cfg.StoragePath)
	}
}

func TestConfig_SetDefaults_Storage(t *testing.T) {
	cfg := &Config{}
	cfg.SetDefaults()

	if cfg.StorageType != StorageTypeMemory {
		t.Errorf("StorageType after SetDefaults = %q, want %q", cfg.StorageType, StorageTypeMemory)
	}
}

func TestConfig_Validate_Storage(t *testing.T) {
	tests := []struct {
		name        string
		storageType string
		storagePath string
		wantErr     error
	}{
		{
			name:        "memory storage valid",
			storageType: StorageTypeMemory,
			storagePath: "",
			wantErr:     nil,
		},
		{
			name:        "file storage with path",
			storageType: StorageTypeFile,
			storagePath: "/tmp/pkcs11",
			wantErr:     nil,
		},
		{
			name:        "file storage without path",
			storageType: StorageTypeFile,
			storagePath: "",
			wantErr:     ErrStoragePathRequired,
		},
		{
			name:        "unknown storage type",
			storageType: "unknown",
			storagePath: "",
			wantErr:     ErrInvalidStorageType,
		},
		{
			name:        "empty storage type defaults to memory",
			storageType: "",
			storagePath: "",
			wantErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Target:      "localhost:9090",
				StorageType: tt.storageType,
				StoragePath: tt.storagePath,
			}

			err := cfg.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Validate() = nil, want error containing %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Validate() = %v, want error containing %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestLoadFromEnv_Storage(t *testing.T) {
	// Save and restore environment
	origType := os.Getenv(EnvStorageType)
	origPath := os.Getenv(EnvStoragePath)
	defer func() {
		_ = os.Setenv(EnvStorageType, origType)
		_ = os.Setenv(EnvStoragePath, origPath)
	}()

	_ = os.Setenv(EnvStorageType, "file")
	_ = os.Setenv(EnvStoragePath, "/tmp/test-storage")

	cfg := LoadFromEnv()

	if cfg.StorageType != "file" {
		t.Errorf("StorageType = %q, want %q", cfg.StorageType, "file")
	}
	if cfg.StoragePath != "/tmp/test-storage" {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, "/tmp/test-storage")
	}
}

func TestLoadFromFile_Storage(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "pkcs11.conf")

	content := `target = localhost:9090
storage_type = file
storage_path = /var/lib/pkcs11
`
	if err := os.WriteFile(configFile, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := LoadFromFile(configFile)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if cfg.StorageType != "file" {
		t.Errorf("StorageType = %q, want %q", cfg.StorageType, "file")
	}
	if cfg.StoragePath != "/var/lib/pkcs11" {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, "/var/lib/pkcs11")
	}
}

func TestApplyEnvOverrides_Storage(t *testing.T) {
	// Save and restore environment
	origType := os.Getenv(EnvStorageType)
	origPath := os.Getenv(EnvStoragePath)
	defer func() {
		_ = os.Setenv(EnvStorageType, origType)
		_ = os.Setenv(EnvStoragePath, origPath)
	}()

	cfg := &Config{
		Target:      "localhost:9090",
		StorageType: "memory",
		StoragePath: "",
	}

	_ = os.Setenv(EnvStorageType, "file")
	_ = os.Setenv(EnvStoragePath, "/override/path")

	applyEnvOverrides(cfg)

	if cfg.StorageType != "file" {
		t.Errorf("StorageType = %q, want %q", cfg.StorageType, "file")
	}
	if cfg.StoragePath != "/override/path" {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, "/override/path")
	}
}

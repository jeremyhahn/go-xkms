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

package providers

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnvFileNotFoundError(t *testing.T) {
	t.Run("error message format", func(t *testing.T) {
		innerErr := errors.New("file does not exist")
		err := &EnvFileNotFoundError{
			EnvVar:   "API_KEY",
			FilePath: "/run/secrets/api_key",
			Err:      innerErr,
		}

		expected := "env file not found: API_KEY_FILE=/run/secrets/api_key: file does not exist"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("unwrap returns inner error", func(t *testing.T) {
		innerErr := errors.New("permission denied")
		err := &EnvFileNotFoundError{
			EnvVar:   "SECRET",
			FilePath: "/secrets/key",
			Err:      innerErr,
		}

		if unwrapped := err.Unwrap(); unwrapped != innerErr {
			t.Errorf("Unwrap() returned wrong error: got %v, want %v", unwrapped, innerErr)
		}
	})

	t.Run("errors.Is works with unwrap", func(t *testing.T) {
		innerErr := os.ErrNotExist
		err := &EnvFileNotFoundError{
			EnvVar:   "TOKEN",
			FilePath: "/path/to/token",
			Err:      innerErr,
		}

		if !errors.Is(err, os.ErrNotExist) {
			t.Error("errors.Is should match os.ErrNotExist")
		}
	})
}

func TestGetEnvOrFile(t *testing.T) {
	t.Run("returns direct env var value", func(t *testing.T) {
		const envVar = "TEST_ENV_DIRECT"
		const expected = "direct-value"

		t.Setenv(envVar, expected)

		value, err := GetEnvOrFile(envVar)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if value != expected {
			t.Errorf("expected %q, got %q", expected, value)
		}
	})

	t.Run("prefers direct env var over file", func(t *testing.T) {
		const envVar = "TEST_ENV_PREFER_DIRECT"
		const directValue = "direct"

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "secret")
		if err := os.WriteFile(filePath, []byte("from-file"), 0600); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		t.Setenv(envVar, directValue)
		t.Setenv(envVar+"_FILE", filePath)

		value, err := GetEnvOrFile(envVar)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if value != directValue {
			t.Errorf("expected direct value %q, got %q", directValue, value)
		}
	})

	t.Run("reads from file when env var not set", func(t *testing.T) {
		const envVar = "TEST_ENV_FROM_FILE"
		const expected = "secret-from-file"

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "secret")
		if err := os.WriteFile(filePath, []byte(expected), 0600); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		t.Setenv(envVar+"_FILE", filePath)

		value, err := GetEnvOrFile(envVar)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if value != expected {
			t.Errorf("expected %q, got %q", expected, value)
		}
	})

	t.Run("trims whitespace from file content", func(t *testing.T) {
		const envVar = "TEST_ENV_TRIM_WHITESPACE"
		const expected = "trimmed-value"

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "secret")
		if err := os.WriteFile(filePath, []byte("  "+expected+"  \n"), 0600); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}

		t.Setenv(envVar+"_FILE", filePath)

		value, err := GetEnvOrFile(envVar)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if value != expected {
			t.Errorf("expected %q, got %q", expected, value)
		}
	})

	t.Run("returns empty string when neither set", func(t *testing.T) {
		const envVar = "TEST_ENV_NOT_SET_ANYWHERE"

		value, err := GetEnvOrFile(envVar)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if value != "" {
			t.Errorf("expected empty string, got %q", value)
		}
	})

	t.Run("returns error when file does not exist", func(t *testing.T) {
		const envVar = "TEST_ENV_FILE_NOT_FOUND"

		t.Setenv(envVar+"_FILE", "/nonexistent/path/to/secret")

		_, err := GetEnvOrFile(envVar)
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}

		var envFileErr *EnvFileNotFoundError
		if !errors.As(err, &envFileErr) {
			t.Errorf("expected EnvFileNotFoundError, got %T", err)
		}
		if envFileErr.EnvVar != envVar {
			t.Errorf("expected EnvVar %q, got %q", envVar, envFileErr.EnvVar)
		}
	})
}

func TestGetEnvOrDefault(t *testing.T) {
	t.Run("returns env var when set", func(t *testing.T) {
		const envVar = "TEST_DEFAULT_SET"
		const expected = "custom-value"

		t.Setenv(envVar, expected)

		value := GetEnvOrDefault(envVar, "default")
		if value != expected {
			t.Errorf("expected %q, got %q", expected, value)
		}
	})

	t.Run("returns default when not set", func(t *testing.T) {
		const envVar = "TEST_DEFAULT_NOT_SET"
		const expected = "default-value"

		value := GetEnvOrDefault(envVar, expected)
		if value != expected {
			t.Errorf("expected %q, got %q", expected, value)
		}
	})

	t.Run("returns default when empty", func(t *testing.T) {
		const envVar = "TEST_DEFAULT_EMPTY"
		const expected = "default-value"

		t.Setenv(envVar, "")

		value := GetEnvOrDefault(envVar, expected)
		if value != expected {
			t.Errorf("expected %q, got %q", expected, value)
		}
	})
}

func TestGetEnvDuration(t *testing.T) {
	tests := []struct {
		name         string
		envValue     string
		defaultValue time.Duration
		expected     time.Duration
	}{
		{
			name:         "parses seconds",
			envValue:     "30s",
			defaultValue: time.Minute,
			expected:     30 * time.Second,
		},
		{
			name:         "returns default when empty",
			envValue:     "",
			defaultValue: 5 * time.Minute,
			expected:     5 * time.Minute,
		},
		{
			name:         "returns default when invalid",
			envValue:     "invalid",
			defaultValue: 10 * time.Second,
			expected:     10 * time.Second,
		},
		{
			name:         "returns default when numeric without unit",
			envValue:     "100",
			defaultValue: time.Minute,
			expected:     time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envVar := "TEST_DURATION_" + tt.name
			if tt.envValue != "" {
				t.Setenv(envVar, tt.envValue)
			}

			result := GetEnvDuration(envVar, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name         string
		envValue     string
		defaultValue int
		expected     int
	}{
		{
			name:         "parses positive integer",
			envValue:     "42",
			defaultValue: 0,
			expected:     42,
		},
		{
			name:         "parses zero",
			envValue:     "0",
			defaultValue: 100,
			expected:     0,
		},
		{
			name:         "returns default when empty",
			envValue:     "",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "returns default when invalid",
			envValue:     "not-a-number",
			defaultValue: 50,
			expected:     50,
		},
		{
			name:         "returns default when has spaces",
			envValue:     "  42  ",
			defaultValue: 0,
			expected:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envVar := "TEST_INT_" + tt.name
			if tt.envValue != "" {
				t.Setenv(envVar, tt.envValue)
			}

			result := GetEnvInt(envVar, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name         string
		envValue     string
		defaultValue bool
		expected     bool
	}{
		// Standard bool values
		{
			name:         "parses true",
			envValue:     "true",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "parses false",
			envValue:     "false",
			defaultValue: true,
			expected:     false,
		},
		// Extended values (yes/no, on/off)
		{
			name:         "parses yes as true",
			envValue:     "yes",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "parses no as false",
			envValue:     "no",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "parses YES uppercase",
			envValue:     "YES",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "parses on as true",
			envValue:     "on",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "parses off as false",
			envValue:     "off",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "parses OFF uppercase",
			envValue:     "OFF",
			defaultValue: true,
			expected:     false,
		},
		// Default fallback
		{
			name:         "returns default when empty",
			envValue:     "",
			defaultValue: true,
			expected:     true,
		},
		{
			name:         "returns default when invalid",
			envValue:     "invalid",
			defaultValue: false,
			expected:     false,
		},
		{
			name:         "returns default true when invalid",
			envValue:     "maybe",
			defaultValue: true,
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envVar := "TEST_BOOL_" + tt.name
			if tt.envValue != "" {
				t.Setenv(envVar, tt.envValue)
			}

			result := GetEnvBool(envVar, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

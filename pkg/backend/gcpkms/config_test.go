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

//go:build gcpkms

package gcpkms

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
)

func TestConfig_Validate(t *testing.T) {
	// Create temporary credentials file for testing
	tmpDir := t.TempDir()
	credsFile := filepath.Join(tmpDir, "creds.json")
	if err := os.WriteFile(credsFile, []byte(`{"type":"service_account"}`), 0644); err != nil {
		t.Fatalf("Failed to create test credentials file: %v", err)
	}

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errType error
	}{
		{
			name: "valid minimal config",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: false,
		},
		{
			name: "valid config with all fields",
			config: &Config{
				ProjectID:       "test-project",
				LocationID:      "us-central1",
				KeyRingID:       "test-keyring",
				CredentialsFile: credsFile,
				Endpoint:        "localhost:8080",
				Debug:           true,
				KeyStorage:      memory.New(),
				CertStorage:     memory.New(),
			},
			wantErr: false,
		},
		{
			name: "valid config with credentials JSON",
			config: &Config{
				ProjectID:       "test-project",
				LocationID:      "us-central1",
				KeyRingID:       "test-keyring",
				CredentialsJSON: []byte(`{"type":"service_account"}`),
				KeyStorage:      memory.New(),
				CertStorage:     memory.New(),
			},
			wantErr: false,
		},
		{
			name: "valid config with global location",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "global",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "missing project ID",
			config: &Config{
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidProjectID,
		},
		{
			name: "empty project ID",
			config: &Config{
				ProjectID:   "",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidProjectID,
		},
		{
			name: "missing location ID",
			config: &Config{
				ProjectID:   "test-project",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidLocationID,
		},
		{
			name: "empty location ID",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidLocationID,
		},
		{
			name: "missing key ring ID",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidKeyRingID,
		},
		{
			name: "empty key ring ID",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidKeyRingID,
		},
		{
			name: "nonexistent credentials file",
			config: &Config{
				ProjectID:       "test-project",
				LocationID:      "us-central1",
				KeyRingID:       "test-keyring",
				CredentialsFile: "/nonexistent/path/to/creds.json",
				KeyStorage:      memory.New(),
				CertStorage:     memory.New(),
			},
			wantErr: true,
			errType: ErrInvalidCredentials,
		},
		{
			name: "credentials JSON takes precedence over file",
			config: &Config{
				ProjectID:       "test-project",
				LocationID:      "us-central1",
				KeyRingID:       "test-keyring",
				CredentialsFile: "/nonexistent/path/to/creds.json",
				CredentialsJSON: []byte(`{"type":"service_account"}`),
				KeyStorage:      memory.New(),
				CertStorage:     memory.New(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Error("Validate() expected error, got nil")
					return
				}
				if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("Validate() error = %v, want error containing %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestConfig_KeyRingName(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{
			name: "standard key ring",
			config: &Config{
				ProjectID:   "my-project",
				LocationID:  "us-east1",
				KeyRingID:   "my-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			expected: "projects/my-project/locations/us-east1/keyRings/my-keyring",
		},
		{
			name: "global location",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "global",
				KeyRingID:   "global-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			expected: "projects/test-project/locations/global/keyRings/global-keyring",
		},
		{
			name: "multi-region location",
			config: &Config{
				ProjectID:   "prod-project",
				LocationID:  "nam4",
				KeyRingID:   "prod-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			expected: "projects/prod-project/locations/nam4/keyRings/prod-keyring",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.KeyRingName()
			if result != tt.expected {
				t.Errorf("KeyRingName() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConfig_String(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		contains []string
	}{
		{
			name: "minimal config",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			contains: []string{
				"test-project",
				"us-central1",
				"test-keyring",
				"<not set>",
				"<default>",
				"Debug: false",
			},
		},
		{
			name: "config with credentials file",
			config: &Config{
				ProjectID:       "test-project",
				LocationID:      "us-central1",
				KeyRingID:       "test-keyring",
				CredentialsFile: "/path/to/credentials.json",
				KeyStorage:      memory.New(),
				CertStorage:     memory.New(),
			},
			contains: []string{
				"test-project",
				"us-central1",
				"test-keyring",
				"credentials.json",
			},
		},
		{
			name: "config with credentials JSON",
			config: &Config{
				ProjectID:       "test-project",
				LocationID:      "us-central1",
				KeyRingID:       "test-keyring",
				CredentialsJSON: []byte(`{"type":"service_account"}`),
				KeyStorage:      memory.New(),
				CertStorage:     memory.New(),
			},
			contains: []string{
				"test-project",
				"us-central1",
				"test-keyring",
				"<json:",
				"bytes>",
			},
		},
		{
			name: "config with custom endpoint",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				Endpoint:    "localhost:8080",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			contains: []string{
				"test-project",
				"us-central1",
				"test-keyring",
				"localhost:8080",
			},
		},
		{
			name: "config with debug enabled",
			config: &Config{
				ProjectID:   "test-project",
				LocationID:  "us-central1",
				KeyRingID:   "test-keyring",
				Debug:       true,
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			contains: []string{
				"test-project",
				"us-central1",
				"test-keyring",
				"Debug: true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.String()

			for _, expected := range tt.contains {
				if !contains(result, expected) {
					t.Errorf("String() output missing expected substring %q\nGot: %s", expected, result)
				}
			}

			// Verify sensitive data is masked
			if tt.config.CredentialsFile != "" {
				// Should not contain full path
				if contains(result, "/path/to/") {
					t.Errorf("String() should mask middle path components, got: %s", result)
				}
			}
		})
	}
}

func TestMaskPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "empty path",
			path:     "",
			expected: "",
		},
		{
			name:     "short path",
			path:     "/creds.json",
			expected: "/creds.json",
		},
		{
			name:     "two component path",
			path:     "/path/creds.json",
			expected: "/creds.json",
		},
		{
			name:     "long path",
			path:     "/home/user/secrets/credentials.json",
			expected: "/.../credentials.json",
		},
		{
			name:     "very long path",
			path:     "/var/lib/secrets/app/config/credentials.json",
			expected: "/.../credentials.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskPath(tt.path)
			if result != tt.expected {
				t.Errorf("maskPath() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

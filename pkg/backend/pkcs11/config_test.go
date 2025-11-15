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

//go:build pkcs11

package pkcs11

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage/memory"
)

func TestConfig_Validate(t *testing.T) {
	// Create a temporary library file for testing
	tempDir := t.TempDir()
	tempLib := filepath.Join(tempDir, "libtest.so")
	if err := os.WriteFile(tempLib, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp library file: %v", err)
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
			errType: ErrInvalidConfig,
		},
		{
			name: "valid config",
			config: &Config{
				CN:          "test",
				Library:     tempLib,
				TokenLabel:  "test-token",
				PIN:         "1234",
				SOPIN:       "5678",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
			},
			wantErr: false,
		},
		{
			name: "missing library",
			config: &Config{
				CN:         "test",
				Library:    "",
				TokenLabel: "test-token",
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "library not found",
			config: &Config{
				CN:         "test",
				Library:    "/nonexistent/lib.so",
				TokenLabel: "test-token",
			},
			wantErr: true,
			errType: ErrLibraryNotFound,
		},
		{
			name: "missing token label",
			config: &Config{
				CN:         "test",
				Library:    tempLib,
				TokenLabel: "",
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "PIN too short",
			config: &Config{
				CN:         "test",
				Library:    tempLib,
				TokenLabel: "test-token",
				PIN:        "123",
			},
			wantErr: true,
			errType: ErrInvalidPINLength,
		},
		{
			name: "SOPIN too short",
			config: &Config{
				CN:         "test",
				Library:    tempLib,
				TokenLabel: "test-token",
				SOPIN:      "12",
			},
			wantErr: true,
			errType: ErrInvalidSOPINLength,
		},
		{
			name: "empty PIN is allowed",
			config: &Config{
				CN:          "test",
				Library:     tempLib,
				TokenLabel:  "test-token",
				PIN:         "",
				KeyStorage:  memory.New(),
				CertStorage: memory.New(),
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
				// Check for typed errors using errors.Is
				if !errors.Is(err, tt.errType) {
					t.Errorf("Config.Validate() error = %v, want %v", err, tt.errType)
				}
			}
		})
	}
}

func TestConfig_IsSoftHSM(t *testing.T) {
	tests := []struct {
		name    string
		library string
		want    bool
	}{
		{
			name:    "SoftHSM library",
			library: "/usr/lib/softhsm/libsofthsm2.so",
			want:    true,
		},
		{
			name:    "SoftHSM on macOS",
			library: "/usr/local/lib/libsofthsm2.so",
			want:    true,
		},
		{
			name:    "YubiKey library",
			library: "/usr/lib/libykcs11.so",
			want:    false,
		},
		{
			name:    "nCipher library",
			library: "/opt/nfast/toolkits/pkcs11/libcknfast.so",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Library: tt.library}
			if got := c.IsSoftHSM(); got != tt.want {
				t.Errorf("Config.IsSoftHSM() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_String(t *testing.T) {
	slot := 0
	config := &Config{
		CN:         "test-hsm",
		Library:    "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "test-token",
		Slot:       &slot,
		PIN:        "secret1234",
		SOPIN:      "sosecret5678",
	}

	result := config.String()

	// Verify sensitive data is masked
	if strings.Contains(result, "secret1234") {
		t.Error("Config.String() should mask PIN but contains actual PIN")
	}
	if strings.Contains(result, "sosecret5678") {
		t.Error("Config.String() should mask SOPIN but contains actual SOPIN")
	}

	// Verify non-sensitive data is present
	if !strings.Contains(result, "test-hsm") {
		t.Error("Config.String() should contain CN")
	}
	if !strings.Contains(result, "test-token") {
		t.Error("Config.String() should contain TokenLabel")
	}
	if !strings.Contains(result, "libsofthsm2.so") {
		t.Error("Config.String() should contain Library path")
	}

	// Test with empty PINs
	emptyConfig := &Config{
		CN:         "test",
		Library:    "/usr/lib/test.so",
		TokenLabel: "token",
	}
	emptyResult := emptyConfig.String()
	if !strings.Contains(emptyResult, "<not set>") {
		t.Error("Config.String() should indicate when PIN is not set")
	}
}

func TestSoftHSMConfig(t *testing.T) {
	tokenDir := "/tmp/softhsm/tokens"
	config := SoftHSMConfig(tokenDir)

	// Verify required elements are present
	required := []string{
		tokenDir,
		"directories.tokendir",
		"objectstore.backend = file",
		"log.level = ERROR",
		"slots.removable = false",
		"slots.mechanisms = ALL",
		"library.reset_on_fork = false",
	}

	for _, req := range required {
		if !strings.Contains(config, req) {
			t.Errorf("SoftHSMConfig() missing required element: %s", req)
		}
	}

	// Verify it's valid configuration format (contains key = value pairs)
	if !strings.Contains(config, "=") {
		t.Error("SoftHSMConfig() should contain key=value configuration pairs")
	}
}

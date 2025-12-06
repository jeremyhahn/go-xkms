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

//go:build awskms

package awskms

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// TestConfigValidate tests the Config.Validate method.
func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errType error
	}{
		{
			name: "valid minimal config",
			config: &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantErr: false,
		},
		{
			name: "valid config with credentials",
			config: &Config{
				Region:          "us-west-2",
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				KeyStorage:      storage.New(),
				CertStorage:     storage.New(),
			},
			wantErr: false,
		},
		{
			name: "valid config with session token",
			config: &Config{
				Region:          "eu-west-1",
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "FwoGZXIvYXdzEBYaDCAMPLE",
				KeyStorage:      storage.New(),
				CertStorage:     storage.New(),
			},
			wantErr: false,
		},
		{
			name: "valid config with endpoint",
			config: &Config{
				Region:      "local",
				Endpoint:    "http://localhost:4566",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantErr: false,
		},
		{
			name: "valid config with key ID",
			config: &Config{
				Region:      "ap-southeast-1",
				KeyID:       "arn:aws:kms:ap-southeast-1:123456789012:key/12345678-1234-1234-1234-123456789012",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
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
			name: "missing region",
			config: &Config{
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "invalid region format",
			config: &Config{
				Region:      "invalid_region",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantErr: true,
			errType: ErrInvalidRegion,
		},
		{
			name: "region with uppercase",
			config: &Config{
				Region:      "US-EAST-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantErr: true,
			errType: ErrInvalidRegion,
		},
		{
			name: "access key without secret",
			config: &Config{
				Region:      "us-east-1",
				AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "secret key without access key",
			config: &Config{
				Region:          "us-east-1",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				KeyStorage:      storage.New(),
				CertStorage:     storage.New(),
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name: "valid LocalStack region",
			config: &Config{
				Region:      "us-east-1-local",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
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
		})
	}
}

// TestConfigString tests the Config.String method.
func TestConfigString(t *testing.T) {
	tests := []struct {
		name           string
		config         *Config
		wantSubstrings []string
		dontWant       []string
	}{
		{
			name: "minimal config",
			config: &Config{
				Region:      "us-east-1",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantSubstrings: []string{
				"us-east-1",
				"<not set>",
			},
			dontWant: []string{},
		},
		{
			name: "config with credentials",
			config: &Config{
				Region:          "us-west-2",
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				KeyStorage:      storage.New(),
				CertStorage:     storage.New(),
			},
			wantSubstrings: []string{
				"us-west-2",
				"****MPLE", // Last 4 chars of access key
				"****",     // Masked secret
			},
			dontWant: []string{
				"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // Full secret should not appear
			},
		},
		{
			name: "config with session token",
			config: &Config{
				Region:          "eu-west-1",
				AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				SessionToken:    "FwoGZXIvYXdzEBYaDCAMPLE",
				KeyStorage:      storage.New(),
				CertStorage:     storage.New(),
			},
			wantSubstrings: []string{
				"eu-west-1",
				"****",
			},
			dontWant: []string{
				"FwoGZXIvYXdzEBYaDCAMPLE", // Session token should be masked
			},
		},
		{
			name: "config with endpoint",
			config: &Config{
				Region:      "local",
				Endpoint:    "http://localhost:4566",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantSubstrings: []string{
				"local",
				"http://localhost:4566",
			},
			dontWant: []string{},
		},
		{
			name: "config with key ID",
			config: &Config{
				Region:      "ap-southeast-1",
				KeyID:       "arn:aws:kms:ap-southeast-1:123456789012:key/12345678-1234-1234-1234-123456789012",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantSubstrings: []string{
				"ap-southeast-1",
				"arn:aws:kms",
			},
			dontWant: []string{},
		},
		{
			name: "config with debug enabled",
			config: &Config{
				Region:      "us-east-1",
				Debug:       true,
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			},
			wantSubstrings: []string{
				"us-east-1",
				"Debug: true",
			},
			dontWant: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.String()

			// Check for expected substrings
			for _, want := range tt.wantSubstrings {
				if !strings.Contains(result, want) {
					t.Errorf("Config.String() missing expected substring: %q\nGot: %s", want, result)
				}
			}

			// Check that sensitive data is not present
			for _, dontWant := range tt.dontWant {
				if strings.Contains(result, dontWant) {
					t.Errorf("Config.String() contains sensitive data that should be masked: %q\nGot: %s", dontWant, result)
				}
			}
		})
	}
}

// TestIsValidRegion tests the isValidRegion helper function.
func TestIsValidRegion(t *testing.T) {
	tests := []struct {
		name   string
		region string
		want   bool
	}{
		{
			name:   "valid us-east-1",
			region: "us-east-1",
			want:   true,
		},
		{
			name:   "valid us-west-2",
			region: "us-west-2",
			want:   true,
		},
		{
			name:   "valid eu-west-1",
			region: "eu-west-1",
			want:   true,
		},
		{
			name:   "valid ap-southeast-1",
			region: "ap-southeast-1",
			want:   true,
		},
		{
			name:   "valid ap-northeast-2",
			region: "ap-northeast-2",
			want:   true,
		},
		{
			name:   "valid ca-central-1",
			region: "ca-central-1",
			want:   true,
		},
		{
			name:   "valid sa-east-1",
			region: "sa-east-1",
			want:   true,
		},
		{
			name:   "valid me-south-1",
			region: "me-south-1",
			want:   true,
		},
		{
			name:   "valid af-south-1",
			region: "af-south-1",
			want:   true,
		},
		{
			name:   "valid local for testing",
			region: "local",
			want:   true,
		},
		{
			name:   "valid LocalStack region",
			region: "us-east-1-local",
			want:   true,
		},
		{
			name:   "empty region",
			region: "",
			want:   false,
		},
		{
			name:   "invalid format no hyphen",
			region: "useast1",
			want:   false,
		},
		{
			name:   "invalid format single part",
			region: "invalid",
			want:   false,
		},
		{
			name:   "invalid format with underscore",
			region: "us_east_1",
			want:   false,
		},
		{
			name:   "invalid format with uppercase",
			region: "US-EAST-1",
			want:   false,
		},
		{
			name:   "invalid format with special chars",
			region: "us-east-1!",
			want:   false,
		},
		{
			name:   "invalid format empty part",
			region: "us--1",
			want:   false,
		},
		{
			name:   "invalid format trailing hyphen",
			region: "us-east-1-",
			want:   false,
		},
		{
			name:   "invalid format leading hyphen",
			region: "-us-east-1",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidRegion(tt.region)
			if got != tt.want {
				t.Errorf("isValidRegion(%q) = %v, want %v", tt.region, got, tt.want)
			}
		})
	}
}

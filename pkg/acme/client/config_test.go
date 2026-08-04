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

package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.Equal(t, "", config.DirectoryURL)
	assert.Equal(t, 60*time.Second, config.Timeout)
	assert.False(t, config.RequestServerBundle)
	assert.Empty(t, config.TrustedRoots)
	assert.Equal(t, 3, config.RetryAttempts)
	assert.Equal(t, 1*time.Second, config.RetryDelay)
	assert.Equal(t, 30*time.Second, config.MaxRetryDelay)
}

func TestDefaultRenewalConfig(t *testing.T) {
	config := DefaultRenewalConfig()

	assert.NotNil(t, config)
	assert.True(t, config.Enabled)
	assert.Equal(t, 24*time.Hour, config.CheckInterval)
	assert.Equal(t, 0.33, config.RenewalThreshold)
	assert.Equal(t, 5, config.MaxRetries)
	assert.Equal(t, 1*time.Hour, config.RetryInterval)
	assert.True(t, config.NotifyOnSuccess)
	assert.True(t, config.NotifyOnFailure)
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr error
	}{
		{
			name: "valid configuration",
			config: &Config{
				DirectoryURL:  "https://acme.example.com/directory",
				Timeout:       60 * time.Second,
				RetryAttempts: 3,
			},
			wantErr: nil,
		},
		{
			name: "empty directory URL",
			config: &Config{
				DirectoryURL:  "",
				Timeout:       60 * time.Second,
				RetryAttempts: 3,
			},
			wantErr: ErrInvalidDirectoryURL,
		},
		{
			name: "zero timeout",
			config: &Config{
				DirectoryURL:  "https://acme.example.com/directory",
				Timeout:       0,
				RetryAttempts: 3,
			},
			wantErr: ErrInvalidTimeout,
		},
		{
			name: "negative timeout",
			config: &Config{
				DirectoryURL:  "https://acme.example.com/directory",
				Timeout:       -1 * time.Second,
				RetryAttempts: 3,
			},
			wantErr: ErrInvalidTimeout,
		},
		{
			name: "negative retry attempts",
			config: &Config{
				DirectoryURL:  "https://acme.example.com/directory",
				Timeout:       60 * time.Second,
				RetryAttempts: -1,
			},
			wantErr: ErrInvalidRetryAttempts,
		},
		{
			name: "zero retry attempts is valid",
			config: &Config{
				DirectoryURL:  "https://acme.example.com/directory",
				Timeout:       60 * time.Second,
				RetryAttempts: 0,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRenewalConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *RenewalConfig
		wantErr error
	}{
		{
			name: "valid configuration",
			config: &RenewalConfig{
				Enabled:          true,
				CheckInterval:    24 * time.Hour,
				RenewalThreshold: 0.33,
				MaxRetries:       5,
				RetryInterval:    1 * time.Hour,
			},
			wantErr: nil,
		},
		{
			name: "renewal threshold too low",
			config: &RenewalConfig{
				Enabled:          true,
				CheckInterval:    24 * time.Hour,
				RenewalThreshold: -0.1,
				MaxRetries:       5,
				RetryInterval:    1 * time.Hour,
			},
			wantErr: ErrInvalidRenewalThreshold,
		},
		{
			name: "renewal threshold too high",
			config: &RenewalConfig{
				Enabled:          true,
				CheckInterval:    24 * time.Hour,
				RenewalThreshold: 1.5,
				MaxRetries:       5,
				RetryInterval:    1 * time.Hour,
			},
			wantErr: ErrInvalidRenewalThreshold,
		},
		{
			name: "renewal threshold at boundary (0)",
			config: &RenewalConfig{
				Enabled:          true,
				CheckInterval:    24 * time.Hour,
				RenewalThreshold: 0.0,
				MaxRetries:       5,
				RetryInterval:    1 * time.Hour,
			},
			wantErr: nil,
		},
		{
			name: "renewal threshold at boundary (1)",
			config: &RenewalConfig{
				Enabled:          true,
				CheckInterval:    24 * time.Hour,
				RenewalThreshold: 1.0,
				MaxRetries:       5,
				RetryInterval:    1 * time.Hour,
			},
			wantErr: nil,
		},
		{
			name: "zero check interval",
			config: &RenewalConfig{
				Enabled:          true,
				CheckInterval:    0,
				RenewalThreshold: 0.33,
				MaxRetries:       5,
				RetryInterval:    1 * time.Hour,
			},
			wantErr: ErrInvalidTimeout,
		},
		{
			name: "negative check interval",
			config: &RenewalConfig{
				Enabled:          true,
				CheckInterval:    -1 * time.Hour,
				RenewalThreshold: 0.33,
				MaxRetries:       5,
				RetryInterval:    1 * time.Hour,
			},
			wantErr: ErrInvalidTimeout,
		},
		{
			name: "negative max retries",
			config: &RenewalConfig{
				Enabled:          true,
				CheckInterval:    24 * time.Hour,
				RenewalThreshold: 0.33,
				MaxRetries:       -1,
				RetryInterval:    1 * time.Hour,
			},
			wantErr: ErrInvalidRetryAttempts,
		},
		{
			name: "zero max retries is valid",
			config: &RenewalConfig{
				Enabled:          true,
				CheckInterval:    24 * time.Hour,
				RenewalThreshold: 0.33,
				MaxRetries:       0,
				RetryInterval:    1 * time.Hour,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

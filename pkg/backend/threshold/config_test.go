// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	keyStorage := storage.New()

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &Config{
				KeyStorage:       keyStorage,
				ShareStorage:     keyStorage,
				LocalShareID:     1,
				DefaultThreshold: 3,
				DefaultTotal:     5,
				DefaultAlgorithm: types.ThresholdAlgorithmShamir,
				Participants:     []string{"n1", "n2", "n3", "n4", "n5"},
			},
			wantErr: false,
		},
		{
			name: "missing key storage",
			config: &Config{
				DefaultThreshold: 3,
				DefaultTotal:     5,
			},
			wantErr: true,
			errMsg:  "key storage is required",
		},
		{
			name: "threshold too low",
			config: &Config{
				KeyStorage:       keyStorage,
				DefaultThreshold: 1,
				DefaultTotal:     5,
			},
			wantErr: true,
			errMsg:  "threshold must be at least 2",
		},
		{
			name: "total less than threshold",
			config: &Config{
				KeyStorage:       keyStorage,
				DefaultThreshold: 5,
				DefaultTotal:     3,
			},
			wantErr: true,
			errMsg:  "must be >= default threshold",
		},
		{
			name: "threshold exceeds maximum",
			config: &Config{
				KeyStorage:       keyStorage,
				DefaultThreshold: 256,
				DefaultTotal:     300,
			},
			wantErr: true,
			errMsg:  "cannot exceed 255",
		},
		{
			name: "total exceeds maximum",
			config: &Config{
				KeyStorage:       keyStorage,
				DefaultThreshold: 3,
				DefaultTotal:     256,
			},
			wantErr: true,
			errMsg:  "cannot exceed 255",
		},
		{
			name: "participants mismatch",
			config: &Config{
				KeyStorage:       keyStorage,
				DefaultThreshold: 3,
				DefaultTotal:     5,
				Participants:     []string{"n1", "n2", "n3"}, // Only 3, should be 5
			},
			wantErr: true,
			errMsg:  "participants length",
		},
		{
			name: "invalid local share ID (too high)",
			config: &Config{
				KeyStorage:       keyStorage,
				LocalShareID:     10,
				DefaultThreshold: 3,
				DefaultTotal:     5,
			},
			wantErr: true,
			errMsg:  "local share ID",
		},
		{
			name: "invalid local share ID (zero is allowed)",
			config: &Config{
				KeyStorage:       keyStorage,
				LocalShareID:     0,
				DefaultThreshold: 3,
				DefaultTotal:     5,
			},
			wantErr: false,
		},
		{
			name: "no participants (allowed)",
			config: &Config{
				KeyStorage:       keyStorage,
				DefaultThreshold: 3,
				DefaultTotal:     5,
				Participants:     nil,
			},
			wantErr: false,
		},
		{
			name: "defaults to Shamir algorithm",
			config: &Config{
				KeyStorage:       keyStorage,
				DefaultThreshold: 3,
				DefaultTotal:     5,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				// Check that defaults are set
				if tt.config.DefaultAlgorithm == "" {
					assert.Equal(t, types.ThresholdAlgorithmShamir, tt.config.DefaultAlgorithm)
				}
				// Check that ShareStorage defaults to KeyStorage
				if tt.config.ShareStorage == nil {
					assert.Equal(t, tt.config.KeyStorage, tt.config.ShareStorage)
				}
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	keyStorage := storage.New()
	config := DefaultConfig(keyStorage)

	require.NotNil(t, config)
	assert.Equal(t, keyStorage, config.KeyStorage)
	assert.Equal(t, keyStorage, config.ShareStorage)
	assert.Equal(t, 1, config.LocalShareID)
	assert.Equal(t, 3, config.DefaultThreshold)
	assert.Equal(t, 5, config.DefaultTotal)
	assert.Equal(t, types.ThresholdAlgorithmShamir, config.DefaultAlgorithm)
	assert.Len(t, config.Participants, 5)

	// Validate should pass
	err := config.Validate()
	assert.NoError(t, err)
}

func TestConfig_AlgorithmTypes(t *testing.T) {
	keyStorage := storage.New()

	algorithms := []types.ThresholdAlgorithm{
		types.ThresholdAlgorithmShamir,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			config := &Config{
				KeyStorage:       keyStorage,
				DefaultThreshold: 3,
				DefaultTotal:     5,
				DefaultAlgorithm: algo,
			}

			err := config.Validate()
			assert.NoError(t, err)
			assert.Equal(t, algo, config.DefaultAlgorithm)
		})
	}
}

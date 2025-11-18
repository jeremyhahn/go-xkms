// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThresholdAttributes_Validate(t *testing.T) {
	tests := []struct {
		name    string
		attrs   *ThresholdAttributes
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid 3-of-5 configuration",
			attrs: &ThresholdAttributes{
				Threshold:    3,
				Total:        5,
				Algorithm:    ThresholdAlgorithmShamir,
				Participants: []string{"node1", "node2", "node3", "node4", "node5"},
			},
			wantErr: false,
		},
		{
			name: "valid without participants",
			attrs: &ThresholdAttributes{
				Threshold: 2,
				Total:     3,
				Algorithm: ThresholdAlgorithmShamir,
			},
			wantErr: false,
		},
		{
			name: "threshold too low",
			attrs: &ThresholdAttributes{
				Threshold: 1,
				Total:     5,
				Algorithm: ThresholdAlgorithmShamir,
			},
			wantErr: true,
			errMsg:  "threshold must be at least 2",
		},
		{
			name: "total less than threshold",
			attrs: &ThresholdAttributes{
				Threshold: 5,
				Total:     3,
				Algorithm: ThresholdAlgorithmShamir,
			},
			wantErr: true,
			errMsg:  "total (3) must be >= threshold (5)",
		},
		{
			name: "threshold exceeds maximum",
			attrs: &ThresholdAttributes{
				Threshold: 256,
				Total:     300,
				Algorithm: ThresholdAlgorithmShamir,
			},
			wantErr: true,
			errMsg:  "threshold cannot exceed 255",
		},
		{
			name: "total exceeds maximum",
			attrs: &ThresholdAttributes{
				Threshold: 3,
				Total:     256,
				Algorithm: ThresholdAlgorithmShamir,
			},
			wantErr: true,
			errMsg:  "total cannot exceed 255",
		},
		{
			name: "participants length mismatch",
			attrs: &ThresholdAttributes{
				Threshold:    3,
				Total:        5,
				Algorithm:    ThresholdAlgorithmShamir,
				Participants: []string{"node1", "node2", "node3"}, // Only 3, should be 5
			},
			wantErr: true,
			errMsg:  "participants length (3) must match total (5)",
		},
		{
			name: "invalid shareID (zero is allowed)",
			attrs: &ThresholdAttributes{
				Threshold: 3,
				Total:     5,
				Algorithm: ThresholdAlgorithmShamir,
				ShareID:   0, // 0 means unassigned, should be valid
			},
			wantErr: false,
		},
		{
			name: "invalid shareID (too high)",
			attrs: &ThresholdAttributes{
				Threshold: 3,
				Total:     5,
				Algorithm: ThresholdAlgorithmShamir,
				ShareID:   6, // Exceeds total
			},
			wantErr: true,
			errMsg:  "shareID (6) must be between 1 and total (5)",
		},
		{
			name: "valid shareID",
			attrs: &ThresholdAttributes{
				Threshold: 3,
				Total:     5,
				Algorithm: ThresholdAlgorithmShamir,
				ShareID:   3, // Valid: 1 <= 3 <= 5
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.attrs.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestThresholdAlgorithm_String(t *testing.T) {
	tests := []struct {
		algorithm ThresholdAlgorithm
		expected  string
	}{
		{ThresholdAlgorithmShamir, "SHAMIR"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.algorithm))
		})
	}
}

func TestKeyAttributes_WithThresholdAttributes(t *testing.T) {
	attrs := &KeyAttributes{
		CN:        "threshold-key",
		KeyType:   KeyTypeSigning,
		StoreType: StoreThreshold,
		ThresholdAttributes: &ThresholdAttributes{
			Threshold:    3,
			Total:        5,
			Algorithm:    ThresholdAlgorithmShamir,
			Participants: []string{"node1", "node2", "node3", "node4", "node5"},
		},
	}

	// Validate threshold attributes
	require.NotNil(t, attrs.ThresholdAttributes)
	err := attrs.ThresholdAttributes.Validate()
	require.NoError(t, err)

	// Check values
	assert.Equal(t, 3, attrs.ThresholdAttributes.Threshold)
	assert.Equal(t, 5, attrs.ThresholdAttributes.Total)
	assert.Equal(t, ThresholdAlgorithmShamir, attrs.ThresholdAttributes.Algorithm)
	assert.Len(t, attrs.ThresholdAttributes.Participants, 5)
}

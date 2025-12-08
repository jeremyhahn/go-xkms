// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package shamir

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplit_BasicFunctionality(t *testing.T) {
	secret := []byte("This is a secret message!")
	threshold := 3
	total := 5

	shares, err := Split(secret, threshold, total)
	require.NoError(t, err)
	require.Len(t, shares, total)

	// Verify all shares have correct metadata
	for i, share := range shares {
		assert.Equal(t, i+1, share.Index)
		assert.Equal(t, threshold, share.Threshold)
		assert.Equal(t, total, share.Total)
		assert.NotEmpty(t, share.Value)
		assert.NoError(t, share.Validate())
	}
}

func TestCombine_ExactThreshold(t *testing.T) {
	secret := []byte("Secret key data 12345")
	threshold := 3
	total := 5

	shares, err := Split(secret, threshold, total)
	require.NoError(t, err)

	// Use exactly M shares
	subset := []*Share{shares[0], shares[2], shares[4]}
	reconstructed, err := Combine(subset)
	require.NoError(t, err)
	assert.Equal(t, secret, reconstructed)
}

func TestCombine_MoreThanThreshold(t *testing.T) {
	secret := []byte("Another secret message")
	threshold := 3
	total := 5

	shares, err := Split(secret, threshold, total)
	require.NoError(t, err)

	// Use M+1 shares (should still work)
	subset := []*Share{shares[0], shares[1], shares[3], shares[4]}
	reconstructed, err := Combine(subset)
	require.NoError(t, err)
	assert.Equal(t, secret, reconstructed)
}

func TestCombine_AllShares(t *testing.T) {
	secret := []byte("Complete reconstruction test")
	threshold := 3
	total := 5

	shares, err := Split(secret, threshold, total)
	require.NoError(t, err)

	// Use all N shares
	reconstructed, err := Combine(shares)
	require.NoError(t, err)
	assert.Equal(t, secret, reconstructed)
}

func TestCombine_InsufficientShares(t *testing.T) {
	secret := []byte("Not enough shares")
	threshold := 3
	total := 5

	shares, err := Split(secret, threshold, total)
	require.NoError(t, err)

	// Try with K-1 shares (should fail)
	subset := []*Share{shares[0], shares[2]}
	_, err = Combine(subset)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "need at least 3 shares")
}

func TestSplit_ParameterValidation(t *testing.T) {
	secret := []byte("test secret")

	tests := []struct {
		name      string
		threshold int
		total     int
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "threshold too low",
			threshold: 1,
			total:     5,
			wantErr:   true,
			errMsg:    "threshold must be at least 2",
		},
		{
			name:      "total less than threshold",
			threshold: 5,
			total:     3,
			wantErr:   true,
			errMsg:    "total shares (3) must be >= threshold (5)",
		},
		{
			name:      "threshold exceeds maximum",
			threshold: 256,
			total:     260,
			wantErr:   true,
			errMsg:    "threshold cannot exceed 255",
		},
		{
			name:      "total exceeds maximum",
			threshold: 3,
			total:     256,
			wantErr:   true,
			errMsg:    "total shares cannot exceed 255",
		},
		{
			name:      "valid parameters",
			threshold: 3,
			total:     5,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Split(secret, tt.threshold, tt.total)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSplit_EmptySecret(t *testing.T) {
	_, err := Split([]byte{}, 3, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret cannot be empty")
}

func TestShare_JSONSerialization(t *testing.T) {
	secret := []byte("Serialize me!")
	shares, err := Split(secret, 3, 5)
	require.NoError(t, err)

	for i, share := range shares {
		// Marshal to JSON
		data, err := json.Marshal(share)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Unmarshal from JSON
		var decoded Share
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		// Verify fields match
		assert.Equal(t, share.Index, decoded.Index)
		assert.Equal(t, share.Threshold, decoded.Threshold)
		assert.Equal(t, share.Total, decoded.Total)
		assert.Equal(t, share.Value, decoded.Value)

		t.Logf("Share %d JSON: %s", i+1, string(data))
	}
}

func TestShare_Validation(t *testing.T) {
	tests := []struct {
		name    string
		share   *Share
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid share",
			share: &Share{
				Index:     1,
				Threshold: 3,
				Total:     5,
				Value:     "dGVzdA==",
			},
			wantErr: false,
		},
		{
			name: "invalid index (zero)",
			share: &Share{
				Index:     0,
				Threshold: 3,
				Total:     5,
				Value:     "dGVzdA==",
			},
			wantErr: true,
			errMsg:  "invalid share index: 0",
		},
		{
			name: "invalid threshold (too low)",
			share: &Share{
				Index:     1,
				Threshold: 1,
				Total:     5,
				Value:     "dGVzdA==",
			},
			wantErr: true,
			errMsg:  "invalid threshold: 1",
		},
		{
			name: "total less than threshold",
			share: &Share{
				Index:     1,
				Threshold: 5,
				Total:     3,
				Value:     "dGVzdA==",
			},
			wantErr: true,
			errMsg:  "invalid total: 3",
		},
		{
			name: "index exceeds total",
			share: &Share{
				Index:     6,
				Threshold: 3,
				Total:     5,
				Value:     "dGVzdA==",
			},
			wantErr: true,
			errMsg:  "invalid share index: 6",
		},
		{
			name: "empty value",
			share: &Share{
				Index:     1,
				Threshold: 3,
				Total:     5,
				Value:     "",
			},
			wantErr: true,
			errMsg:  "share value is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.share.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVerifyShare(t *testing.T) {
	shares, err := Split([]byte("test secret"), 3, 5)
	require.NoError(t, err)

	// Valid share with consistent others
	err = VerifyShare(shares[0], shares[1:])
	assert.NoError(t, err)

	// Create inconsistent share (different threshold, but valid index)
	badShare := &Share{
		Index:     4, // Valid index within total
		Threshold: 4, // Different threshold
		Total:     5,
		Value:     "dGVzdA==",
	}

	err = VerifyShare(badShare, shares)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "threshold mismatch")

	// Duplicate index
	duplicate := &Share{
		Index:     shares[0].Index, // Same index
		Threshold: 3,
		Total:     5,
		Value:     "test",
	}

	err = VerifyShare(duplicate, shares)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate share index")
}

func TestCombine_DifferentSubsets(t *testing.T) {
	secret := []byte("Testing different share combinations")
	threshold := 3
	total := 7

	shares, err := Split(secret, threshold, total)
	require.NoError(t, err)

	// Test multiple different K-size subsets
	subsets := [][]*Share{
		{shares[0], shares[1], shares[2]},
		{shares[0], shares[3], shares[6]},
		{shares[1], shares[4], shares[5]},
		{shares[2], shares[3], shares[4]},
	}

	for i, subset := range subsets {
		reconstructed, err := Combine(subset)
		require.NoError(t, err, "Subset %d failed", i)
		assert.Equal(t, secret, reconstructed, "Subset %d reconstructed incorrectly", i)
		t.Logf("✓ Subset %d reconstructed successfully", i+1)
	}
}

func TestSplit_LargeSecret(t *testing.T) {
	// Test with large secret (simulating encryption key)
	secret := make([]byte, 1024) // 1KB secret
	_, err := rand.Read(secret)
	require.NoError(t, err)

	shares, err := Split(secret, 5, 9)
	require.NoError(t, err)
	require.Len(t, shares, 9)

	// Reconstruct with threshold shares
	subset := []*Share{shares[0], shares[2], shares[4], shares[6], shares[8]}
	reconstructed, err := Combine(subset)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(secret, reconstructed))
	t.Logf("✓ Successfully split and reconstructed %d byte secret", len(secret))
}

func TestSplit_BinaryData(t *testing.T) {
	// Test with random binary data
	secret := make([]byte, 256)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	shares, err := Split(secret, 3, 5)
	require.NoError(t, err)

	reconstructed, err := Combine([]*Share{shares[1], shares[2], shares[4]})
	require.NoError(t, err)
	assert.True(t, bytes.Equal(secret, reconstructed))
}

func TestCombine_InconsistentShares(t *testing.T) {
	// Create shares from different secrets
	secret1 := []byte("Secret 1")
	secret2 := []byte("Secret 2")

	shares1, err := Split(secret1, 3, 5)
	require.NoError(t, err)

	shares2, err := Split(secret2, 3, 5)
	require.NoError(t, err)

	// Try to combine shares from different secrets (should detect mismatch)
	mixed := []*Share{shares1[0], shares1[1], shares2[2]}
	_, err = Combine(mixed)
	// Note: sssa-golang may or may not detect this - it will reconstruct garbage
	// This is expected behavior for SSS without verification
	t.Logf("Mixed shares result: %v", err)
}

func TestShare_Metadata(t *testing.T) {
	shares, err := Split([]byte("test"), 3, 5)
	require.NoError(t, err)

	// Add metadata
	shares[0].Metadata["owner"] = "alice"
	shares[0].Metadata["created"] = "2025-01-01"

	// Serialize and deserialize
	data, err := json.Marshal(shares[0])
	require.NoError(t, err)

	var decoded Share
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "alice", decoded.Metadata["owner"])
	assert.Equal(t, "2025-01-01", decoded.Metadata["created"])
}

// Benchmark tests
func BenchmarkSplit_SmallSecret(b *testing.B) {
	secret := []byte("Small secret for benchmarking")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Split(secret, 3, 5)
	}
}

func BenchmarkSplit_LargeSecret(b *testing.B) {
	secret := make([]byte, 1024)
	_, _ = rand.Read(secret)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Split(secret, 5, 9)
	}
}

func BenchmarkCombine(b *testing.B) {
	secret := []byte("Benchmark secret")
	shares, _ := Split(secret, 3, 5)
	subset := []*Share{shares[0], shares[2], shares[4]}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Combine(subset)
	}
}

func TestShare_Bytes(t *testing.T) {
	shares, err := Split([]byte("test secret"), 3, 5)
	require.NoError(t, err)

	// Test Bytes method
	for _, share := range shares {
		b, err := share.Bytes()
		require.NoError(t, err)
		assert.NotEmpty(t, b)
	}
}

func TestShare_String(t *testing.T) {
	shares, err := Split([]byte("test secret"), 3, 5)
	require.NoError(t, err)

	// Test String method
	for i, share := range shares {
		s := share.String()
		assert.Contains(t, s, "Share{Index:")
		assert.Contains(t, s, fmt.Sprintf("Index: %d", i+1))
		t.Logf("Share %d: %s", i+1, s)
	}
}

func TestMin(t *testing.T) {
	// Test min function through String method
	// Create a share with a very short value
	share := &Share{
		Index:     1,
		Threshold: 3,
		Total:     5,
		Value:     "abc", // Less than 16 characters
	}
	s := share.String()
	assert.Contains(t, s, "abc")

	// Test with longer value
	share2 := &Share{
		Index:     1,
		Threshold: 3,
		Total:     5,
		Value:     "abcdefghijklmnopqrstuvwxyz",
	}
	s2 := share2.String()
	assert.Contains(t, s2, "...")
}

func TestCombine_NoShares(t *testing.T) {
	_, err := Combine([]*Share{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no shares provided")
}

func TestCombine_InvalidShare(t *testing.T) {
	// Test with invalid share (empty value)
	invalidShares := []*Share{
		{Index: 1, Threshold: 3, Total: 5, Value: "dGVzdA=="},
		{Index: 2, Threshold: 3, Total: 5, Value: ""}, // empty value
		{Index: 3, Threshold: 3, Total: 5, Value: "dGVzdA=="},
	}
	_, err := Combine(invalidShares)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid share")
}

func TestCombine_DifferentTotal(t *testing.T) {
	// Test with shares having different total values
	shares := []*Share{
		{Index: 1, Threshold: 3, Total: 5, Value: "dGVzdA=="},
		{Index: 2, Threshold: 3, Total: 7, Value: "dGVzdA=="}, // different total
		{Index: 3, Threshold: 3, Total: 5, Value: "dGVzdA=="},
	}
	_, err := Combine(shares)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "different total")
}

func TestCombine_InvalidBase64(t *testing.T) {
	shares, err := Split([]byte("test"), 3, 5)
	require.NoError(t, err)

	// Corrupt one share's base64 value
	shares[1].Value = "!!!invalid-base64!!!"

	_, err = Combine([]*Share{shares[0], shares[1], shares[2]})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode share")
}

func TestVerifyShare_TotalMismatch(t *testing.T) {
	shares, err := Split([]byte("test secret"), 3, 5)
	require.NoError(t, err)

	// Create share with different total
	badShare := &Share{
		Index:     4,
		Threshold: 3,
		Total:     9, // Different total
		Value:     "dGVzdA==",
	}

	err = VerifyShare(badShare, shares[:3])
	require.Error(t, err)
	assert.Contains(t, err.Error(), "total mismatch")
}

func TestShare_UnmarshalJSON_Error(t *testing.T) {
	var share Share
	err := share.UnmarshalJSON([]byte("invalid json"))
	require.Error(t, err)
}

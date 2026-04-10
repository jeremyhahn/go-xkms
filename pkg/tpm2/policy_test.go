package tpm2

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPCRDigestSize_AllBanks(t *testing.T) {
	tests := []struct {
		name     string
		bank     string
		expected int
	}{
		{
			name:     "sha1 returns 20",
			bank:     PCRBankSHA1,
			expected: sha1.Size,
		},
		{
			name:     "sha256 returns 32",
			bank:     PCRBankSHA256,
			expected: sha256.Size,
		},
		{
			name:     "sha384 returns 48",
			bank:     PCRBankSHA384,
			expected: sha512.Size384,
		},
		{
			name:     "sha512 returns 64",
			bank:     PCRBankSHA512,
			expected: sha512.Size,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := PCRDigestSize(tc.bank)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestPCRDigestSize_UnknownBankDefaultsSHA256(t *testing.T) {
	tests := []struct {
		name string
		bank string
	}{
		{name: "empty string", bank: ""},
		{name: "unknown bank", bank: "md5"},
		{name: "uppercase SHA256", bank: "SHA256"},
		{name: "arbitrary string", bank: "nonexistent"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := PCRDigestSize(tc.bank)
			assert.Equal(t, sha256.Size, got, "unknown bank should default to sha256 size")
		})
	}
}

func TestEncodePCRSelection_SinglePCR(t *testing.T) {
	// PCR 7 in sha256 bank should produce a well-defined 10-byte wire encoding.
	result := EncodePCRSelection(PCRBankSHA256, []int{7})

	require.Len(t, result, 10, "TPML_PCR_SELECTION encoding must be 10 bytes")

	// count = 1 (uint32 big-endian)
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x01}, result[0:4], "count field")
	// algorithm ID for SHA256 = 0x000B
	assert.Equal(t, []byte{0x00, 0x0B}, result[4:6], "algorithm ID for sha256")
	// sizeofSelect = 3
	assert.Equal(t, byte(3), result[6], "sizeofSelect field")
	// PCR 7 sets bit 7 of byte 0: 1<<7 = 0x80
	assert.Equal(t, byte(0x80), result[7], "bitmap byte 0 for PCR 7")
	assert.Equal(t, byte(0x00), result[8], "bitmap byte 1 should be zero")
	assert.Equal(t, byte(0x00), result[9], "bitmap byte 2 should be zero")
}

func TestEncodePCRSelection_MultiplePCRs(t *testing.T) {
	// PCRs 0, 1, 2, 7 in sha256 bank.
	result := EncodePCRSelection(PCRBankSHA256, []int{0, 1, 2, 7})

	require.Len(t, result, 10)

	// PCR 0 = bit 0 (0x01), PCR 1 = bit 1 (0x02), PCR 2 = bit 2 (0x04), PCR 7 = bit 7 (0x80)
	// byte 0 = 0x01 | 0x02 | 0x04 | 0x80 = 0x87
	assert.Equal(t, byte(0x87), result[7], "bitmap byte 0 for PCRs 0,1,2,7")
	assert.Equal(t, byte(0x00), result[8])
	assert.Equal(t, byte(0x00), result[9])
}

func TestEncodePCRSelection_AllKnownBanks(t *testing.T) {
	tests := []struct {
		name          string
		bank          string
		expectedAlgID []byte
	}{
		{
			name:          "sha1 algorithm ID 0x0004",
			bank:          PCRBankSHA1,
			expectedAlgID: []byte{0x00, 0x04},
		},
		{
			name:          "sha256 algorithm ID 0x000B",
			bank:          PCRBankSHA256,
			expectedAlgID: []byte{0x00, 0x0B},
		},
		{
			name:          "sha384 algorithm ID 0x000C",
			bank:          PCRBankSHA384,
			expectedAlgID: []byte{0x00, 0x0C},
		},
		{
			name:          "sha512 algorithm ID 0x000D",
			bank:          PCRBankSHA512,
			expectedAlgID: []byte{0x00, 0x0D},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := EncodePCRSelection(tc.bank, []int{0})
			require.Len(t, result, 10)
			assert.Equal(t, tc.expectedAlgID, result[4:6], "algorithm ID mismatch")
		})
	}
}

func TestEncodePCRSelection_UnknownBankDefaultsSHA256(t *testing.T) {
	result := EncodePCRSelection("unknown-bank", []int{0})

	require.Len(t, result, 10)
	// Should default to SHA256 algorithm ID = 0x000B
	assert.Equal(t, []byte{0x00, 0x0B}, result[4:6], "unknown bank should default to sha256 algorithm ID")
}

func TestEncodePCRSelection_EmptyIndices(t *testing.T) {
	result := EncodePCRSelection(PCRBankSHA256, []int{})

	require.Len(t, result, 10)
	// All bitmap bytes should be zero.
	assert.Equal(t, byte(0x00), result[7])
	assert.Equal(t, byte(0x00), result[8])
	assert.Equal(t, byte(0x00), result[9])
}

func TestEncodePCRSelection_NilIndices(t *testing.T) {
	result := EncodePCRSelection(PCRBankSHA256, nil)

	require.Len(t, result, 10)
	assert.Equal(t, byte(0x00), result[7])
	assert.Equal(t, byte(0x00), result[8])
	assert.Equal(t, byte(0x00), result[9])
}

func TestEncodePCRSelection_OutOfRangeIndicesIgnored(t *testing.T) {
	tests := []struct {
		name    string
		indices []int
	}{
		{name: "negative index", indices: []int{-1}},
		{name: "index 24", indices: []int{24}},
		{name: "large index", indices: []int{100}},
		{name: "mixed valid and invalid", indices: []int{-5, 0, 24, 50}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := EncodePCRSelection(PCRBankSHA256, tc.indices)
			require.Len(t, result, 10, "encoding length must always be 10")

			// Only valid indices (0-23) should appear. For the "mixed" case,
			// only PCR 0 is valid.
			if tc.name == "mixed valid and invalid" {
				assert.Equal(t, byte(0x01), result[7], "only PCR 0 should be set")
			}
		})
	}
}

func TestEncodePCRSelection_BitmapSpanAllBytes(t *testing.T) {
	// PCR 0 -> byte 0 bit 0, PCR 8 -> byte 1 bit 0, PCR 16 -> byte 2 bit 0, PCR 23 -> byte 2 bit 7
	result := EncodePCRSelection(PCRBankSHA256, []int{0, 8, 16, 23})

	require.Len(t, result, 10)
	assert.Equal(t, byte(0x01), result[7], "PCR 0 in byte 0")
	assert.Equal(t, byte(0x01), result[8], "PCR 8 in byte 1")
	// PCR 16 = bit 0 (0x01), PCR 23 = bit 7 (0x80) => byte 2 = 0x81
	assert.Equal(t, byte(0x81), result[9], "PCRs 16 and 23 in byte 2")
}

func TestComputePolicyPCRDigest_SHA256Success(t *testing.T) {
	// Use a known zero-value digest for PCR 0 in sha256 bank.
	zeroDigest := hex.EncodeToString(make([]byte, sha256.Size))
	digests := map[string]string{
		"sha256:0": zeroDigest,
	}

	result, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0}, digests)
	require.NoError(t, err)
	assert.Len(t, result, sha256.Size, "result must be sha256 digest length")
}

func TestComputePolicyPCRDigest_AllBanksProduceCorrectLength(t *testing.T) {
	tests := []struct {
		name         string
		bank         string
		expectedSize int
	}{
		{name: "sha1", bank: PCRBankSHA1, expectedSize: sha1.Size},
		{name: "sha256", bank: PCRBankSHA256, expectedSize: sha256.Size},
		{name: "sha384", bank: PCRBankSHA384, expectedSize: sha512.Size384},
		{name: "sha512", bank: PCRBankSHA512, expectedSize: sha512.Size},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zeroDigest := hex.EncodeToString(make([]byte, tc.expectedSize))
			digests := map[string]string{
				fmt.Sprintf("%s:0", tc.bank): zeroDigest,
			}

			result, err := ComputePolicyPCRDigest(tc.bank, []int{0}, digests)
			require.NoError(t, err)
			assert.Len(t, result, tc.expectedSize)
		})
	}
}

func TestComputePolicyPCRDigest_EmptyPCRsError(t *testing.T) {
	_, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{}, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyEmptyPCRs))
}

func TestComputePolicyPCRDigest_NilPCRsError(t *testing.T) {
	_, err := ComputePolicyPCRDigest(PCRBankSHA256, nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyEmptyPCRs))
}

func TestComputePolicyPCRDigest_InvalidHexDigestError(t *testing.T) {
	digests := map[string]string{
		"sha256:0": "not-valid-hex!!",
	}

	_, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0}, digests)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyInvalidDigest))
}

func TestComputePolicyPCRDigest_OddLengthHexDigestError(t *testing.T) {
	// Odd-length hex strings are invalid for hex.DecodeString.
	digests := map[string]string{
		"sha256:0": "abc",
	}

	_, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0}, digests)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPolicyInvalidDigest))
}

func TestComputePolicyPCRDigest_MissingDigestsZeroFilled(t *testing.T) {
	// Provide digest only for PCR 0, but request PCRs 0 and 7.
	// PCR 7 should be zero-filled.
	zeroDigest := hex.EncodeToString(make([]byte, sha256.Size))
	digests := map[string]string{
		"sha256:0": zeroDigest,
	}

	result, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0, 7}, digests)
	require.NoError(t, err)
	assert.Len(t, result, sha256.Size)

	// Verify it matches the result when both digests are explicitly provided as zeros.
	digestsBothZero := map[string]string{
		"sha256:0": zeroDigest,
		"sha256:7": zeroDigest,
	}

	resultBothZero, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0, 7}, digestsBothZero)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(result, resultBothZero),
		"missing digest should produce same result as explicitly provided zero digest")
}

func TestComputePolicyPCRDigest_Deterministic(t *testing.T) {
	zeroDigest := hex.EncodeToString(make([]byte, sha256.Size))
	digests := map[string]string{
		"sha256:0": zeroDigest,
		"sha256:7": zeroDigest,
	}

	result1, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0, 7}, digests)
	require.NoError(t, err)

	result2, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0, 7}, digests)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(result1, result2),
		"same inputs must produce identical policy digests")
}

func TestComputePolicyPCRDigest_OrderIndependence(t *testing.T) {
	// PCR indices should be sorted internally, so order of input should not matter.
	digestA := hex.EncodeToString(make([]byte, sha256.Size))
	onesBuf := make([]byte, sha256.Size)
	for i := range onesBuf {
		onesBuf[i] = 0xFF
	}
	digestB := hex.EncodeToString(onesBuf)

	digests := map[string]string{
		"sha256:0": digestA,
		"sha256:7": digestB,
	}

	result1, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0, 7}, digests)
	require.NoError(t, err)

	result2, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{7, 0}, digests)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(result1, result2),
		"PCR index order should not affect the policy digest")
}

func TestComputePolicyPCRDigest_DifferentDigestsProduceDifferentOutput(t *testing.T) {
	zeroDigest := hex.EncodeToString(make([]byte, sha256.Size))
	onesBuf := make([]byte, sha256.Size)
	for i := range onesBuf {
		onesBuf[i] = 0xFF
	}
	onesDigest := hex.EncodeToString(onesBuf)

	digestsZero := map[string]string{
		"sha256:0": zeroDigest,
	}

	digestsOnes := map[string]string{
		"sha256:0": onesDigest,
	}

	resultZero, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0}, digestsZero)
	require.NoError(t, err)

	resultOnes, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0}, digestsOnes)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(resultZero, resultOnes),
		"different PCR digest values must produce different policy digests")
}

func TestComputePolicyPCRDigest_MultiplePCRs(t *testing.T) {
	// Verify that requesting multiple PCRs produces a valid digest.
	hashSize := sha256.Size
	digests := map[string]string{}
	indices := []int{0, 1, 2, 3, 4, 5, 6, 7}
	for _, idx := range indices {
		key := fmt.Sprintf("sha256:%d", idx)
		digests[key] = hex.EncodeToString(make([]byte, hashSize))
	}

	result, err := ComputePolicyPCRDigest(PCRBankSHA256, indices, digests)
	require.NoError(t, err)
	assert.Len(t, result, hashSize)
}

func TestComputePolicyPCRDigest_EmptyDigestsMap(t *testing.T) {
	// All PCR digests should be zero-filled when the map is empty.
	result, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0}, map[string]string{})
	require.NoError(t, err)
	assert.Len(t, result, sha256.Size)

	// Should match providing nil map.
	resultNil, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{0}, nil)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(result, resultNil),
		"empty map and nil map should produce identical zero-filled results")
}

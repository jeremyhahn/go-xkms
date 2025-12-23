//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestGetCiphersuite_AllAlgorithms(t *testing.T) {
	tests := []struct {
		algorithm types.FrostAlgorithm
	}{
		{types.FrostAlgorithmEd25519},
		{types.FrostAlgorithmRistretto255},
		{types.FrostAlgorithmEd448},
		{types.FrostAlgorithmP256},
		{types.FrostAlgorithmSecp256k1},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			cs, err := GetCiphersuite(tt.algorithm)
			require.NoError(t, err)
			assert.NotNil(t, cs)
			assert.NotNil(t, cs.Group())
		})
	}
}

func TestGetCiphersuite_InvalidAlgorithm(t *testing.T) {
	cs, err := GetCiphersuite("FROST-invalid")
	assert.Nil(t, cs)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnsupportedAlgorithm))

	var algErr *AlgorithmError
	assert.True(t, errors.As(err, &algErr))
	assert.Equal(t, "FROST-invalid", algErr.Algorithm)
}

func TestGetCiphersuiteID(t *testing.T) {
	tests := []struct {
		algorithm types.FrostAlgorithm
		wantID    string
	}{
		{types.FrostAlgorithmEd25519, "FROST-ED25519-SHA512-v1"},
		{types.FrostAlgorithmRistretto255, "FROST-RISTRETTO255-SHA512-v1"},
		{types.FrostAlgorithmEd448, "FROST-ED448-SHAKE256-v1"},
		{types.FrostAlgorithmP256, "FROST-P256-SHA256-v1"},
		{types.FrostAlgorithmSecp256k1, "FROST-secp256k1-SHA256-v1"},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			id := GetCiphersuiteID(tt.algorithm)
			assert.Equal(t, tt.wantID, id)
		})
	}
}

func TestGetCiphersuiteID_Unknown(t *testing.T) {
	id := GetCiphersuiteID("unknown")
	assert.Empty(t, id)
}

func TestGetSignatureSize(t *testing.T) {
	tests := []struct {
		algorithm types.FrostAlgorithm
		wantSize  int
	}{
		{types.FrostAlgorithmEd25519, 64},
		{types.FrostAlgorithmRistretto255, 64},
		{types.FrostAlgorithmEd448, 114},
		{types.FrostAlgorithmP256, 64},
		{types.FrostAlgorithmSecp256k1, 64},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			size := GetSignatureSize(tt.algorithm)
			assert.Equal(t, tt.wantSize, size)
		})
	}
}

func TestGetSignatureSize_Unknown(t *testing.T) {
	size := GetSignatureSize("unknown")
	assert.Equal(t, 0, size)
}

func TestGetPublicKeySize(t *testing.T) {
	tests := []struct {
		algorithm types.FrostAlgorithm
		wantSize  int
	}{
		{types.FrostAlgorithmEd25519, 32},
		{types.FrostAlgorithmRistretto255, 32},
		{types.FrostAlgorithmEd448, 57},
		{types.FrostAlgorithmP256, 33},
		{types.FrostAlgorithmSecp256k1, 33},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			size := GetPublicKeySize(tt.algorithm)
			assert.Equal(t, tt.wantSize, size)
		})
	}
}

func TestGetPublicKeySize_Unknown(t *testing.T) {
	size := GetPublicKeySize("unknown")
	assert.Equal(t, 0, size)
}

func TestGetScalarSize(t *testing.T) {
	tests := []struct {
		algorithm types.FrostAlgorithm
		wantSize  int
	}{
		{types.FrostAlgorithmEd25519, 32},
		{types.FrostAlgorithmRistretto255, 32},
		{types.FrostAlgorithmEd448, 57},
		{types.FrostAlgorithmP256, 32},
		{types.FrostAlgorithmSecp256k1, 32},
	}

	for _, tt := range tests {
		t.Run(string(tt.algorithm), func(t *testing.T) {
			size := GetScalarSize(tt.algorithm)
			assert.Equal(t, tt.wantSize, size)
		})
	}
}

func TestGetScalarSize_Unknown(t *testing.T) {
	size := GetScalarSize("unknown")
	assert.Equal(t, 0, size)
}

func TestGetAlgorithmInfo_AllAlgorithms(t *testing.T) {
	algorithms := []types.FrostAlgorithm{
		types.FrostAlgorithmEd25519,
		types.FrostAlgorithmRistretto255,
		types.FrostAlgorithmEd448,
		types.FrostAlgorithmP256,
		types.FrostAlgorithmSecp256k1,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			info := GetAlgorithmInfo(algo)
			require.NotNil(t, info)

			assert.Equal(t, algo, info.Algorithm)
			assert.NotEmpty(t, info.CiphersuiteID)
			assert.Greater(t, info.ScalarSize, 0)
			assert.Greater(t, info.PublicKeySize, 0)
			assert.Greater(t, info.SignatureSize, 0)
			assert.NotEmpty(t, info.Description)

			// Verify consistency with other functions
			assert.Equal(t, GetCiphersuiteID(algo), info.CiphersuiteID)
			assert.Equal(t, GetScalarSize(algo), info.ScalarSize)
			assert.Equal(t, GetPublicKeySize(algo), info.PublicKeySize)
			assert.Equal(t, GetSignatureSize(algo), info.SignatureSize)
		})
	}
}

func TestGetAlgorithmInfo_Ed25519(t *testing.T) {
	info := GetAlgorithmInfo(types.FrostAlgorithmEd25519)
	require.NotNil(t, info)

	assert.Equal(t, "FROST-ED25519-SHA512-v1", info.CiphersuiteID)
	assert.Equal(t, 32, info.ScalarSize)
	assert.Equal(t, 32, info.PublicKeySize)
	assert.Equal(t, 64, info.SignatureSize)
	assert.Contains(t, info.Description, "Ed25519")
}

func TestGetAlgorithmInfo_P256(t *testing.T) {
	info := GetAlgorithmInfo(types.FrostAlgorithmP256)
	require.NotNil(t, info)

	assert.Contains(t, info.Description, "FIPS")
	assert.Equal(t, 33, info.PublicKeySize) // Compressed point
}

func TestGetAlgorithmInfo_Secp256k1(t *testing.T) {
	info := GetAlgorithmInfo(types.FrostAlgorithmSecp256k1)
	require.NotNil(t, info)

	assert.Contains(t, info.Description, "Bitcoin")
}

func TestGetAlgorithmInfo_Unknown(t *testing.T) {
	info := GetAlgorithmInfo("unknown")
	assert.Nil(t, info)
}

func TestListSupportedAlgorithms(t *testing.T) {
	algorithms := ListSupportedAlgorithms()

	assert.Len(t, algorithms, 5)
	assert.Contains(t, algorithms, types.FrostAlgorithmEd25519)
	assert.Contains(t, algorithms, types.FrostAlgorithmRistretto255)
	assert.Contains(t, algorithms, types.FrostAlgorithmEd448)
	assert.Contains(t, algorithms, types.FrostAlgorithmP256)
	assert.Contains(t, algorithms, types.FrostAlgorithmSecp256k1)
}

func TestDefaultAlgorithm(t *testing.T) {
	algo := DefaultAlgorithm()
	assert.Equal(t, types.FrostAlgorithmEd25519, algo)
}

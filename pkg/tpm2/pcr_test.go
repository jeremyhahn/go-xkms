//go:build tpm_simulator
// +build tpm_simulator

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtendPCR_EmptyData(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	require.True(t, ok)

	err := tpm2.ExtendPCR(16, "sha256", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data cannot be nil or empty")
}

func TestExtendPCR_EmptySlice(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	require.True(t, ok)

	err := tpm2.ExtendPCR(16, "sha256", []byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data cannot be nil or empty")
}

func TestExtendPCR_InvalidHashAlgorithm(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	require.True(t, ok)

	err := tpm2.ExtendPCR(16, "md5", []byte("test data"))
	assert.Error(t, err)
	// Should fail because md5 is not a valid PCR bank algorithm
}

func TestExtendPCR_SHA1_ValidInput(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	require.True(t, ok)

	// Debug PCR 16 is extendable
	err := tpm2.ExtendPCR(16, "sha1", []byte("test data"))
	assert.NoError(t, err)
}

func TestExtendPCR_SHA256_ValidInput(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	require.True(t, ok)

	before, err := tpm2.ReadPCRs([]uint{16})
	require.NoError(t, err)

	// Debug PCR 16 is extendable
	err = tpm2.ExtendPCR(16, "sha256", []byte("test data"))
	assert.NoError(t, err)

	// Verify PCR is extended
	after, err := tpm2.ReadPCRs([]uint{16})
	require.NoError(t, err)
	assert.NotEqual(t, before, after)
}

func TestExtendPCR_SHA384_ValidInput(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	require.True(t, ok)

	// Debug PCR 16 is extendable
	err := tpm2.ExtendPCR(16, "sha384", []byte("test data"))
	assert.NoError(t, err)
}

func TestExtendPCR_SHA512_ValidInput(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	require.True(t, ok)

	// Debug PCR 16 is extendable
	err := tpm2.ExtendPCR(16, "sha512", []byte("test data"))
	assert.NoError(t, err)
}

func TestExtendPCR_UnknownHashAlgorithm(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	require.True(t, ok)

	// sha3-256 is not a standard TPM PCR bank algorithm
	err := tpm2.ExtendPCR(16, "sha3-256", []byte("test data"))
	assert.Error(t, err)
	// The error message should indicate this is an unsupported algorithm
	// The error comes from ParsePCRBankAlgID
}

func TestExtendPCR_MultipleExtensions(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	require.True(t, ok)

	before, err := tpm2.ReadPCRs([]uint{16})
	require.NoError(t, err)

	// Extend PCR multiple times
	err = tpm2.ExtendPCR(16, "sha256", []byte("data 1"))
	require.NoError(t, err)

	err = tpm2.ExtendPCR(16, "sha256", []byte("data 2"))
	require.NoError(t, err)

	err = tpm2.ExtendPCR(16, "sha256", []byte("data 3"))
	require.NoError(t, err)

	// PCR should be extended
	after, err := tpm2.ReadPCRs([]uint{16})
	require.NoError(t, err)
	assert.NotEqual(t, before, after)
}

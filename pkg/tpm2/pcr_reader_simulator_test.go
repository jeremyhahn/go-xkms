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

func TestBankPCRReader_ReadsTheNamedBank(t *testing.T) {
	_, tpm := createSim(false)
	defer func() { _ = tpm.Close() }()

	concrete, ok := tpm.(*TPM2)
	require.True(t, ok)
	require.NoError(t, concrete.ExtendPCR(16, "sha256", []byte("bank-pcr-reader")))

	reader, err := NewBankPCRReader(tpm)
	require.NoError(t, err)

	banks, err := tpm.ReadPCRs([]uint{0, 16})
	require.NoError(t, err)

	values, err := reader.ReadPCRs("SHA256", []int{0, 16})
	require.NoError(t, err)
	require.Len(t, values, 2)
	assert.Equal(t, pcrValue(t, banks, "SHA256", 16), values[16])
	assert.Equal(t, pcrValue(t, banks, "SHA256", 0), values[0])
	assert.Len(t, values[16], 32)

	sha1Values, err := reader.ReadPCRs("sha1", []int{16})
	require.NoError(t, err)
	assert.Len(t, sha1Values[16], 20)
	assert.Equal(t, pcrValue(t, banks, "SHA1", 16), sha1Values[16])
}

func TestBankPCRReader_NoIndicesReadsNothing(t *testing.T) {
	_, tpm := createSim(false)
	defer func() { _ = tpm.Close() }()

	reader, err := NewBankPCRReader(tpm)
	require.NoError(t, err)

	values, err := reader.ReadPCRs("sha256", nil)
	require.NoError(t, err)
	assert.Empty(t, values)
}

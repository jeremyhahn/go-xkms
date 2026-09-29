// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package tpm2

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBankPCRReader_NilTPM(t *testing.T) {
	reader, err := NewBankPCRReader(nil)
	assert.Nil(t, reader)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// The bank and indices are validated before the TPM is touched, so a reader
// with no TPM behind it answers these refusals without panicking.
func TestBankPCRReader_RefusesBeforeTouchingTheTPM(t *testing.T) {
	reader := &BankPCRReader{}

	_, err := reader.ReadPCRs("md5", []int{16})
	assert.ErrorIs(t, err, ErrInvalidPCRBankType)

	_, err = reader.ReadPCRs("", []int{16})
	assert.ErrorIs(t, err, ErrInvalidPCRBankType)

	_, err = reader.ReadPCRs("sha256", []int{16, -1})
	assert.ErrorIs(t, err, ErrInvalidPCRIndex)

	_, err = reader.ReadPCRs("sha256", []int{maxPCRIndex + 1})
	assert.ErrorIs(t, err, ErrInvalidPCRIndex)
}

func TestPCRReadError_UnwrapsAndNamesThePCR(t *testing.T) {
	err := &PCRReadError{Bank: "sha384", Index: 7, Err: ErrPCRBankUnavailable}
	require.True(t, errors.Is(err, ErrPCRBankUnavailable))
	assert.Equal(t, "tpm: reading PCR 7 in bank sha384: "+ErrPCRBankUnavailable.Error(), err.Error())
}

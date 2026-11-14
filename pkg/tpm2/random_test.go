//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomBytes_VeryLargeRequest(t *testing.T) {

	_, tpm := createSim(t, true)
	defer func() { _ = tpm.Close() }()

	// Test a very large request
	size := 1024
	randomBytes, err := tpm.RandomBytes(size)
	assert.Nil(t, err)
	assert.Equal(t, size, len(randomBytes))
}

func TestRandomHex_ValidLength(t *testing.T) {

	_, tpm := createSim(t, true)
	defer func() { _ = tpm.Close() }()

	// Test valid hex encoding
	hexBytes, err := tpm.RandomHex(32)
	assert.Nil(t, err)
	assert.Equal(t, 32, len(hexBytes))

	// Verify it's valid hex
	_, err = hex.DecodeString(string(hexBytes))
	assert.Nil(t, err)
}

func TestRandomHex_InvalidLength(t *testing.T) {

	_, tpm := createSim(t, true)
	defer func() { _ = tpm.Close() }()

	// Test with odd length (must be even)
	_, err := tpm.RandomHex(31)
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)

	// Test with zero length
	_, err = tpm.RandomHex(0)
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)

	// Test with negative length
	_, err = tpm.RandomHex(-2)
	assert.NotNil(t, err)
	assert.Equal(t, ErrInvalidRandomBytesLength, err)
}

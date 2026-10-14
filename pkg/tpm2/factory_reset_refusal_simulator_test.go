//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFactoryReset_WrongOwnerAuthKeepsKeys proves a factory reset the owner
// hierarchy refuses reports ErrFactoryReset and evicts nothing, rather than
// claiming a reset that never happened.
func TestFactoryReset_WrongOwnerAuthKeepsKeys(t *testing.T) {
	h := newSimHarness(t, nil)
	iakHandle := tpm2.TPMHandle(h.TPM.config.IAK.Handle)
	_, before, err := h.TPM.ReadHandle(iakHandle)
	require.NoError(t, err)

	err = h.TPM.FactoryReset([]byte("not-the-owner-auth"))
	assert.ErrorIs(t, err, ErrFactoryReset)

	_, after, err := h.TPM.ReadHandle(iakHandle)
	require.NoError(t, err, "a refused reset must leave the IAK persisted")
	assert.Equal(t, before.Unique, after.Unique)
}

//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSealKey_FailurePaths proves SealKey refuses, without storing anything,
// a parent that is not persisted and a random source that cannot fill the
// generated secret.
func TestSealKey_FailurePaths(t *testing.T) {
	h := newSimHarness(t, nil)

	t.Run("parent not persisted", func(t *testing.T) {
		attrs := sealedKeyAttrs(t, h, "seal-missing-parent", false, mustPassword(t, []byte("seal-pin")))
		parent := *attrs.Parent
		parentTPM := *parent.TPMAttributes
		parentTPM.Handle = 0x810100EE
		parent.TPMAttributes = &parentTPM
		attrs.Parent = &parent

		_, err := h.TPM.SealKey(attrs, h.Backend, true)
		assert.Error(t, err)
	})

	t.Run("random source fails", func(t *testing.T) {
		attrs := sealedKeyAttrs(t, h, "seal-no-entropy", false, mustPassword(t, []byte("seal-pin")))
		random := h.TPM.random
		h.TPM.random = failingReader{}
		t.Cleanup(func() { h.TPM.random = random })

		_, err := h.TPM.SealKey(attrs, h.Backend, true)
		assert.ErrorIs(t, err, errShortRead)
		assert.Nil(t, attrs.SealData, "no secret may be recorded when none was generated")
	})
}

// TestSealKey_ExistingWithoutOverwrite proves a second seal under the same
// name without overwrite is refused and leaves the first secret sealed.
func TestSealKey_ExistingWithoutOverwrite(t *testing.T) {
	h := newSimHarness(t, nil)
	first := []byte("first-sealed-secret")

	attrs := sealedKeyAttrs(t, h, "seal-no-overwrite", false, mustPassword(t, []byte("seal-pin")))
	attrs.SealData = types.NewSealData(first)
	_, err := h.TPM.SealKey(attrs, h.Backend, false)
	require.NoError(t, err)

	again := sealedKeyAttrs(t, h, "seal-no-overwrite", false, mustPassword(t, []byte("seal-pin")))
	again.SealData = types.NewSealData([]byte("second-sealed-secret"))
	_, err = h.TPM.SealKey(again, h.Backend, false)
	require.Error(t, err)

	got, err := h.TPM.UnsealKey(sealedKeyAttrs(t, h, "seal-no-overwrite", false, mustPassword(t, []byte("seal-pin"))), h.Backend)
	require.NoError(t, err)
	assert.Equal(t, first, got)
}

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// policyWriteAuth is the write secret the authorized-policy tests define
// their policy indices and counters with.
var policyWriteAuth = []byte("policy-index-write-secret-000001")

// TestPolicyIndex_DefineWriteRead proves a policy index is defined, written
// with its write secret and read back without one, and that the Name objects
// bind to is the written Name, not the defined one.
func TestPolicyIndex_DefineWriteRead(t *testing.T) {
	h := newSimHarness(t, nil)

	index, err := h.TPM.FindFreeNVIndex(NVOwnerIndexFirst, NVOwnerIndexLast)
	require.NoError(t, err)

	definedName, err := h.TPM.DefinePolicyIndex(index, tpm2.TPMAlgSHA256, policyWriteAuth, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.TPM.UndefineNVIndex(index, nil) })

	digest := bytes.Repeat([]byte{0xA5}, 32)
	writtenName, err := h.TPM.WritePolicyIndex(index, policyWriteAuth, digest, tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	assert.NotEqual(t, definedName.Buffer, writtenName.Buffer, "the first write sets TPMA_NV_WRITTEN, which is part of the Name")

	liveName, err := h.TPM.NVIndexName(index)
	require.NoError(t, err)
	assert.Equal(t, writtenName.Buffer, liveName.Buffer)

	alg, got, err := h.TPM.ReadPolicyIndex(index)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMAlgSHA256, alg)
	assert.Equal(t, digest, got)
}

// TestPolicyIndex_WriteRejectsWrongSecret proves the index is only writable
// with its write secret, and that a malformed digest is refused before the TPM
// is asked.
func TestPolicyIndex_WriteRejectsWrongSecret(t *testing.T) {
	h := newSimHarness(t, nil)

	index, err := h.TPM.FindFreeNVIndex(NVOwnerIndexFirst, NVOwnerIndexLast)
	require.NoError(t, err)
	_, err = h.TPM.DefinePolicyIndex(index, tpm2.TPMAlgSHA256, policyWriteAuth, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.TPM.UndefineNVIndex(index, nil) })

	_, err = h.TPM.WritePolicyIndex(index, []byte("wrong"), make([]byte, 32), tpm2.TPMAlgSHA256)
	require.Error(t, err)

	_, err = h.TPM.WritePolicyIndex(index, policyWriteAuth, make([]byte, 31), tpm2.TPMAlgSHA256)
	require.ErrorIs(t, err, ErrInvalidPolicyIndexContent)

	_, _, err = h.TPM.ReadPolicyIndex(index)
	require.Error(t, err, "an index that was never written cannot be read")
}

// TestCounterIndex_DefineIncrementRead proves a counter is readable as soon
// as it is defined (DefineCounterIndex increments it once), increments only
// with its write secret, and reads without one.
func TestCounterIndex_DefineIncrementRead(t *testing.T) {
	h := newSimHarness(t, nil)

	index, err := h.TPM.FindFreeNVIndex(NVOwnerIndexFirst, NVOwnerIndexLast)
	require.NoError(t, err)
	name, err := h.TPM.DefineCounterIndex(index, policyWriteAuth, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.TPM.UndefineNVIndex(index, nil) })

	first, err := h.TPM.ReadCounter(index)
	require.NoError(t, err)

	next, err := h.TPM.IncrementCounter(index, policyWriteAuth)
	require.NoError(t, err)
	assert.Equal(t, first+1, next)

	read, err := h.TPM.ReadCounter(index)
	require.NoError(t, err)
	assert.Equal(t, next, read)

	liveName, err := h.TPM.NVIndexName(index)
	require.NoError(t, err)
	assert.Equal(t, name.Buffer, liveName.Buffer, "increments after the first leave the Name unchanged")

	_, err = h.TPM.IncrementCounter(index, []byte("wrong"))
	require.Error(t, err)
	read, err = h.TPM.ReadCounter(index)
	require.NoError(t, err)
	assert.Equal(t, next, read, "a refused increment must not move the counter")
}

// TestFindFreeNVIndex_SkipsDefinedIndex proves a defined index is never
// offered, and that a range with no free index is reported as exhausted.
func TestFindFreeNVIndex_SkipsDefinedIndex(t *testing.T) {
	h := newSimHarness(t, nil)

	first, err := h.TPM.FindFreeNVIndex(NVOwnerIndexFirst, NVOwnerIndexLast)
	require.NoError(t, err)
	_, err = h.TPM.DefineCounterIndex(first, policyWriteAuth, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.TPM.UndefineNVIndex(first, nil) })

	second, err := h.TPM.FindFreeNVIndex(first, NVOwnerIndexLast)
	require.NoError(t, err)
	assert.Greater(t, second, first)

	_, err = h.TPM.FindFreeNVIndex(first, first)
	require.ErrorIs(t, err, ErrTPMNVExhausted)
}

// TestFindFreeNVIndex_RejectsInvalidRange proves a range outside the NV
// handle type, or an empty one, is refused.
func TestFindFreeNVIndex_RejectsInvalidRange(t *testing.T) {
	h := newSimHarness(t, nil)

	_, err := h.TPM.FindFreeNVIndex(NVOwnerIndexLast, NVOwnerIndexFirst)
	require.ErrorIs(t, err, ErrInvalidNVIndexRange)
	_, err = h.TPM.FindFreeNVIndex(0x81000000, 0x81000010)
	require.ErrorIs(t, err, ErrInvalidNVIndexRange)
}

// TestUndefineNVIndex_RemovesIndex proves an undefined index is gone and
// that undefining a missing index fails.
func TestUndefineNVIndex_RemovesIndex(t *testing.T) {
	h := newSimHarness(t, nil)

	index, err := h.TPM.FindFreeNVIndex(NVOwnerIndexFirst, NVOwnerIndexLast)
	require.NoError(t, err)
	_, err = h.TPM.DefinePolicyIndex(index, tpm2.TPMAlgSHA256, policyWriteAuth, nil)
	require.NoError(t, err)

	require.NoError(t, h.TPM.UndefineNVIndex(index, nil))
	_, err = h.TPM.NVIndexName(index)
	require.Error(t, err)
	require.Error(t, h.TPM.UndefineNVIndex(index, nil))
}

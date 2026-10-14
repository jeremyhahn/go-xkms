//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"slices"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNvIndexes_ReportsEveryDefinedIndexType defines one NV index of each
// TCG type (ordinary, counter, extend) on a live simulator and proves
// nvIndexes enumerates all three with the correct Type classification and
// size. A regression that dropped a case from the pub.Attributes.NT switch,
// or that mis-set Size/AuthRead/AuthWrite from the wrong field, would leave
// this producing a report an operator or CLI could not trust.
func TestNvIndexes_ReportsEveryDefinedIndexType(t *testing.T) {
	h := newSimHarness(t, nil)

	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)

	ordinary := &types.KeyAttributes{
		Parent:   ekAttrs,
		Password: mustPassword(t, []byte("ordinary")),
		SealData: types.NewSealData([]byte("secret-payload")),
		TPMAttributes: &types.TPMAttributes{
			Handle:    tpm2.TPMHandle(nvramOwnerIndex),
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
	require.NoError(t, h.TPM.NVWrite(ordinary))
	t.Cleanup(func() { _ = h.TPM.NVUndefine(ordinary) })

	counter := &types.KeyAttributes{
		Parent: ekAttrs,
		TPMAttributes: &types.TPMAttributes{
			Handle:    tpm2.TPMHandle(nvramCounterIndex),
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
	require.NoError(t, h.TPM.NVDefineCounter(counter))
	t.Cleanup(func() { _ = h.TPM.NVUndefine(counter) })

	extend := &types.KeyAttributes{
		Parent: ekAttrs,
		TPMAttributes: &types.TPMAttributes{
			Handle:    tpm2.TPMHandle(nvramExtendIndex),
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
	require.NoError(t, h.TPM.NVDefineExtend(extend))
	t.Cleanup(func() { _ = h.TPM.NVUndefine(extend) })

	indexes, err := nvIndexes(h.TPM.transport, h.Logger)
	require.NoError(t, err)

	byHandle := make(map[tpm2.TPMHandle]NVIndexInfo, len(indexes))
	for _, idx := range indexes {
		byHandle[idx.Handle] = idx
	}

	ordinaryInfo, ok := byHandle[tpm2.TPMHandle(nvramOwnerIndex)]
	require.True(t, ok, "the ordinary index must be reported")
	assert.Equal(t, "ordinary", ordinaryInfo.Type)
	assert.Equal(t, uint16(len("secret-payload")), ordinaryInfo.Size)

	counterInfo, ok := byHandle[tpm2.TPMHandle(nvramCounterIndex)]
	require.True(t, ok, "the counter index must be reported")
	assert.Equal(t, "counter", counterInfo.Type)

	extendInfo, ok := byHandle[tpm2.TPMHandle(nvramExtendIndex)]
	require.True(t, ok, "the extend index must be reported")
	assert.Equal(t, "extend", extendInfo.Type)

	names := make([]tpm2.TPMHandle, 0, len(indexes))
	for _, idx := range indexes {
		names = append(names, idx.Handle)
	}
	require.True(t, slices.Contains(names, tpm2.TPMHandle(nvramOwnerIndex)))
}

// TestNvIndexes_SkipsIndexesThatDisappearBetweenEnumerationAndRead covers the
// defensive per-index error handling nvIndexes documents: TPM2_GetCapability
// enumerates the defined handles first, and a later NVReadPublic against one
// of those handles can still fail (the index was undefined concurrently, or
// -- as reproduced here -- the transport drops the follow-up read). nvIndexes
// must log and skip that entry rather than aborting the whole report, so one
// uncooperative index never hides every other index's data from an operator.
func TestNvIndexes_SkipsIndexesThatDisappearBetweenEnumerationAndRead(t *testing.T) {
	h := newSimHarness(t, nil)

	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)

	counter := &types.KeyAttributes{
		Parent: ekAttrs,
		TPMAttributes: &types.TPMAttributes{
			Handle:    tpm2.TPMHandle(nvramCounterIndex),
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
	require.NoError(t, h.TPM.NVDefineCounter(counter))
	t.Cleanup(func() { _ = h.TPM.NVUndefine(counter) })

	faulty := &createFaultyTransport{inner: h.TPM.transport, failCC: tpm2.TPMCCNVReadPublic}

	indexes, err := nvIndexes(faulty, discardLogger())
	require.NoError(t, err, "a per-index read failure must not fail the whole enumeration")
	assert.Empty(t, indexes, "the one defined index must have been skipped, not reported")
	assert.Greater(t, faulty.failCount, 0, "precondition: NVReadPublic must have been attempted and failed")
}

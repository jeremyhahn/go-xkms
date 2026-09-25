//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capabilitySelectorRewritingTransport rewrites the Capability selector of
// every TPM2_GetCapability request to a fixed value before the command
// reaches the real transport. The simulator answers honestly for whatever
// capability it is asked for, so the response comes back well-formed and
// internally consistent -- just carrying a different TPMU_CAPABILITIES union
// member than the caller assumed it would request. This reproduces, without
// any hand-rolled response encoding, exactly the shape of bug the accessors
// below must defend against: a GetCapability response whose union tag does
// not match what the accessor is about to read from it.
type capabilitySelectorRewritingTransport struct {
	inner  transport.TPM
	newCap tpm2.TPMCap
}

func (m *capabilitySelectorRewritingTransport) Send(input []byte) ([]byte, error) {
	if len(input) >= getCapCapabilityOffset+4 {
		cc := tpm2.TPMCC(binary.BigEndian.Uint32(input[tpmCCOffset : tpmCCOffset+4]))
		if cc == tpm2.TPMCCGetCapability {
			rewritten := make([]byte, len(input))
			copy(rewritten, input)
			binary.BigEndian.PutUint32(
				rewritten[getCapCapabilityOffset:getCapCapabilityOffset+4],
				uint32(m.newCap))
			return m.inner.Send(rewritten)
		}
	}
	return m.inner.Send(input)
}

// stringAccessor pairs a string-returning capability accessor with its name
// for table output.
type stringAccessor struct {
	name string
	fn   func(transport.TPM) (string, error)
}

var allStringAccessors = []stringAccessor{
	{"family", family},
	{"manufacturer", manufacturer},
	{"manufacturerCode", manufacturerCode},
	{"model", model},
	{"revision", revision},
	{"vendorID", vendorID},
}

// TestCapabilityAccessors_UnionMismatch_PropagatesError proves every
// property-reading capability accessor checks the union selector on the
// response it gets back, rather than assuming CapabilityData.Data always
// holds TPM properties. A TPM that (legitimately, per TCG's "next
// implemented property" rule) or a proxy/resource-manager bug that answers
// with a different capability union must surface as an error, never as a
// silently wrong or zero reading.
func TestCapabilityAccessors_UnionMismatch_PropagatesError(t *testing.T) {
	h := newSimHarness(t, nil)
	wrongCap := &capabilitySelectorRewritingTransport{inner: h.TPM.transport, newCap: tpm2.TPMCapHandles}

	for _, acc := range allUint32Accessors {
		t.Run(acc.name, func(t *testing.T) {
			v, err := acc.fn(wrongCap)
			require.Error(t, err, "%s must reject a response carrying the wrong capability union", acc.name)
			assert.Zero(t, v, "%s must not return a value alongside a union-mismatch error", acc.name)
		})
	}

	for _, acc := range allStringAccessors {
		t.Run(acc.name, func(t *testing.T) {
			v, err := acc.fn(wrongCap)
			require.Error(t, err, "%s must reject a response carrying the wrong capability union", acc.name)
			assert.Empty(t, v, "%s must not return a value alongside a union-mismatch error", acc.name)
		})
	}

	t.Run("firmware", func(t *testing.T) {
		major, minor, err := firmware(wrongCap)
		require.Error(t, err)
		assert.Zero(t, major)
		assert.Zero(t, minor)
	})

	t.Run("queryPropertyBatch", func(t *testing.T) {
		batch, err := queryPropertyBatch(wrongCap, tpm2.TPMPTFamilyIndicator, 100)
		require.Error(t, err)
		assert.Empty(t, batch)
	})

	t.Run("IsFIPS140_2", func(t *testing.T) {
		original := h.TPM.transport
		h.TPM.transport = wrongCap
		t.Cleanup(func() { h.TPM.transport = original })

		fips, err := h.TPM.IsFIPS140_2()
		require.Error(t, err, "IsFIPS140_2 must reject a response carrying the wrong capability union")
		assert.False(t, fips)
	})
}

// TestHandleAccessors_UnionMismatch_PropagatesError proves the TPM_CAP_HANDLES
// accessors -- which read the union's Handles() member rather than
// TPMProperties() -- are equally defensive against a response carrying an
// unexpected capability union.
func TestHandleAccessors_UnionMismatch_PropagatesError(t *testing.T) {
	h := newSimHarness(t, nil)
	wrongCap := &capabilitySelectorRewritingTransport{inner: h.TPM.transport, newCap: tpm2.TPMCapTPMProperties}

	t.Run("persistentHandles", func(t *testing.T) {
		v, err := persistentHandles(wrongCap)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrListPersistentHandles)
		assert.Empty(t, v)
	})
	t.Run("transientHandles", func(t *testing.T) {
		v, err := transientHandles(wrongCap)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrListTransientHandles)
		assert.Empty(t, v)
	})
	t.Run("nvIndexes", func(t *testing.T) {
		v, err := nvIndexes(wrongCap, discardLogger())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrListNVIndexes)
		assert.Empty(t, v)
	})
}

// TestQueryPropertyBatch_PaginatesAcrossMultiplePages proves the pagination
// loop actually advances to the next page: with PropertyCount pinned to 1,
// the TPM's MoreData flag stays true after every response but the last, so a
// batch that only ever read the first page would return a single-entry map
// instead of the full property set. This is the one shape of GetCapability
// traffic none of the package's other tests produce, since every other
// caller requests a page large enough to collect everything in one round
// trip.
func TestQueryPropertyBatch_PaginatesAcrossMultiplePages(t *testing.T) {
	h := newSimHarness(t, nil)

	paged, err := queryPropertyBatch(h.TPM.transport, tpm2.TPMPTFamilyIndicator, 1)
	require.NoError(t, err)

	whole, err := queryPropertyBatch(h.TPM.transport, tpm2.TPMPTFamilyIndicator, 100)
	require.NoError(t, err)

	require.Greater(t, len(paged), 1,
		"a one-property-per-page batch must still traverse more than one page")
	assert.Equal(t, whole, paged,
		"paginating one property at a time must collect the same set as one large page")
}

// TestQueryPropertyBatch_NoImplementedPropertyAtOrAfterStart_ReturnsEmpty
// covers the TCG behavior at the tail of the property space: a TPM that has
// no implemented property at or after the requested start value answers with
// zero properties and MoreData false rather than an error. queryPropertyBatch
// must recognize that as "nothing more to page through," not misread it as a
// transport or decode failure.
func TestQueryPropertyBatch_NoImplementedPropertyAtOrAfterStart_ReturnsEmpty(t *testing.T) {
	h := newSimHarness(t, nil)

	batch, err := queryPropertyBatch(h.TPM.transport, tpm2.TPMPT(0x7FFFFFFF), 1)
	require.NoError(t, err)
	assert.Empty(t, batch)
}

// TestIsFIPS140_2_NoPropertyAtOrAfterModes_ReportsFalse covers the case
// where TPM_PT_MODES is unimplemented AND no other property sorts after it
// (the last-property edge case), so GetCapability returns zero properties
// rather than the "next implemented property" TestIsFIPS140_2_TPMWithoutModesProperty_ReportsFalse
// exercises. Both are "not advertising FIPS mode" and must report false, not
// an error.
func TestIsFIPS140_2_NoPropertyAtOrAfterModes_ReportsFalse(t *testing.T) {
	h := newSimHarness(t, nil)

	rewriter := &propertyRewritingTransport{
		inner:    h.TPM.transport,
		fromProp: tpm2.TPMPTModes,
		toProp:   tpm2.TPMPT(0x7FFFFFFF),
	}
	original := h.TPM.transport
	h.TPM.transport = rewriter
	t.Cleanup(func() { h.TPM.transport = original })

	fips, err := h.TPM.IsFIPS140_2()
	require.NoError(t, err, "no implemented property at or after TPM_PT_MODES must not be an error")
	assert.False(t, fips)
	require.Equal(t, 1, rewriter.rewrites, "precondition: the modes query must have been rewritten exactly once")
}

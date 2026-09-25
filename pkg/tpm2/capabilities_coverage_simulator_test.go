//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errCapabilityTransport is a synthetic transport fault used to drive the
// error branch of every capability query. It never reaches a TPM, so it needs
// no simulator instance of its own -- which matters because the go-tpm-tools
// simulator is a process-global singleton and only one may be live at a time.
var errCapabilityTransport = errors.New("tpm: synthetic transport failure")

// failingTransport fails every command send. Capability queries are pure
// request/response with no session state, so a blanket failure is exactly the
// shape of a transport that has gone away (device unplugged, resource manager
// closed, TCP simulator disconnected).
type failingTransport struct{}

func (failingTransport) Send([]byte) ([]byte, error) { return nil, errCapabilityTransport }

// uint32Accessor pairs a capability accessor with its name for table output.
type uint32Accessor struct {
	name string
	fn   func(transport.TPM) (uint32, error)
}

// allUint32Accessors is every package-private single-property capability
// accessor. They share one implementation shape (GetCapability, then read the
// first returned property), so covering them as a table proves the whole family
// propagates transport failures instead of silently returning a zero value --
// a zero returned as if it were real data would, for example, make
// lockoutCounter report "no failed auth attempts" on a broken transport.
var allUint32Accessors = []uint32Accessor{
	{"memory", memory},
	{"persistentLoaded", persistentLoaded},
	{"persistentAvail", persistentAvail},
	{"persistentMin", persistentMin},
	{"transientMin", transientMin},
	{"transientAvail", transientAvail},
	{"activeSessionsMax", activeSessionsMax},
	{"authSessionsActive", authSessionsActive},
	{"authSessionsActiveAvail", authSessionsActiveAvail},
	{"authSessionsLoaded", authSessionsLoaded},
	{"authSessionsLoadedAvail", authSessionsLoadedAvail},
	{"level", level},
	{"loadedCurves", loadedCurves},
	{"lockoutCounter", lockoutCounter},
	{"lockoutRecovery", lockoutRecovery},
	{"lockoutInterval", lockoutInterval},
	{"maxAuthFail", maxAuthFail},
	{"nvIndexesDefined", nvIndexesDefined},
	{"nvIndexesMax", nvIndexesMax},
	{"nvBufferMax", nvBufferMax},
	{"inputBufferMax", inputBufferMax},
	{"maxDigestSize", maxDigestSize},
	{"maxObjectContext", maxObjectContext},
	{"nvWriteRecovery", nvWriteRecovery},
}

// TestCapabilityAccessors_TransportFailure_PropagatesError proves no capability
// accessor swallows a transport failure. Each must return the error and the
// zero value, never a zero value with a nil error that a caller would mistake
// for a genuine TPM reading.
func TestCapabilityAccessors_TransportFailure_PropagatesError(t *testing.T) {
	broken := failingTransport{}

	for _, acc := range allUint32Accessors {
		t.Run(acc.name, func(t *testing.T) {
			v, err := acc.fn(broken)
			require.Error(t, err, "%s must report the transport failure", acc.name)
			assert.Zero(t, v, "%s must not return a value alongside an error", acc.name)
		})
	}

	t.Run("family", func(t *testing.T) {
		v, err := family(broken)
		require.Error(t, err)
		assert.Empty(t, v)
	})
	t.Run("manufacturer", func(t *testing.T) {
		v, err := manufacturer(broken)
		require.Error(t, err)
		assert.Empty(t, v)
	})
	t.Run("model", func(t *testing.T) {
		v, err := model(broken)
		require.Error(t, err)
		assert.Empty(t, v)
	})
	t.Run("revision", func(t *testing.T) {
		v, err := revision(broken)
		require.Error(t, err)
		assert.Empty(t, v)
	})
	t.Run("vendorID", func(t *testing.T) {
		v, err := vendorID(broken)
		require.Error(t, err)
		assert.Empty(t, v)
	})
	t.Run("firmware", func(t *testing.T) {
		major, minor, err := firmware(broken)
		require.Error(t, err)
		assert.Zero(t, major)
		assert.Zero(t, minor)
	})
	t.Run("persistentHandles", func(t *testing.T) {
		v, err := persistentHandles(broken)
		require.Error(t, err)
		assert.Empty(t, v)
	})
	t.Run("transientHandles", func(t *testing.T) {
		v, err := transientHandles(broken)
		require.Error(t, err)
		assert.Empty(t, v)
	})
	t.Run("nvIndexes", func(t *testing.T) {
		v, err := nvIndexes(broken, discardLogger())
		require.Error(t, err)
		assert.Empty(t, v)
	})
	t.Run("queryPropertyBatch", func(t *testing.T) {
		batch, err := queryPropertyBatch(broken, tpm2.TPMPTFamilyIndicator, 100)
		require.Error(t, err)
		assert.Empty(t, batch)
	})
}

// TestTPM2CapabilityMethods_TransportFailure_PropagateError covers the exported
// capability surface against a dead transport. These are the methods a CLI or
// API handler calls to render a "TPM info" view; each must surface the failure
// rather than render an empty-but-successful report.
func TestTPM2CapabilityMethods_TransportFailure_PropagateError(t *testing.T) {
	h := newSimHarness(t, nil)

	// Swap in the broken transport after provisioning so only the capability
	// calls under test see the fault. The simulator stays owned by the harness.
	original := h.TPM.transport
	h.TPM.transport = failingTransport{}
	t.Cleanup(func() { h.TPM.transport = original })

	t.Run("AllFixedProperties", func(t *testing.T) {
		props, err := h.TPM.AllFixedProperties()
		require.Error(t, err)
		assert.Nil(t, props)
	})
	t.Run("AllVariableProperties", func(t *testing.T) {
		props, err := h.TPM.AllVariableProperties()
		require.Error(t, err)
		assert.Nil(t, props)
	})
	t.Run("SupportedAlgorithms", func(t *testing.T) {
		algs, err := h.TPM.SupportedAlgorithms()
		require.Error(t, err)
		assert.Nil(t, algs)
	})
	t.Run("SupportedCommands", func(t *testing.T) {
		cmds, err := h.TPM.SupportedCommands()
		require.Error(t, err)
		assert.Nil(t, cmds)
	})
	t.Run("SupportedCommandsInfo", func(t *testing.T) {
		info, err := h.TPM.SupportedCommandsInfo()
		require.Error(t, err)
		assert.Nil(t, info)
	})
	t.Run("SupportedECCCurves", func(t *testing.T) {
		curves, err := h.TPM.SupportedECCCurves()
		require.Error(t, err)
		assert.Nil(t, curves)
	})
	t.Run("IsFIPS140_2", func(t *testing.T) {
		fips, err := h.TPM.IsFIPS140_2()
		require.Error(t, err)
		assert.False(t, fips)
	})
	t.Run("Capabilities", func(t *testing.T) {
		caps, err := h.TPM.Capabilities()
		require.Error(t, err)
		assert.Nil(t, caps)
	})
}

// TestQueryAlgorithms_TransportFailure and TestQueryECCCurves_TransportFailure
// cover the TPM_CAP_ALGS / TPM_CAP_ECC_CURVES paginating queries directly.
// Capabilities calls queryAlgorithms first and queryECCCurves only if that
// succeeds, so the table above never reaches queryECCCurves's own transport
// check; calling each function directly proves both refuse a dead transport
// on their own first GetCapability call, rather than returning an empty map
// indistinguishable from "device implements nothing".
func TestQueryAlgorithms_TransportFailure(t *testing.T) {
	algs, err := queryAlgorithms(failingTransport{})
	require.Error(t, err)
	assert.Nil(t, algs)
}

func TestQueryECCCurves_TransportFailure(t *testing.T) {
	curves, err := queryECCCurves(failingTransport{})
	require.Error(t, err)
	assert.Nil(t, curves)
}

// getCapPropertyCountOffset is the byte offset of TPM2_GetCapability's
// propertyCount parameter: header(10) + capability(4) + property(4).
const getCapPropertyCountOffset = 18

// pageSizeCappingTransport rewrites TPM2_GetCapability's propertyCount to 1
// for one capability selector, forcing the simulator's honest (and
// otherwise single-page) answer across several round trips. It is how
// queryAlgorithms/queryECCCurves's moreData pagination loop is exercised
// without depending on a device that happens to implement more entries than
// this package's own hardcoded capabilityPageSize requests in one call.
type pageSizeCappingTransport struct {
	inner      transport.TPM
	capability tpm2.TPMCap
}

func (m *pageSizeCappingTransport) Send(input []byte) ([]byte, error) {
	if len(input) >= getCapPropertyCountOffset+4 {
		cc := tpm2.TPMCC(binary.BigEndian.Uint32(input[tpmCCOffset : tpmCCOffset+4]))
		capability := binary.BigEndian.Uint32(input[getCapCapabilityOffset : getCapCapabilityOffset+4])
		if cc == tpm2.TPMCCGetCapability && capability == uint32(m.capability) {
			rewritten := make([]byte, len(input))
			copy(rewritten, input)
			binary.BigEndian.PutUint32(rewritten[getCapPropertyCountOffset:getCapPropertyCountOffset+4], 1)
			return m.inner.Send(rewritten)
		}
	}
	return m.inner.Send(input)
}

// TestQueryAlgorithms_PaginatesAcrossMultiplePages proves the moreData loop
// actually advances to the next page rather than only ever reading the
// first: with propertyCount pinned to 1, collecting one algorithm at a time
// must still reach the same set queryAlgorithms's own default page size
// (100) collects in a single round trip.
func TestQueryAlgorithms_PaginatesAcrossMultiplePages(t *testing.T) {
	h := newSimHarness(t, nil)

	paged, err := queryAlgorithms(&pageSizeCappingTransport{inner: h.TPM.transport, capability: tpm2.TPMCapAlgs})
	require.NoError(t, err)
	whole, err := queryAlgorithms(h.TPM.transport)
	require.NoError(t, err)

	require.Greater(t, len(paged), 1,
		"a one-algorithm-per-page query must still traverse more than one page")
	assert.Equal(t, whole, paged,
		"paginating one algorithm at a time must collect the same set as one large page")
}

// TestQueryECCCurves_PaginatesAcrossMultiplePages is
// TestQueryAlgorithms_PaginatesAcrossMultiplePages for TPM_CAP_ECC_CURVES.
func TestQueryECCCurves_PaginatesAcrossMultiplePages(t *testing.T) {
	h := newSimHarness(t, nil)

	paged, err := queryECCCurves(&pageSizeCappingTransport{inner: h.TPM.transport, capability: tpm2.TPMCapECCCurves})
	require.NoError(t, err)
	whole, err := queryECCCurves(h.TPM.transport)
	require.NoError(t, err)

	require.Greater(t, len(paged), 1,
		"a one-curve-per-page query must still traverse more than one page")
	assert.Equal(t, whole, paged,
		"paginating one curve at a time must collect the same set as one large page")
}

// TestAllFixedProperties_ReturnsSortedNamedProperties proves AllFixedProperties
// returns canonically-named, sorted properties including the family indicator
// rendered as a readable string rather than a raw integer. A regression that
// dropped the name lookup or the sort would surface here.
func TestAllFixedProperties_ReturnsSortedNamedProperties(t *testing.T) {
	h := newSimHarness(t, nil)

	props, err := h.TPM.AllFixedProperties()
	require.NoError(t, err)
	require.NotEmpty(t, props, "a TPM must report at least one fixed property")

	names := make([]string, len(props))
	for i, p := range props {
		names[i] = p.Name
		assert.NotEmpty(t, p.Raw, "%s must carry a raw hex value", p.Name)
		assert.True(t, len(p.Raw) > 2 && p.Raw[:2] == "0x",
			"%s raw value must be hex-formatted, got %q", p.Name, p.Raw)
	}
	assert.True(t, slices.IsSorted(names), "properties must be returned sorted by name")

	idx := slices.Index(names, "TPM2_PT_FAMILY_INDICATOR")
	require.GreaterOrEqual(t, idx, 0, "the fixed properties must include the family indicator")
	assert.Equal(t, "2.0", props[idx].Value,
		"the family indicator must be decoded from its packed 4-byte form to a readable string")
}

// TestAllVariableProperties_ReturnsNamedProperties covers the variable (0x200)
// property range, which reports mutable state such as the lockout counter.
func TestAllVariableProperties_ReturnsNamedProperties(t *testing.T) {
	h := newSimHarness(t, nil)

	props, err := h.TPM.AllVariableProperties()
	require.NoError(t, err)
	require.NotEmpty(t, props)

	names := make([]string, len(props))
	for i, p := range props {
		names[i] = p.Name
	}
	assert.True(t, slices.IsSorted(names), "properties must be returned sorted by name")
	assert.Contains(t, names, "TPM2_PT_PERMANENT",
		"the variable range must include the permanent-attributes property")
}

// TestSupportedCommands_IncludesMandatoryCommands proves the command-capability
// decode maps command codes to canonical names. TPM2_CC_Create is mandatory for
// any TPM 2.0 implementation, so its absence means the decode is broken rather
// than the TPM being unusual.
func TestSupportedCommands_IncludesMandatoryCommands(t *testing.T) {
	h := newSimHarness(t, nil)

	cmds, err := h.TPM.SupportedCommands()
	require.NoError(t, err)
	require.NotEmpty(t, cmds)

	for _, mandatory := range []string{
		"TPM2_CC_Create",
		"TPM2_CC_Load",
		"TPM2_CC_Unseal",
		"TPM2_CC_StartAuthSession",
		"TPM2_CC_GetCapability",
	} {
		assert.Contains(t, cmds, mandatory,
			"a TPM 2.0 implementation must advertise %s", mandatory)
	}
}

// TestSupportedCommandsInfo_DescribesEveryCommand proves the richer command
// listing never emits an entry with a blank name or description -- the CLI
// renders these directly, and a blank cell would be a visible defect.
func TestSupportedCommandsInfo_DescribesEveryCommand(t *testing.T) {
	h := newSimHarness(t, nil)

	info, err := h.TPM.SupportedCommandsInfo()
	require.NoError(t, err)
	require.NotEmpty(t, info)

	cmds, err := h.TPM.SupportedCommands()
	require.NoError(t, err)
	assert.Len(t, info, len(cmds),
		"SupportedCommandsInfo and SupportedCommands must describe the same command set")

	for _, ci := range info {
		assert.NotEmpty(t, ci.Code, "every command must carry a hex code")
		assert.NotEmpty(t, ci.Name, "every command must carry a name, vendor commands included")
		assert.NotEmpty(t, ci.Description, "every command must carry a description")
	}

	idx := slices.IndexFunc(info, func(ci CommandInfo) bool { return ci.Name == "TPM2_CC_Create" })
	require.GreaterOrEqual(t, idx, 0)
	assert.Equal(t, "Create a child object under a specified parent key", info[idx].Description)
}

// TestSupportedECCCurves_IncludesNISTP256 proves the ECC curve capability
// decode maps curve IDs to human names. P-256 is the curve the product's own
// ECC key templates default to, so a broken decode here would mislead operators
// about whether their configured curve is usable.
func TestSupportedECCCurves_IncludesNISTP256(t *testing.T) {
	h := newSimHarness(t, nil)

	curves, err := h.TPM.SupportedECCCurves()
	require.NoError(t, err)
	require.NotEmpty(t, curves)
	assert.Contains(t, curves, "NIST P-256")
}

// TestSupportedAlgorithms_IncludesRSAAndSHA256 proves the algorithm capability
// decode resolves algorithm IDs to names.
func TestSupportedAlgorithms_IncludesRSAAndSHA256(t *testing.T) {
	h := newSimHarness(t, nil)

	algs, err := h.TPM.SupportedAlgorithms()
	require.NoError(t, err)
	require.NotEmpty(t, algs)
	assert.Contains(t, algs, "RSA")
	assert.Contains(t, algs, "SHA-256")
}

// TestIsFIPS140_2_MatchesRawModesBit covers the TPM_PT_MODES decode by
// comparing the answer against the raw property read straight from the TPM,
// rather than hardcoding an expected value. That way the test validates the
// decode logic (correct property selected, bit 0 masked) on any TPM, and would
// catch a regression that read the wrong property index or returned the whole
// bitfield as a boolean.
func TestIsFIPS140_2_MatchesRawModesBit(t *testing.T) {
	h := newSimHarness(t, nil)

	fips, err := h.TPM.IsFIPS140_2()
	require.NoError(t, err, "a TPM that does not implement TPM_PT_MODES must not be an error")

	resp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTModes),
		PropertyCount: 1,
	}.Execute(h.TPM.transport)
	require.NoError(t, err)
	props, err := resp.CapabilityData.Data.TPMProperties()
	require.NoError(t, err)

	want := false
	if len(props.TPMProperty) > 0 && props.TPMProperty[0].Property == tpm2.TPMPTModes {
		want = props.TPMProperty[0].Value&0x1 == 0x1
	}
	assert.Equal(t, want, fips,
		"IsFIPS140_2 must report bit 0 of TPM_PT_MODES and nothing else")
}

// propertyRewritingTransport simulates a TPM that does not implement the
// queried property. Per TCG, such a TPM answers a GetCapability for an
// unimplemented property with the NEXT implemented property rather than an
// error. This transport reproduces that by rewriting the requested property
// from fromProp to toProp before the command reaches the simulator, so the
// response legitimately carries a different property.
//
// GetCapability takes no handles and no auth, so its parameter area starts
// immediately after the 10-byte header: tag(2) + commandSize(4) + commandCode(4),
// then capability(4), property(4), propertyCount(4).
type propertyRewritingTransport struct {
	inner    transport.TPM
	fromProp tpm2.TPMPT
	toProp   tpm2.TPMPT
	rewrites int
}

const (
	getCapCapabilityOffset = 10
	getCapPropertyOffset   = 14
)

func (m *propertyRewritingTransport) Send(input []byte) ([]byte, error) {
	if len(input) >= getCapPropertyOffset+4 {
		cc := tpm2.TPMCC(binary.BigEndian.Uint32(input[tpmCCOffset : tpmCCOffset+4]))
		capability := binary.BigEndian.Uint32(input[getCapCapabilityOffset : getCapCapabilityOffset+4])
		property := binary.BigEndian.Uint32(input[getCapPropertyOffset : getCapPropertyOffset+4])

		if cc == tpm2.TPMCCGetCapability &&
			capability == uint32(tpm2.TPMCapTPMProperties) &&
			property == uint32(m.fromProp) {

			rewritten := make([]byte, len(input))
			copy(rewritten, input)
			binary.BigEndian.PutUint32(
				rewritten[getCapPropertyOffset:getCapPropertyOffset+4],
				uint32(m.toProp))
			m.rewrites++
			return m.inner.Send(rewritten)
		}
	}
	return m.inner.Send(input)
}

// TestIsFIPS140_2_TPMWithoutModesProperty_ReportsFalse covers the subtle TCG
// rule the implementation documents: a TPM that does not implement
// TPM_PT_MODES answers with the next implemented property instead of an error.
// Reading that unrelated value as a FIPS flag would be a false positive -- the
// worst possible failure mode for a compliance check, since it would report a
// non-FIPS TPM as FIPS-enforcing.
//
// The rewriting transport makes the TPM answer with TPM_PT_FAMILY_INDICATOR,
// whose value (the packed ASCII "2.0\0" = 0x322E3000) has bit 0 clear but is
// plainly not a modes bitfield. The guard must key off the property identity.
func TestIsFIPS140_2_TPMWithoutModesProperty_ReportsFalse(t *testing.T) {
	h := newSimHarness(t, nil)

	rewriter := &propertyRewritingTransport{
		inner:    h.TPM.transport,
		fromProp: tpm2.TPMPTModes,
		toProp:   tpm2.TPMPTFamilyIndicator,
	}
	original := h.TPM.transport
	h.TPM.transport = rewriter
	t.Cleanup(func() { h.TPM.transport = original })

	fips, err := h.TPM.IsFIPS140_2()
	require.NoError(t, err,
		"a TPM that does not implement TPM_PT_MODES must not be reported as an error")
	assert.False(t, fips,
		"a response carrying a property other than TPM_PT_MODES must never be read as a FIPS answer")
	require.Equal(t, 1, rewriter.rewrites,
		"precondition: the modes query must have been rewritten exactly once")
}

// TestFixedProperties_PopulatesIdentityAndLimits proves FixedProperties
// assembles a coherent report. It deliberately tolerates individual property
// failures by design, so the assertions target the properties every TPM 2.0
// implementation must provide.
func TestFixedProperties_PopulatesIdentityAndLimits(t *testing.T) {
	h := newSimHarness(t, nil)

	props, err := h.TPM.FixedProperties()
	require.NoError(t, err)
	require.NotNil(t, props)

	assert.Equal(t, "2.0", props.Family, "the simulator implements TPM family 2.0")
	assert.NotEmpty(t, props.Manufacturer, "a TPM must report a manufacturer")
	assert.NotEmpty(t, props.Revision, "a TPM must report a specification revision")
	assert.NotEmpty(t, props.SupportedAlgorithms, "a TPM must advertise algorithms")

	// Limits must be self-consistent rather than merely non-zero: a report
	// claiming zero maximum input buffer or zero digest size would be unusable.
	assert.Greater(t, props.InputBufferMax, uint32(0), "the input buffer limit must be positive")
	assert.Greater(t, props.MaxDigestSize, uint32(0), "the maximum digest size must be positive")
	assert.GreaterOrEqual(t, props.MaxAuthFail, uint32(1),
		"a TPM must tolerate at least one auth failure before lockout")
	assert.LessOrEqual(t, props.LockoutCounter, props.MaxAuthFail,
		"the lockout counter cannot exceed the configured maximum auth failures")
}

// TestFixedProperties_TransportFailure_ReturnsEmptyReport documents the
// deliberate resilience contract of FixedProperties: individual property
// queries are best-effort, so a totally dead transport yields an empty report
// rather than an error. This is the one capability entry point that does NOT
// propagate failures, and pinning it prevents someone "fixing" it by accident.
func TestFixedProperties_TransportFailure_ReturnsEmptyReport(t *testing.T) {
	h := newSimHarness(t, nil)

	original := h.TPM.transport
	h.TPM.transport = failingTransport{}
	t.Cleanup(func() { h.TPM.transport = original })

	props, err := h.TPM.FixedProperties()
	require.NoError(t, err, "FixedProperties is best-effort and must not fail as a whole")
	require.NotNil(t, props)
	assert.Empty(t, props.Family, "no property may be populated from a dead transport")
	assert.Empty(t, props.Manufacturer)
	assert.Zero(t, props.InputBufferMax)
}

// discardLogger returns a logger that writes nowhere, for accessors that take
// one purely to report per-index failures.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

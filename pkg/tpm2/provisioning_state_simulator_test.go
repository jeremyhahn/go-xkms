//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger returns a logger that discards output, matching the pattern
// newSimHarness uses.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// enrollPlatformSRKForTest creates the Platform SRK on an already-provisioned
// harness, mirroring what firstboot enrollment does in production. newSimHarness
// stops after EK/SSRK/IAK (see Provision), so State tests that need to observe
// PlatformSRKPresent call this explicitly.
func enrollPlatformSRKForTest(t *testing.T, h *simHarness) {
	t.Helper()

	if _, err := h.TPM.PlatformSRKAttributes(); err == nil {
		return
	}
	psrkAttrs, err := PlatformSRKAttributesFromConfig(h.TPM.config)
	require.NoError(t, err)
	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	psrkAttrs.Parent = ekAttrs
	require.NoError(t, h.TPM.CreateSRK(psrkAttrs))
}

// TestState_FreshTPM proves State reports every handle absent and every
// hierarchy auth unset on a TPM that has never been provisioned.
func TestState_FreshTPM(t *testing.T) {
	sim, err := OpenSimulator()
	require.NoError(t, err, "the in-process TPM simulator must open; build with -tags tpm_simulator")
	t.Cleanup(func() { _ = sim.Close() })

	config := newSimConfig()
	params := &Params{
		Logger:    testLogger(),
		Config:    config,
		Transport: sim.Transport(),
	}

	tpmIface, err := NewTPM2(params)
	require.ErrorIs(t, err, ErrNotInitialized, "a never-provisioned simulator must report ErrNotInitialized")
	require.NotNil(t, tpmIface)
	t.Cleanup(func() { _ = tpmIface.Close() })

	state, err := tpmIface.State()
	require.NoError(t, err)

	assert.False(t, state.OwnerAuthSet)
	assert.False(t, state.EndorsementAuthSet)
	assert.False(t, state.LockoutAuthSet)
	assert.False(t, state.EKPresent)
	assert.False(t, state.SSRKPresent)
	assert.False(t, state.IAKPresent)
	assert.False(t, state.IDevIDPresent)
	assert.False(t, state.PlatformSRKPresent)
	assert.False(t, state.PlatformSRKPolicyCurrent)
}

// TestState_ProvisionedTPM proves State reports the handles Provision(nil)
// creates (EK, SSRK, IAK) as present, the Platform SRK -- which Provision
// deliberately does not create -- as absent, and every hierarchy auth still
// unset, since Provision(nil) leaves hierarchy auth empty.
func TestState_ProvisionedTPM(t *testing.T) {
	h := newSimHarness(t, nil)

	state, err := h.TPM.State()
	require.NoError(t, err)

	assert.False(t, state.OwnerAuthSet)
	assert.False(t, state.EndorsementAuthSet)
	assert.False(t, state.LockoutAuthSet)
	assert.True(t, state.EKPresent)
	assert.True(t, state.SSRKPresent)
	assert.True(t, state.IAKPresent)
	assert.False(t, state.PlatformSRKPresent)
	assert.False(t, state.PlatformSRKPolicyCurrent)
}

// TestState_PlatformSRKPolicyCurrent proves State reports the Platform SRK
// present and its policy current once it has been enrolled under this
// device's live platform policy digest.
func TestState_PlatformSRKPolicyCurrent(t *testing.T) {
	h := newSimHarness(t, nil)
	enrollPlatformSRKForTest(t, h)

	state, err := h.TPM.State()
	require.NoError(t, err)

	assert.True(t, state.PlatformSRKPresent)
	assert.True(t, state.PlatformSRKPolicyCurrent)
}

// TestState_OwnedTPM proves State reports all three hierarchy auth bits set
// once Provision has been run with a non-empty Security Officer PIN.
func TestState_OwnedTPM(t *testing.T) {
	sim, err := OpenSimulator()
	require.NoError(t, err, "the in-process TPM simulator must open; build with -tags tpm_simulator")
	t.Cleanup(func() { _ = sim.Close() })

	config := newSimConfig()
	params := &Params{
		Logger:    testLogger(),
		Config:    config,
		Transport: sim.Transport(),
	}

	tpmIface, err := NewTPM2(params)
	require.ErrorIs(t, err, ErrNotInitialized)
	t.Cleanup(func() { _ = tpmIface.Close() })

	require.NoError(t, tpmIface.Provision(mustPassword([]byte("owned-tpm-so-pin"))))

	state, err := tpmIface.State()
	require.NoError(t, err)

	assert.True(t, state.OwnerAuthSet)
	assert.True(t, state.EndorsementAuthSet)
	assert.True(t, state.LockoutAuthSet)
	assert.True(t, state.EKPresent)
	assert.True(t, state.SSRKPresent)
	assert.True(t, state.IAKPresent)
}

// TestState_TransportError proves State returns ErrProvisioningStateRead,
// not a bare transport error, when computing the live platform policy
// digest (needed to answer PlatformSRKPolicyCurrent) fails at the
// transport. FixedProperties itself never fails -- every property query it
// makes degrades to a zero value on error -- so this is the one real
// failure surface State has, and it is reached only once a Platform SRK is
// present. createFaultyTransport (see
// auth_session_leak_transport_fault_simulator_test.go) lets every other
// command through unmodified.
func TestState_TransportError(t *testing.T) {
	h := newSimHarness(t, nil)
	enrollPlatformSRKForTest(t, h)

	h.TPM.transport = &createFaultyTransport{inner: h.TPM.transport, failCC: tpm2.TPMCCPCRRead}

	_, err := h.TPM.State()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProvisioningStateRead)
}

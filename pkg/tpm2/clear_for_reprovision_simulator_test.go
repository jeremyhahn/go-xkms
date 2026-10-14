//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"errors"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freshSimTPM opens a fresh simulator and TPM2 without provisioning it,
// returning the concrete *TPM2 so tests can reach unexported state (setting
// hierarchy auth on individual hierarchies, swapping the transport).
func freshSimTPM(t *testing.T) *TPM2 {
	t.Helper()

	sim, err := OpenSimulator()
	require.NoError(t, err, "the in-process TPM simulator must open; build with -tags tpm_simulator")
	t.Cleanup(func() { _ = sim.Close() })

	config := newSimConfig(t)
	params := &Params{
		Logger:    testLogger(),
		Config:    config,
		Transport: sim.Transport(),
	}

	tpmIface, err := NewTPM2(params)
	require.ErrorIs(t, err, ErrNotInitialized)
	require.NotNil(t, tpmIface)
	t.Cleanup(func() { _ = tpmIface.Close() })

	tpmImpl, ok := tpmIface.(*TPM2)
	require.True(t, ok)
	return tpmImpl
}

// TestClearForReprovision_LockoutPath proves the fast path: a fresh
// simulator's lockout auth is still empty, so TPM2_Clear via LOCKOUT
// succeeds immediately and no reboot is needed.
func TestClearForReprovision_LockoutPath(t *testing.T) {
	tpmImpl := freshSimTPM(t)

	rebootRequired, err := tpmImpl.ClearForReprovision()
	require.NoError(t, err)
	assert.False(t, rebootRequired)
}

// TestClearForReprovision_PlatformPath proves the second path: once lockout
// auth is set (refusing the first path), TPM2_Clear via PLATFORM -- whose
// auth this test never touches -- still succeeds, and the clear it performs
// resets the lockout auth it fell back past.
func TestClearForReprovision_PlatformPath(t *testing.T) {
	tpmImpl := freshSimTPM(t)

	lockoutHierarchy := tpm2.TPMRHLockout
	require.NoError(t, tpmImpl.SetHierarchyAuth(nil, mustPassword(t, []byte("lockout-pin")), &lockoutHierarchy))

	rebootRequired, err := tpmImpl.ClearForReprovision()
	require.NoError(t, err)
	assert.False(t, rebootRequired)

	state, err := tpmImpl.State()
	require.NoError(t, err)
	assert.False(t, state.LockoutAuthSet, "TPM2_Clear via PLATFORM must reset the LOCKOUT auth it fell back past")
}

// TestClearForReprovision_PPIPath proves the third path: once both LOCKOUT
// and PLATFORM auths are set, ClearForReprovision falls through to PPI
// ForceClear and reports rebootRequired=true. The PPI write itself goes
// through the injectable seam, never the host's sysfs.
func TestClearForReprovision_PPIPath(t *testing.T) {
	tpmImpl := freshSimTPM(t)

	lockoutHierarchy := tpm2.TPMRHLockout
	require.NoError(t, tpmImpl.SetHierarchyAuth(nil, mustPassword(t, []byte("lockout-pin")), &lockoutHierarchy))
	platformHierarchy := tpm2.TPMRHPlatform
	require.NoError(t, tpmImpl.SetHierarchyAuth(nil, mustPassword(t, []byte("platform-pin")), &platformHierarchy))

	var gotPath string
	var gotData []byte
	orig := ppiRequestWriter
	ppiRequestWriter = func(path string, data []byte, perm os.FileMode) error {
		gotPath = path
		gotData = append([]byte(nil), data...)
		return nil
	}
	t.Cleanup(func() { ppiRequestWriter = orig })

	rebootRequired, err := tpmImpl.ClearForReprovision()
	require.NoError(t, err)
	assert.True(t, rebootRequired, "the PPI path must report that a reboot is required")
	assert.Contains(t, gotPath, "/ppi/request")
	assert.Equal(t, []byte("5"), gotData)
}

// TestClearForReprovision_PPIPathFails proves that when even PPI ForceClear
// is refused, ClearForReprovision surfaces that failure directly (typed as
// ErrForceClear) rather than reporting success.
func TestClearForReprovision_PPIPathFails(t *testing.T) {
	tpmImpl := freshSimTPM(t)

	lockoutHierarchy := tpm2.TPMRHLockout
	require.NoError(t, tpmImpl.SetHierarchyAuth(nil, mustPassword(t, []byte("lockout-pin")), &lockoutHierarchy))
	platformHierarchy := tpm2.TPMRHPlatform
	require.NoError(t, tpmImpl.SetHierarchyAuth(nil, mustPassword(t, []byte("platform-pin")), &platformHierarchy))

	orig := ppiRequestWriter
	ppiRequestWriter = func(path string, data []byte, perm os.FileMode) error {
		return errors.New("injected PPI write failure")
	}
	t.Cleanup(func() { ppiRequestWriter = orig })

	rebootRequired, err := tpmImpl.ClearForReprovision()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrForceClear)
	assert.False(t, rebootRequired)
}

// TestForceClear_Success proves ForceClear writes PPI request code 5 through
// the injectable seam, never touching the host's sysfs in a test.
func TestForceClear_Success(t *testing.T) {
	h := newSimHarness(t, nil)

	var gotPath string
	var gotData []byte
	orig := ppiRequestWriter
	ppiRequestWriter = func(path string, data []byte, perm os.FileMode) error {
		gotPath = path
		gotData = append([]byte(nil), data...)
		return nil
	}
	t.Cleanup(func() { ppiRequestWriter = orig })

	require.NoError(t, h.TPM.ForceClear())
	assert.Contains(t, gotPath, "/ppi/request")
	assert.Equal(t, []byte("5"), gotData)
}

// TestForceClear_SeamError proves ForceClear returns the typed
// ErrForceClear, not a bare seam error, when the PPI write fails.
func TestForceClear_SeamError(t *testing.T) {
	h := newSimHarness(t, nil)

	orig := ppiRequestWriter
	ppiRequestWriter = func(path string, data []byte, perm os.FileMode) error {
		return errors.New("injected PPI write failure")
	}
	t.Cleanup(func() { ppiRequestWriter = orig })

	err := h.TPM.ForceClear()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrForceClear)
}

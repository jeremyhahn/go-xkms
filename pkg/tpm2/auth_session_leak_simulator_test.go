// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

// This file guards a ship-blocking regression found by live Playwright
// testing against real TPM hardware: after roughly 20-90 PIN unlock
// operations, PIN verification permanently stopped working until the process
// was killed. The escalating failure sequence was:
//
//  1. "write /dev/tpmrm0: device or resource busy"
//  2. "tpm2: key not found at handle for auth change"
//  3. "TPM_RC_SESSION_MEMORY: out of memory for session contexts"
//
// Root cause: TPM2.VerifyAuth (auth.go) built its auth-probe session with
// TPM2.HMAC, which returns a one-shot session that go-tpm's tpm2/reflect.go
// only guarantees to clean up in two situations: (a) the TPM itself
// auto-flushes it on success, because ContinueSession=false was sent with
// the command, or (b) go-tpm's own CleanupFailure runs when the response
// header carries a TPM error. Every other return path inside
// tpm2/reflect.go's execute() -- a command/parameter marshalling error, or a
// transport-level fault such as the "device or resource busy" write error
// above -- occurs strictly between the session's TPM2_StartAuthSession
// (issued lazily by the session's Init, itself triggered mid-Execute) and
// that cleanup check, so it returns with the just-started session handle
// never flushed. Each such event permanently consumes one of the TPM's
// limited session-context slots (TCG TPM 2.0 Part 1, Section 19) until the
// resource manager's client connection (the process's fd on /dev/tpmrm0) is
// closed -- which is exactly why killing and restarting the process was the
// only recovery.
//
// The fix makes VerifyAuth own the session's entire lifecycle explicitly: it
// starts a real HMACSession up front (so the handle is known to xkms before
// the probe command ever runs) and flushes it in a defer that always runs,
// regardless of which path the probe command takes to return. The tests
// below prove the session count observed directly from the TPM
// (TPM2_GetCapability / TPM_CAP_HANDLES, exactly what `tpm2_getcap
// handles-loaded-session` and `handles-saved-session` report) stays flat
// across hundreds of VerifyAuth calls, with correct PINs, wrong PINs, and a
// mix of both.

// loadedSessionCount returns the number of sessions the TPM currently holds
// loaded in RAM (TPM_HT_HMAC_SESSION, handle range 0x02000000-0x02FFFFFF).
// This is the TPM-side ground truth for "handles-loaded-session" in
// tpm2_getcap; both HMAC and policy sessions occupy this range once started.
func loadedSessionCount(t *testing.T, tr transport.TPM) int {
	t.Helper()
	resp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTHMACSession) << 24,
		PropertyCount: 255,
	}.Execute(tr)
	require.NoError(t, err)
	handles, err := resp.CapabilityData.Data.Handles()
	require.NoError(t, err)
	return len(handles.Handle)
}

// savedSessionCount returns the number of sessions the TPM has context-saved
// out of RAM under memory pressure (TPM_HT_POLICY_SESSION, handle range
// 0x03000000-0x03FFFFFF) -- the TPM-side ground truth for
// "handles-saved-session" in tpm2_getcap. A leak can present in either range
// depending on how close the TPM is to exhausting TPM_RC_SESSION_MEMORY, so
// tests assert on both.
func savedSessionCount(t *testing.T, tr transport.TPM) int {
	t.Helper()
	resp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTPolicySession) << 24,
		PropertyCount: 255,
	}.Execute(tr)
	require.NoError(t, err)
	handles, err := resp.CapabilityData.Data.Handles()
	require.NoError(t, err)
	return len(handles.Handle)
}

// verifyAuthSessionFixture provisions a simulator TPM plus an SRK ("srk"
// under the EK, auth "srk-pass") using the same createSim/createKey fixture
// shared by the rest of this package's simulator tests.
func verifyAuthSessionFixture(t *testing.T) (tpmImpl *TPM2, handle tpm2.TPMHandle, goodAuth, badAuth []byte) {
	t.Helper()
	_, tpm := createSim(t, false)
	t.Cleanup(func() { _ = tpm.Close() })

	srkAttrs := createKey(t, tpm, false).Parent
	tpmImpl = tpm.(*TPM2)
	return tpmImpl, srkAttrs.TPMAttributes.Handle, []byte("srk-pass"), []byte("wrong-pin")
}

// TestVerifyAuth_NoSessionLeak_CorrectPIN_Simulator proves 200 consecutive
// VerifyAuth calls with the CORRECT auth value leave the TPM's loaded and
// saved session counts exactly where they started -- no session survives a
// successful auth-probe.
func TestVerifyAuth_NoSessionLeak_CorrectPIN_Simulator(t *testing.T) {
	tpmImpl, handle, goodAuth, _ := verifyAuthSessionFixture(t)

	loadedBefore := loadedSessionCount(t, tpmImpl.transport)
	savedBefore := savedSessionCount(t, tpmImpl.transport)

	const iterations = 200
	for i := 0; i < iterations; i++ {
		require.NoError(t, tpmImpl.VerifyAuth(handle, goodAuth), "iteration %d", i)
	}

	require.Equal(t, loadedBefore, loadedSessionCount(t, tpmImpl.transport),
		"loaded session count must not grow across %d correct-PIN VerifyAuth calls", iterations)
	require.Equal(t, savedBefore, savedSessionCount(t, tpmImpl.transport),
		"saved session count must not grow across %d correct-PIN VerifyAuth calls", iterations)
}

// TestVerifyAuth_NoSessionLeak_WrongPIN_Simulator proves 200 consecutive
// VerifyAuth calls with an INCORRECT auth value -- the failure path that
// depended on go-tpm's CleanupFailure before this fix -- also leave session
// counts flat, since the session is now flushed by our own defer rather than
// relying on that path alone.
func TestVerifyAuth_NoSessionLeak_WrongPIN_Simulator(t *testing.T) {
	tpmImpl, handle, _, badAuth := verifyAuthSessionFixture(t)

	loadedBefore := loadedSessionCount(t, tpmImpl.transport)
	savedBefore := savedSessionCount(t, tpmImpl.transport)

	const iterations = 200
	for i := 0; i < iterations; i++ {
		err := tpmImpl.VerifyAuth(handle, badAuth)
		require.ErrorIs(t, err, ErrAuthFailed, "iteration %d", i)
	}

	require.Equal(t, loadedBefore, loadedSessionCount(t, tpmImpl.transport),
		"loaded session count must not grow across %d wrong-PIN VerifyAuth calls", iterations)
	require.Equal(t, savedBefore, savedSessionCount(t, tpmImpl.transport),
		"saved session count must not grow across %d wrong-PIN VerifyAuth calls", iterations)
}

// TestVerifyAuth_NoSessionLeak_MixedPIN_Simulator interleaves correct and
// wrong PINs (the realistic shape of live usage: a user mistypes, retries,
// eventually succeeds) across 200 calls and proves session counts still stay
// flat regardless of which path each individual call takes.
//
// The SRK fixture has dictionary-attack protection enabled (NoDA cleared, see
// createKey), so a wrong PIN increments the TPM's real DA counter exactly as
// it must on production hardware; left unchecked, a handful of interleaved
// wrong PINs would trip TPM_RC_LOCKOUT and start rejecting the CORRECT PIN
// too, which is a distinct, already-covered behavior (see
// TestSwtpm_WrongPIN_IncrementsDA) and not what this test is isolating. Each
// wrong-PIN iteration resets the DA counter immediately afterward so the
// only variable under test here is session accounting, not lockout state.
func TestVerifyAuth_NoSessionLeak_MixedPIN_Simulator(t *testing.T) {
	tpmImpl, handle, goodAuth, badAuth := verifyAuthSessionFixture(t)

	loadedBefore := loadedSessionCount(t, tpmImpl.transport)
	savedBefore := savedSessionCount(t, tpmImpl.transport)

	const iterations = 200
	for i := 0; i < iterations; i++ {
		if i%3 == 0 {
			err := tpmImpl.VerifyAuth(handle, badAuth)
			require.ErrorIs(t, err, ErrAuthFailed, "iteration %d", i)
			require.NoError(t, tpmImpl.DictionaryAttackLockoutReset(nil), "DA reset after iteration %d", i)
			continue
		}
		require.NoError(t, tpmImpl.VerifyAuth(handle, goodAuth), "iteration %d", i)
	}

	require.Equal(t, loadedBefore, loadedSessionCount(t, tpmImpl.transport),
		"loaded session count must not grow across %d mixed-PIN VerifyAuth calls", iterations)
	require.Equal(t, savedBefore, savedSessionCount(t, tpmImpl.transport),
		"saved session count must not grow across %d mixed-PIN VerifyAuth calls", iterations)
}

// TestVerifyAuth_NoSessionLeak_NotFoundHandle_Simulator proves a VerifyAuth
// call against a handle that does not exist -- which returns before any
// session is ever started -- does not touch the session count at all. This
// is the error-handling counterpart to the three tests above: it guards the
// early-return path (ReadHandle failure) rather than the auth-probe path.
func TestVerifyAuth_NoSessionLeak_NotFoundHandle_Simulator(t *testing.T) {
	tpmImpl, _, goodAuth, _ := verifyAuthSessionFixture(t)

	loadedBefore := loadedSessionCount(t, tpmImpl.transport)
	savedBefore := savedSessionCount(t, tpmImpl.transport)

	const bogusHandle = tpm2.TPMHandle(0x81FFFFFE)
	err := tpmImpl.VerifyAuth(bogusHandle, goodAuth)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrAuthChangeKeyNotFound)

	require.Equal(t, loadedBefore, loadedSessionCount(t, tpmImpl.transport))
	require.Equal(t, savedBefore, savedSessionCount(t, tpmImpl.transport))
}

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
	"encoding/binary"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

// This file reproduces the exact leak mechanism identified during triage of
// the live-testing report, rather than just its symptom. Plain wrong-PIN
// loops against the simulator (auth_session_leak_simulator_test.go) do NOT
// leak even the pre-fix code, because go-tpm's CleanupFailure (tpm2/sessions.go)
// correctly flushes a one-shot session whenever the TPM itself returns an
// error response (e.g. ordinary TPM_RC_BAD_AUTH). The reported error
// sequence started with "write /dev/tpmrm0: device or resource busy" -- a
// transport-level fault, not a TPM response -- and go-tpm's execute()
// (tpm2/reflect.go) returns immediately on a transport error, BEFORE it ever
// reaches the code path that would call CleanupFailure. Any session already
// started at that point (via the auth session's lazy TPM2_StartAuthSession)
// is abandoned with no cleanup whatsoever.
//
// createFaultyTransport below reproduces precisely that shape: it lets every
// command through to the real simulator transport except TPM2_Create, whose
// send it fails with a synthetic "device or resource busy" error -- so the
// auth-probe's TPM2_StartAuthSession always succeeds (the session is real
// and loaded) but the probe command itself always fails at the transport,
// exactly as reported.

// tpmCCOffset is the byte offset of the command code within a marshalled TPM
// command: 2 bytes tag + 4 bytes commandSize, then the 4-byte TPM_CC.
const tpmCCOffset = 6

// createFaultyTransport wraps a real transport.TPM and fails every send of
// the given command code with a synthetic transport error, while passing all
// other commands through unmodified. It is used to simulate a transient
// "device or resource busy" fault landing on exactly one command in an
// otherwise healthy session lifecycle.
type createFaultyTransport struct {
	inner      transport.TPM
	failCC     tpm2.TPMCC
	failCount  int
	totalCalls int
}

func (f *createFaultyTransport) Send(input []byte) ([]byte, error) {
	f.totalCalls++
	if len(input) >= tpmCCOffset+4 {
		cc := tpm2.TPMCC(binary.BigEndian.Uint32(input[tpmCCOffset : tpmCCOffset+4]))
		if cc == f.failCC {
			f.failCount++
			return nil, errors.New("write /dev/tpmrm0: device or resource busy")
		}
	}
	return f.inner.Send(input)
}

// TestVerifyAuth_NoSessionLeak_TransportFaultOnProbeCommand_Simulator proves
// the fix holds even when the auth-probe TPM2_Create command itself fails at
// the transport layer AFTER its auth session has already been started on the
// TPM -- the specific fault sequence from the live report. Before the fix
// (TPM2.HMAC one-shot session, cleaned up only via go-tpm's CleanupFailure on
// a TPM response error) this exact fault leaked one session per call,
// growing monotonically; VerifyAuth now owns the session in an unconditional
// defer, so the session count must stay exactly flat across 50 faulting
// calls.
func TestVerifyAuth_NoSessionLeak_TransportFaultOnProbeCommand_Simulator(t *testing.T) {
	tpmImpl, handle, goodAuth, _ := verifyAuthSessionFixture(t)

	faulty := &createFaultyTransport{inner: tpmImpl.transport, failCC: tpm2.TPMCCCreate}
	tpmImpl.transport = faulty

	loadedBefore := loadedSessionCount(t, faulty.inner)
	savedBefore := savedSessionCount(t, faulty.inner)

	const iterations = 50
	for i := 0; i < iterations; i++ {
		err := tpmImpl.VerifyAuth(handle, goodAuth)
		require.Error(t, err, "iteration %d: injected transport fault must surface as an error", i)
		require.ErrorIs(t, err, ErrAuthProbeRejected,
			"iteration %d: a transport fault is not an auth failure and must not be misreported as one", i)
	}
	require.Equal(t, iterations, faulty.failCount, "the injected fault must have fired on every iteration")

	require.Equal(t, loadedBefore, loadedSessionCount(t, faulty.inner),
		"loaded session count must not grow across %d calls that fault on the probe command send", iterations)
	require.Equal(t, savedBefore, savedSessionCount(t, faulty.inner),
		"saved session count must not grow across %d calls that fault on the probe command send", iterations)
}

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

// TestNonceSession_UsableAgainstEndorsementHierarchy proves NonceSession
// returns a policy session that actually authorizes TPM_RH_ENDORSEMENT
// operations -- not merely a session object that constructs without error.
// It is exercised here by using the session to read back the EK's public
// area via an authorized command shape (TPM2_PolicySecret against the
// endorsement hierarchy is also the auth path TPM2_ActivateCredential and
// EK-certificate provisioning use), and by closing it cleanly leaves no
// session behind on the TPM.
func TestNonceSession_UsableAgainstEndorsementHierarchy(t *testing.T) {
	h := newSimHarness(t, nil)

	loadedBefore := loadedSessionCount(t, h.TPM.transport)

	session, closer, err := h.TPM.NonceSession(nil)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotNil(t, closer)

	require.Greater(t, loadedSessionCount(t, h.TPM.transport), loadedBefore,
		"precondition: NonceSession must leave a session loaded on the TPM while open")

	// TPM2_PolicyGetDigest is authorization-free and simply proves the
	// session handle the caller got back is a live, TPM-recognized session
	// (a session lost or misconstructed would not resolve to a valid handle).
	digestRsp, err := tpm2.PolicyGetDigest{PolicySession: session.Handle()}.Execute(h.TPM.transport)
	require.NoError(t, err)
	require.NotEmpty(t, digestRsp.PolicyDigest.Buffer,
		"a session that satisfied PolicySecret against the endorsement hierarchy must carry a non-empty policy digest")

	require.NoError(t, closer())
	require.Equal(t, loadedBefore, loadedSessionCount(t, h.TPM.transport),
		"closing the session must not leave it loaded on the TPM")
}

// TestNonceSession_PolicySecretFailure_ClosesSessionAndPropagatesError
// covers the second TPM round trip: TPM2_PolicySecret failing after the
// session was already started on the TPM. NonceSession must both report the
// error AND clean up the now-useless session it already opened, rather than
// leaking it -- the same leaked-session failure mode auth_session_leak's
// tests pin for VerifyAuth.
func TestNonceSession_PolicySecretFailure_ClosesSessionAndPropagatesError(t *testing.T) {
	h := newSimHarness(t, nil)

	loadedBefore := loadedSessionCount(t, h.TPM.transport)
	savedBefore := savedSessionCount(t, h.TPM.transport)

	faulty := &createFaultyTransport{inner: h.TPM.transport, failCC: tpm2.TPMCCPolicySecret}
	h.TPM.transport = faulty

	session, closer, err := h.TPM.NonceSession(nil)
	require.Error(t, err)
	require.Nil(t, session)
	require.Nil(t, closer)
	require.Equal(t, 1, faulty.failCount, "precondition: PolicySecret must have been attempted and failed")

	// Verify cleanup against the real transport: the faulty wrapper only
	// blocks PolicySecret, so the FlushContext the error path issues went
	// through to the simulator and must be reflected in its session counts.
	require.Equal(t, loadedBefore, loadedSessionCount(t, faulty.inner),
		"a PolicySecret failure must not leave the session loaded on the TPM")
	require.Equal(t, savedBefore, savedSessionCount(t, faulty.inner),
		"a PolicySecret failure must not leave the session context-saved on the TPM")
}

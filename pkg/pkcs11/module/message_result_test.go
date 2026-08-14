// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package module

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signingModuleWithRealCrypto returns a module whose backend performs genuine
// ECDSA, together with a logged-in session and a signing key.
//
// It reuses the transport built for the concurrency tests rather than the
// package's canned mock, which answers every Sign with the same constant bytes.
// Against that mock a test comparing two signatures cannot fail, so it would
// certify the defect it was written to catch.
func signingModuleWithRealCrypto(t *testing.T) (*Module, SessionHandle, ObjectHandle) {
	t.Helper()

	m, _ := newConcurrentModule(t)

	session, err := openLoggedInSession(m)
	require.NoError(t, err, "opening a logged-in session must succeed")

	_, priv, _, err := generateP256Pair(m, session, "message-result-key")
	require.NoError(t, err, "generating the signing key must succeed")

	return m, session, priv
}

// TestSignMessage_SecondMessageIsNotTheFirstSignature is the regression test
// for a defect that returned silently wrong cryptographic output.
//
// C_SignMessage delegates to the same code as C_Sign, which caches its result
// so the PKCS#11 v3.2 §5.2 two-call sequence can answer a length query without
// signing twice. C_Sign clears that cache by calling FinishOperation once it has
// copied the signature out; C_SignMessage did not clear it at all. Because
// C_MessageSignInit stays live across many messages until C_MessageSignFinal,
// every subsequent message hit the cache and received the FIRST message's
// signature under CKR_OK.
//
// Nothing detected it: the operation succeeded, the signature was well formed,
// and it verified — against the wrong data. Only comparing two different
// messages' signatures reveals it.
func TestSignMessage_SecondMessageIsNotTheFirstSignature(t *testing.T) {
	// The package's canned mock transport returns a constant signature, so it
	// cannot tell a replayed cache from a fresh signature — the assertion below
	// would hold no matter what the module did. This transport performs real
	// ECDSA over the data it is given, which is the only way the test can fail
	// for the right reason.
	m, session, keyHandle := signingModuleWithRealCrypto(t)

	rv := m.MessageSignInit(session, &Mechanism{Type: CKM_ECDSA}, keyHandle)
	require.Equal(t, CKR_OK, rv, "MessageSignInit must succeed")

	first, rv := m.SignMessage(session, []byte("the first message"))
	require.Equal(t, CKR_OK, rv, "signing the first message must succeed")
	require.NotEmpty(t, first, "a signature must not be empty")

	// The C shim calls this once it has copied the signature out. Without it
	// the cached result below is returned again.
	rv = m.ReleaseOperationResult(session, OperationSign)
	require.Equal(t, CKR_OK, rv)

	second, rv := m.SignMessage(session, []byte("an entirely different message"))
	require.Equal(t, CKR_OK, rv, "signing the second message must succeed")
	require.NotEmpty(t, second)

	assert.False(t, bytes.Equal(first, second),
		"a second message must produce its own signature; identical bytes mean the "+
			"cached result of the first message was replayed")
}

// TestSignMessage_ReplaysCachedResultUntilReleased pins the other half of the
// contract, so a future fix cannot simply drop the cache and break the two-call
// convention instead.
//
// PKCS#11 v3.2 §5.2 requires that a length query and a CKR_BUFFER_TOO_SMALL
// leave the operation intact and the same bytes available. The Go API has no
// NULL-buffer concept, so it caches the result and the caller at the C boundary
// decides when the output has been collected. Until it says so, repeating the
// call must return the identical signature rather than sign again — signing
// again would consume a second nonce for the mechanisms that use one.
func TestSignMessage_ReplaysCachedResultUntilReleased(t *testing.T) {
	m, session, keyHandle := signingModuleWithRealCrypto(t)

	rv := m.MessageSignInit(session, &Mechanism{Type: CKM_ECDSA}, keyHandle)
	require.Equal(t, CKR_OK, rv)

	data := []byte("a message signed once and collected twice")

	first, rv := m.SignMessage(session, data)
	require.Equal(t, CKR_OK, rv)
	require.NotEmpty(t, first)

	// Simulates the application retrying after a length query, with no
	// intervening release.
	replay, rv := m.SignMessage(session, data)
	require.Equal(t, CKR_OK, rv)

	assert.True(t, bytes.Equal(first, replay),
		"a repeated call before the result is released must return the cached "+
			"signature, so a length query does not sign twice")
}

// TestReleaseOperationResult_KeepsOperationInitialized proves the release drops
// the cached bytes without ending the operation.
//
// FinishOperation would also clear the cache, but it terminates the operation,
// which is correct for C_Sign and wrong for C_SignMessage: the message-based
// functions run under an Init that survives until their C_Message*Final. Using
// the wrong one here would turn a stale-signature bug into a
// CKR_OPERATION_NOT_INITIALIZED on the second message.
func TestReleaseOperationResult_KeepsOperationInitialized(t *testing.T) {
	m, session, keyHandle := signingModuleWithRealCrypto(t)

	rv := m.MessageSignInit(session, &Mechanism{Type: CKM_ECDSA}, keyHandle)
	require.Equal(t, CKR_OK, rv)

	_, rv = m.SignMessage(session, []byte("first"))
	require.Equal(t, CKR_OK, rv)

	rv = m.ReleaseOperationResult(session, OperationSign)
	require.Equal(t, CKR_OK, rv)

	// The operation must still be usable, which is what distinguishes this from
	// FinishOperation.
	_, rv = m.SignMessage(session, []byte("second"))
	assert.Equal(t, CKR_OK, rv,
		"the signing operation must survive a release; CKR_OPERATION_NOT_INITIALIZED "+
			"here would mean the release finalized it")
}

// TestReleaseOperationResult_Rejected covers the error paths.
func TestReleaseOperationResult_Rejected(t *testing.T) {
	t.Run("fails when not initialized", func(t *testing.T) {
		m := createTestModule(t)

		rv := m.ReleaseOperationResult(1, OperationSign)
		assert.Equal(t, CKR_CRYPTOKI_NOT_INITIALIZED, rv)
	})

	t.Run("fails with an invalid session", func(t *testing.T) {
		m := initializeTestModule(t)
		defer m.Finalize()

		rv := m.ReleaseOperationResult(9999, OperationSign)
		assert.Equal(t, CKR_SESSION_HANDLE_INVALID, rv)
	})

	t.Run("is a no-op when no operation is active", func(t *testing.T) {
		m, _ := newConcurrentModule(t)

		session, err := openLoggedInSession(m)
		require.NoError(t, err)

		// Releasing a result that was never produced must not fail: the C shim
		// calls this on every successful collection and cannot know whether the
		// operation cached anything.
		rv := m.ReleaseOperationResult(session, OperationSign)
		assert.Equal(t, CKR_OK, rv)
	})
}

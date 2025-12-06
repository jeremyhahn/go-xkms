//go:build integration && tpm2

package integration

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHMACBasic tests basic unauthenticated HMAC session creation
func TestHMACBasic(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	t.Run("WithNilAuth", func(t *testing.T) {
		session := tpmInstance.HMAC(nil)
		require.NotNil(t, session)

		// Verify session handle is valid (non-zero)
		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
	})

	t.Run("WithEmptyAuth", func(t *testing.T) {
		session := tpmInstance.HMAC([]byte{})
		require.NotNil(t, session)

		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
	})

	t.Run("WithPassword", func(t *testing.T) {
		session := tpmInstance.HMAC([]byte("test-password"))
		require.NotNil(t, session)

		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
	})
}

// TestHMACSession tests authenticated HMAC session with proper cleanup
func TestHMACSession(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	t.Run("WithNilAuth", func(t *testing.T) {
		session, closer, err := tpmInstance.HMACSession(nil)
		require.NoError(t, err)
		require.NotNil(t, session)
		require.NotNil(t, closer)
		defer func() {
			assert.NoError(t, closer())
		}()

		// Verify session is valid
		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
		assert.NotNil(t, session.NonceTPM())
	})

	t.Run("WithEmptyAuth", func(t *testing.T) {
		session, closer, err := tpmInstance.HMACSession([]byte{})
		require.NoError(t, err)
		require.NotNil(t, session)
		require.NotNil(t, closer)
		defer func() {
			assert.NoError(t, closer())
		}()

		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
	})

	t.Run("WithPassword", func(t *testing.T) {
		session, closer, err := tpmInstance.HMACSession([]byte("test-auth"))
		require.NoError(t, err)
		require.NotNil(t, session)
		require.NotNil(t, closer)
		defer func() {
			assert.NoError(t, closer())
		}()

		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
		assert.NotNil(t, session.NonceTPM())
	})

	t.Run("MultipleSequential", func(t *testing.T) {
		// Create and close first session
		session1, closer1, err := tpmInstance.HMACSession([]byte("session-1"))
		require.NoError(t, err)
		require.NotNil(t, session1)
		handle1 := session1.Handle()
		t.Logf("First session handle: 0x%x", handle1)
		assert.NoError(t, closer1())

		// Create and close second session
		session2, closer2, err := tpmInstance.HMACSession([]byte("session-2"))
		require.NoError(t, err)
		require.NotNil(t, session2)
		handle2 := session2.Handle()
		t.Logf("Second session handle: 0x%x", handle2)
		assert.NoError(t, closer2())

		// Note: TPM may reuse the same handle after it's flushed
		// The key test is that both sessions can be created and closed successfully
		t.Logf("Successfully created and closed %d sequential sessions", 2)
	})
}

// TestHMACSaltedSession tests salted HMAC sessions with encryption
func TestHMACSaltedSession(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	// Get EK attributes for salted session
	ekAttrs, err := tpmInstance.EKAttributes()
	require.NoError(t, err)
	require.NotNil(t, ekAttrs)
	require.NotNil(t, ekAttrs.TPMAttributes)

	ekHandle := ekAttrs.TPMAttributes.Handle
	ekPublic := ekAttrs.TPMAttributes.Public

	t.Run("WithNilAuth", func(t *testing.T) {
		session, closer, err := tpmInstance.HMACSaltedSession(ekHandle, ekPublic, nil)
		require.NoError(t, err)
		require.NotNil(t, session)
		require.NotNil(t, closer)
		defer func() {
			assert.NoError(t, closer())
		}()

		// Verify session is valid
		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
		assert.NotNil(t, session.NonceTPM())
	})

	t.Run("WithPassword", func(t *testing.T) {
		session, closer, err := tpmInstance.HMACSaltedSession(
			ekHandle,
			ekPublic,
			[]byte("salted-auth"))
		require.NoError(t, err)
		require.NotNil(t, session)
		require.NotNil(t, closer)
		defer func() {
			assert.NoError(t, closer())
		}()

		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
		assert.NotNil(t, session.NonceTPM())
	})

	t.Run("MultipleSequential", func(t *testing.T) {
		// Create and close first salted session
		session1, closer1, err := tpmInstance.HMACSaltedSession(
			ekHandle,
			ekPublic,
			[]byte("salted-1"))
		require.NoError(t, err)
		require.NotNil(t, session1)
		handle1 := session1.Handle()
		t.Logf("First salted session handle: 0x%x", handle1)
		assert.NoError(t, closer1())

		// Create and close second salted session
		session2, closer2, err := tpmInstance.HMACSaltedSession(
			ekHandle,
			ekPublic,
			[]byte("salted-2"))
		require.NoError(t, err)
		require.NotNil(t, session2)
		handle2 := session2.Handle()
		t.Logf("Second salted session handle: 0x%x", handle2)
		assert.NoError(t, closer2())

		// Note: TPM may reuse the same handle after it's flushed
		t.Logf("Successfully created and closed %d sequential salted sessions", 2)
	})
}

// TestNonceSession tests nonce-based policy sessions
func TestNonceSession(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	t.Run("WithNilPassword", func(t *testing.T) {
		session, closer, err := tpmInstance.NonceSession(nil)
		require.NoError(t, err)
		require.NotNil(t, session)
		require.NotNil(t, closer)
		defer func() {
			assert.NoError(t, closer())
		}()

		// Verify session is valid
		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
		assert.NotNil(t, session.NonceTPM())
	})

	t.Run("WithClearPassword", func(t *testing.T) {
		// Note: NonceSession uses PolicySecret with Endorsement hierarchy
		// The password must match the Endorsement hierarchy auth (empty by default)
		password := types.NewClearPassword([]byte("")) // Empty password matches TPM default
		session, closer, err := tpmInstance.NonceSession(password)
		require.NoError(t, err)
		require.NotNil(t, session)
		require.NotNil(t, closer)
		defer func() {
			assert.NoError(t, closer())
		}()

		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
		assert.NotNil(t, session.NonceTPM())
	})

	t.Run("MultipleSequential", func(t *testing.T) {
		// Create and close first nonce session
		session1, closer1, err := tpmInstance.NonceSession(nil)
		require.NoError(t, err)
		require.NotNil(t, session1)
		handle1 := session1.Handle()
		t.Logf("First nonce session handle: 0x%x", handle1)
		assert.NoError(t, closer1())

		// Create and close second nonce session
		session2, closer2, err := tpmInstance.NonceSession(nil)
		require.NoError(t, err)
		require.NotNil(t, session2)
		handle2 := session2.Handle()
		t.Logf("Second nonce session handle: 0x%x", handle2)
		assert.NoError(t, closer2())

		// Note: TPM may reuse the same handle after it's flushed
		t.Logf("Successfully created and closed %d sequential nonce sessions", 2)
	})
}

// TestPlatformPolicySession tests platform PCR policy sessions
func TestPlatformPolicySession(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	t.Run("BasicCreation", func(t *testing.T) {
		session, closer, err := tpmInstance.PlatformPolicySession()
		require.NoError(t, err)
		require.NotNil(t, session)
		require.NotNil(t, closer)
		defer func() {
			assert.NoError(t, closer())
		}()

		// Verify session is valid
		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
		assert.NotNil(t, session.NonceTPM())
	})

	t.Run("PolicyDigestSet", func(t *testing.T) {
		session, closer, err := tpmInstance.PlatformPolicySession()
		require.NoError(t, err)
		require.NotNil(t, session)
		defer func() {
			assert.NoError(t, closer())
		}()

		// Verify policy digest is set
		policyDigest := tpmInstance.PlatformPolicyDigest()
		assert.NotNil(t, policyDigest.Buffer)
		assert.NotEmpty(t, policyDigest.Buffer)
	})

	t.Run("MultipleSequential", func(t *testing.T) {
		// Create and close first policy session
		session1, closer1, err := tpmInstance.PlatformPolicySession()
		require.NoError(t, err)
		require.NotNil(t, session1)
		handle1 := session1.Handle()
		t.Logf("First policy session handle: 0x%x", handle1)
		assert.NoError(t, closer1())

		// Create and close second policy session
		session2, closer2, err := tpmInstance.PlatformPolicySession()
		require.NoError(t, err)
		require.NotNil(t, session2)
		handle2 := session2.Handle()
		t.Logf("Second policy session handle: 0x%x", handle2)
		assert.NoError(t, closer2())

		// Note: TPM may reuse the same handle after it's flushed
		t.Logf("Successfully created and closed %d sequential policy sessions", 2)
	})

	t.Run("ErrorHandlingCleanup", func(t *testing.T) {
		// Create a session and verify cleanup happens even if we don't use it
		session, closer, err := tpmInstance.PlatformPolicySession()
		require.NoError(t, err)
		require.NotNil(t, session)

		// Immediately close without using
		assert.NoError(t, closer())

		// Should be able to create another session after cleanup
		session2, closer2, err := tpmInstance.PlatformPolicySession()
		require.NoError(t, err)
		require.NotNil(t, session2)
		defer func() {
			assert.NoError(t, closer2())
		}()
	})
}

// TestSessionResourceManagement tests proper resource management with multiple sessions
func TestSessionResourceManagement(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	t.Run("TwoSimultaneousSessions", func(t *testing.T) {
		// Create first session
		session1, closer1, err := tpmInstance.HMACSession([]byte("session-1"))
		require.NoError(t, err)
		require.NotNil(t, session1)
		defer func() {
			assert.NoError(t, closer1())
		}()

		// Create second session (TPM has at least 3 session slots)
		session2, closer2, err := tpmInstance.HMACSession([]byte("session-2"))
		require.NoError(t, err)
		require.NotNil(t, session2)
		defer func() {
			assert.NoError(t, closer2())
		}()

		// Verify both sessions have different handles
		assert.NotEqual(t, session1.Handle(), session2.Handle())
	})

	t.Run("SequentialSessionReuse", func(t *testing.T) {
		handles := make([]tpm2.TPMHandle, 5)

		// Create and close 5 sessions sequentially
		for i := 0; i < 5; i++ {
			session, closer, err := tpmInstance.HMACSession([]byte("sequential"))
			require.NoError(t, err)
			require.NotNil(t, session)

			handles[i] = session.Handle()

			// Close immediately
			assert.NoError(t, closer())
		}

		// Verify we could create all sessions (handles may be reused)
		for _, handle := range handles {
			assert.NotEqual(t, tpm2.TPMHandle(0), handle)
		}
	})

	t.Run("MixedSessionTypes", func(t *testing.T) {
		// Create HMAC session
		hmacSession, hmacCloser, err := tpmInstance.HMACSession([]byte("hmac"))
		require.NoError(t, err)
		require.NotNil(t, hmacSession)
		defer func() {
			assert.NoError(t, hmacCloser())
		}()

		// Create nonce session
		nonceSession, nonceCloser, err := tpmInstance.NonceSession(nil)
		require.NoError(t, err)
		require.NotNil(t, nonceSession)
		defer func() {
			assert.NoError(t, nonceCloser())
		}()

		// Verify different handles
		assert.NotEqual(t, hmacSession.Handle(), nonceSession.Handle())
	})
}

// TestSessionCleanupOnError tests that sessions are properly cleaned up on errors
func TestSessionCleanupOnError(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	t.Run("CleanupAfterUse", func(t *testing.T) {
		session, closer, err := tpmInstance.HMACSession([]byte("test"))
		require.NoError(t, err)
		require.NotNil(t, session)
		require.NotNil(t, closer)

		handle := session.Handle()
		assert.NotEqual(t, tpm2.TPMHandle(0), handle)

		// Close the session
		assert.NoError(t, closer())

		// Note: Calling closer() again will fail with TPM_RC_HANDLE because
		// the session handle is already flushed. This is expected TPM behavior.
		// Applications should track whether they've called closer() already.
		err = closer()
		if err != nil {
			t.Logf("Second close returned expected error: %v", err)
		}
	})

	t.Run("DeferredCleanup", func(t *testing.T) {
		func() {
			session, closer, err := tpmInstance.HMACSession([]byte("deferred"))
			require.NoError(t, err)
			require.NotNil(t, session)
			defer func() {
				assert.NoError(t, closer())
			}()

			// Use session (just verify it exists)
			assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())

			// Session will be cleaned up by defer
		}()

		// After function returns, should be able to create new session
		session, closer, err := tpmInstance.HMACSession([]byte("after-defer"))
		require.NoError(t, err)
		require.NotNil(t, session)
		defer func() {
			assert.NoError(t, closer())
		}()
	})
}

// TestCreateSession tests the high-level CreateSession method
func TestCreateSession(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	// Need to provision TPM first to have key attributes
	if err := tpmInstance.Provision(nil); err != nil {
		// If already provisioned or other error, continue anyway
		t.Logf("Provision returned: %v (continuing anyway)", err)
	}

	t.Run("WithValidKeyAttributes", func(t *testing.T) {
		// Get EK attributes
		ekAttrs, err := tpmInstance.EKAttributes()
		require.NoError(t, err)
		require.NotNil(t, ekAttrs)

		// Create session for EK
		session, closer, err := tpmInstance.CreateSession(ekAttrs)
		require.NoError(t, err)
		require.NotNil(t, session)
		defer func() {
			if closer != nil {
				assert.NoError(t, closer())
			}
		}()

		// Verify session is valid
		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
	})

	t.Run("WithSRKAttributes", func(t *testing.T) {
		// Get SRK attributes
		srkAttrs, err := tpmInstance.SSRKAttributes()
		require.NoError(t, err)
		require.NotNil(t, srkAttrs)

		// Create session for SRK
		session, closer, err := tpmInstance.CreateSession(srkAttrs)
		require.NoError(t, err)
		require.NotNil(t, session)
		defer func() {
			if closer != nil {
				assert.NoError(t, closer())
			}
		}()

		// Verify session is valid
		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
	})
}

// TestCreateKeySession tests the CreateKeySession method
func TestCreateKeySession(t *testing.T) {
	tpmInstance, cleanup := setupTPM2(t)
	defer cleanup()

	// Provision TPM
	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v (continuing anyway)", err)
	}

	t.Run("WithEKAttributes", func(t *testing.T) {
		ekAttrs, err := tpmInstance.EKAttributes()
		require.NoError(t, err)
		require.NotNil(t, ekAttrs)

		session, closer, err := tpmInstance.CreateKeySession(ekAttrs)
		require.NoError(t, err)
		require.NotNil(t, session)
		defer func() {
			if closer != nil {
				assert.NoError(t, closer())
			}
		}()

		// Verify session is valid
		assert.NotEqual(t, tpm2.TPMHandle(0), session.Handle())
	})

	t.Run("WithNilPassword", func(t *testing.T) {
		// Create minimal key attributes without password
		keyAttrs := &types.KeyAttributes{
			CN:             "test-key",
			PlatformPolicy: false,
			Password:       nil,
		}

		session, closer, err := tpmInstance.CreateKeySession(keyAttrs)
		require.NoError(t, err)
		require.NotNil(t, session)
		defer func() {
			if closer != nil {
				assert.NoError(t, closer())
			}
		}()

		// Should return password auth session with nil auth
		assert.NotNil(t, session)
	})
}

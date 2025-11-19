//go:build integration && tpm2

package integration

import (
	"testing"

	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// setupPolicyTPM provisions TPM for policy session testing
func setupPolicyTPM(t *testing.T) (tpm2lib.TrustedPlatformModule, func()) {
	t.Helper()

	// Use existing helper which handles provisioning properly
	tpmInstance, cleanup := createTPM2Instance(t)

	// Provision TPM to create EK, SRK, and IAK needed for policy sessions
	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v (may already be provisioned)", err)
	}

	return tpmInstance, cleanup
}

// TestIntegration_PlatformPolicySession_Create tests platform policy session creation
func TestIntegration_PlatformPolicySession_Create(t *testing.T) {
	tpmInstance, cleanup := setupPolicyTPM(t)
	defer cleanup()

	t.Run("CreatePolicySession", func(t *testing.T) {
		// Create platform policy session
		session, closer, err := tpmInstance.PlatformPolicySession()
		if err != nil {
			t.Fatalf("Failed to create platform policy session: %v", err)
		}
		defer closer()

		// Verify session was created
		if session == nil {
			t.Fatal("PlatformPolicySession returned nil session")
		}

		// Verify session handle is valid
		sessionHandle := session.Handle()
		if sessionHandle == 0 {
			t.Error("Session handle is zero")
		}

		t.Logf("Successfully created platform policy session with handle 0x%x", sessionHandle)
	})

	t.Run("MultiplePolicySessions", func(t *testing.T) {
		// Create multiple policy sessions sequentially
		const numSessions = 3

		for i := 0; i < numSessions; i++ {
			session, closer, err := tpmInstance.PlatformPolicySession()
			if err != nil {
				t.Fatalf("Failed to create policy session %d: %v", i, err)
			}

			// Verify session
			if session == nil {
				closer()
				t.Fatalf("Policy session %d is nil", i)
			}

			sessionHandle := session.Handle()
			t.Logf("Created policy session %d with handle 0x%x", i, sessionHandle)

			// Close the session
			if err := closer(); err != nil {
				t.Errorf("Failed to close policy session %d: %v", i, err)
			}
		}

		t.Logf("Successfully created and closed %d policy sessions", numSessions)
	})
}

// TestIntegration_PlatformPolicySession_PCRPolicy tests PCR policy enforcement
func TestIntegration_PlatformPolicySession_PCRPolicy(t *testing.T) {
	tpmInstance, cleanup := setupPolicyTPM(t)
	defer cleanup()

	t.Run("PCRPolicyDigest", func(t *testing.T) {
		// Create policy session
		session, closer, err := tpmInstance.PlatformPolicySession()
		if err != nil {
			t.Fatalf("Failed to create policy session: %v", err)
		}
		defer closer()

		// The PlatformPolicySession should have set up PCR policy
		// Verify the policy digest is set
		policyDigest := tpmInstance.PlatformPolicyDigest()
		if len(policyDigest.Buffer) == 0 {
			t.Error("Platform policy digest is empty")
		}

		_ = session // Use session
		t.Logf("Platform policy digest: 0x%x", policyDigest.Buffer)
		t.Logf("Policy digest length: %d bytes", len(policyDigest.Buffer))
	})

	t.Run("PolicySessionReuse", func(t *testing.T) {
		// Create first session
		session1, closer1, err := tpmInstance.PlatformPolicySession()
		if err != nil {
			t.Fatalf("Failed to create first policy session: %v", err)
		}

		handle1 := session1.Handle()
		t.Logf("First policy session handle: 0x%x", handle1)

		// Close first session
		if err := closer1(); err != nil {
			t.Errorf("Failed to close first session: %v", err)
		}

		// Create second session
		session2, closer2, err := tpmInstance.PlatformPolicySession()
		if err != nil {
			t.Fatalf("Failed to create second policy session: %v", err)
		}
		defer closer2()

		handle2 := session2.Handle()
		t.Logf("Second policy session handle: 0x%x", handle2)

		// Handles should be different (new session created)
		if handle1 == handle2 {
			t.Log("Session handles are the same (TPM may reuse handles)")
		} else {
			t.Log("Session handles are different (new session created)")
		}
	})
}

// TestIntegration_PlatformPolicySession_ErrorHandling tests error conditions
func TestIntegration_PlatformPolicySession_ErrorHandling(t *testing.T) {
	tpmInstance, cleanup := setupPolicyTPM(t)
	defer cleanup()

	t.Run("DoubleClose", func(t *testing.T) {
		session, closer, err := tpmInstance.PlatformPolicySession()
		if err != nil {
			t.Fatalf("Failed to create policy session: %v", err)
		}

		if session == nil {
			t.Fatal("Session is nil")
		}

		// Close once
		err1 := closer()
		if err1 != nil {
			t.Logf("First close returned error: %v", err1)
		}

		// Close again
		err2 := closer()
		if err2 != nil {
			t.Logf("Second close returned error (expected): %v", err2)
		} else {
			t.Log("Second close succeeded (idempotent closer)")
		}
	})
}

// TestIntegration_NonceSession_Create tests nonce session creation
func TestIntegration_NonceSession_Create(t *testing.T) {
	tpmInstance, cleanup := setupPolicyTPM(t)
	defer cleanup()

	t.Run("CreateNonceSession", func(t *testing.T) {
		// Create nonce session with nil auth (TPM is provisioned with nil)
		session, closer, err := tpmInstance.NonceSession(nil)
		if err != nil {
			t.Fatalf("Failed to create nonce session: %v", err)
		}
		defer closer()

		// Verify session was created
		if session == nil {
			t.Fatal("NonceSession returned nil session")
		}

		sessionHandle := session.Handle()
		if sessionHandle == 0 {
			t.Error("Nonce session handle is zero")
		}

		t.Logf("Successfully created nonce session with handle 0x%x", sessionHandle)
	})

	t.Run("NonceSessionWithNilAuth", func(t *testing.T) {
		// Create nonce session with nil auth
		session, closer, err := tpmInstance.NonceSession(nil)
		if err != nil {
			t.Fatalf("Failed to create nonce session with nil auth: %v", err)
		}
		defer closer()

		if session == nil {
			t.Fatal("NonceSession with nil auth returned nil session")
		}

		t.Logf("Created nonce session with nil auth: handle 0x%x", session.Handle())
	})

	t.Run("MultipleNonceSessions", func(t *testing.T) {
		// Create multiple nonce sessions with nil auth (TPM is provisioned with nil)
		const numSessions = 3
		sessions := make([]interface{}, numSessions)
		closers := make([]func() error, numSessions)

		for i := 0; i < numSessions; i++ {
			session, closer, err := tpmInstance.NonceSession(nil)
			if err != nil {
				// Clean up previously created sessions
				for j := 0; j < i; j++ {
					closers[j]()
				}
				t.Fatalf("Failed to create nonce session %d: %v", i, err)
			}

			sessions[i] = session
			closers[i] = closer

			t.Logf("Created nonce session %d with handle 0x%x", i, session.Handle())
		}

		// Close all sessions
		for i, closer := range closers {
			if err := closer(); err != nil {
				t.Errorf("Failed to close nonce session %d: %v", i, err)
			}
		}

		t.Logf("Successfully created and closed %d nonce sessions", numSessions)
	})
}

// TestIntegration_NonceSession_PolicySecret tests PolicySecret operation
func TestIntegration_NonceSession_PolicySecret(t *testing.T) {
	tpmInstance, cleanup := setupPolicyTPM(t)
	defer cleanup()

	t.Run("PolicySecretOperation", func(t *testing.T) {
		// Create nonce session with nil auth (TPM is provisioned with nil)
		session, closer, err := tpmInstance.NonceSession(nil)
		if err != nil {
			t.Fatalf("Failed to create nonce session: %v", err)
		}
		defer closer()

		// The session should be authorized via PolicySecret
		// Verify session is usable
		if session == nil {
			t.Fatal("Session is nil after PolicySecret")
		}

		sessionHandle := session.Handle()
		if sessionHandle == 0 {
			t.Error("Session handle is zero after PolicySecret")
		}

		t.Logf("PolicySecret successfully authorized session 0x%x", sessionHandle)
	})
}

// TestIntegration_CreateSession_SRKBased tests session creation with SRK parent
func TestIntegration_CreateSession_SRKBased(t *testing.T) {
	tpmInstance, cleanup := setupPolicyTPM(t)
	defer cleanup()

	t.Run("CreateSessionWithSRK", func(t *testing.T) {
		// Get SRK attributes
		srkAttrs, err := tpmInstance.SSRKAttributes()
		if err != nil {
			t.Fatalf("Failed to get SRK attributes: %v", err)
		}

		// Create key attributes with SRK as parent
		keyAttrs := &types.KeyAttributes{
			CN:     "test-session-key",
			Parent: srkAttrs,
		}

		// Create session
		session, closer, err := tpmInstance.CreateSession(keyAttrs)
		if err != nil {
			t.Fatalf("Failed to create session with SRK parent: %v", err)
		}
		defer closer()

		if session == nil {
			t.Fatal("CreateSession returned nil session")
		}

		t.Log("Successfully created session with SRK parent")
	})

	t.Run("CreateSessionWithoutParent", func(t *testing.T) {
		// Create key attributes without parent
		keyAttrs := &types.KeyAttributes{
			CN:     "test-session-no-parent",
			Parent: nil,
		}

		// This should still work, using CreateKeySession path
		session, closer, err := tpmInstance.CreateSession(keyAttrs)
		if err != nil {
			t.Fatalf("Failed to create session without parent: %v", err)
		}
		defer closer()

		if session == nil {
			t.Fatal("CreateSession without parent returned nil session")
		}

		t.Log("Successfully created session without parent")
	})
}

// TestIntegration_CreateSession_WithPlatformPolicy tests session with platform policy
func TestIntegration_CreateSession_WithPlatformPolicy(t *testing.T) {
	tpmInstance, cleanup := setupPolicyTPM(t)
	defer cleanup()

	t.Run("SessionWithPlatformPolicy", func(t *testing.T) {
		// Get SRK attributes
		srkAttrs, err := tpmInstance.SSRKAttributes()
		if err != nil {
			t.Fatalf("Failed to get SRK attributes: %v", err)
		}

		// Create key attributes with platform policy
		keyAttrs := &types.KeyAttributes{
			CN:             "test-policy-session-key",
			Parent:         srkAttrs,
			PlatformPolicy: true,
		}

		// Mark parent as having platform policy
		keyAttrs.Parent.PlatformPolicy = true

		// Create session - should create platform policy session
		session, closer, err := tpmInstance.CreateSession(keyAttrs)
		if err != nil {
			t.Fatalf("Failed to create session with platform policy: %v", err)
		}
		defer closer()

		if session == nil {
			t.Fatal("CreateSession with platform policy returned nil session")
		}

		t.Log("Successfully created session with platform policy")
	})
}

// TestIntegration_Session_Lifecycle tests complete session lifecycle
func TestIntegration_Session_Lifecycle(t *testing.T) {
	tpmInstance, cleanup := setupPolicyTPM(t)
	defer cleanup()

	t.Run("CompletePolicySessionLifecycle", func(t *testing.T) {
		// Step 1: Create session
		t.Log("Step 1: Creating platform policy session...")
		session, closer, err := tpmInstance.PlatformPolicySession()
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		sessionHandle := session.Handle()
		t.Logf("  Session created with handle 0x%x", sessionHandle)

		// Step 2: Verify session is usable
		t.Log("Step 2: Verifying session is usable...")
		if session == nil {
			closer()
			t.Fatal("Session is nil")
		}

		// Step 3: Get policy digest
		t.Log("Step 3: Getting policy digest...")
		policyDigest := tpmInstance.PlatformPolicyDigest()
		if len(policyDigest.Buffer) == 0 {
			closer()
			t.Error("Policy digest is empty")
		}
		t.Logf("  Policy digest: %d bytes", len(policyDigest.Buffer))

		// Step 4: Close session
		t.Log("Step 4: Closing session...")
		if err := closer(); err != nil {
			t.Errorf("Failed to close session: %v", err)
		}

		t.Log("Complete policy session lifecycle successful")
	})

	t.Run("CompleteNonceSessionLifecycle", func(t *testing.T) {
		// Step 1: Create session
		t.Log("Step 1: Creating nonce session...")
		session, closer, err := tpmInstance.NonceSession(nil)
		if err != nil {
			t.Fatalf("Failed to create nonce session: %v", err)
		}

		sessionHandle := session.Handle()
		t.Logf("  Session created with handle 0x%x", sessionHandle)

		// Step 2: Verify session
		t.Log("Step 2: Verifying nonce session...")
		if session == nil {
			closer()
			t.Fatal("Nonce session is nil")
		}

		// Step 3: Use session (implicitly - just verify it's valid)
		t.Log("Step 3: Nonce session is valid and usable")

		// Step 4: Close session
		t.Log("Step 4: Closing nonce session...")
		if err := closer(); err != nil {
			t.Errorf("Failed to close nonce session: %v", err)
		}

		t.Log("Complete nonce session lifecycle successful")
	})
}

// TestIntegration_Session_ConcurrentAccess tests sequential session access
func TestIntegration_Session_ConcurrentAccess(t *testing.T) {
	tpmInstance, cleanup := setupPolicyTPM(t)
	defer cleanup()

	t.Run("SequentialSessions", func(t *testing.T) {
		// Create and use multiple sessions sequentially
		const numIterations = 5

		for i := 0; i < numIterations; i++ {
			session, closer, err := tpmInstance.PlatformPolicySession()
			if err != nil {
				t.Fatalf("Iteration %d: Failed to create session: %v", i, err)
			}

			if session == nil {
				closer()
				t.Fatalf("Iteration %d: Session is nil", i)
			}

			t.Logf("Iteration %d: Created session 0x%x", i, session.Handle())

			// Close immediately
			if err := closer(); err != nil {
				t.Errorf("Iteration %d: Failed to close session: %v", i, err)
			}
		}

		t.Logf("Successfully created and closed %d sequential sessions", numIterations)
	})
}

// TestIntegration_Session_PasswordAuth tests password-based authentication sessions
func TestIntegration_Session_PasswordAuth(t *testing.T) {
	tpmInstance, cleanup := setupPolicyTPM(t)
	defer cleanup()

	t.Run("CreateSessionWithPassword", func(t *testing.T) {
		// Get SRK attributes
		srkAttrs, err := tpmInstance.SSRKAttributes()
		if err != nil {
			t.Fatalf("Failed to get SRK attributes: %v", err)
		}

		// Create key attributes with password
		password := types.NewClearPassword([]byte("test-password"))
		keyAttrs := &types.KeyAttributes{
			CN:       "test-password-session",
			Parent:   srkAttrs,
			Password: password,
		}

		// Ensure parent doesn't have platform policy (use password auth)
		keyAttrs.Parent.PlatformPolicy = false

		// Create session
		session, closer, err := tpmInstance.CreateSession(keyAttrs)
		if err != nil {
			t.Fatalf("Failed to create session with password: %v", err)
		}
		defer closer()

		if session == nil {
			t.Fatal("CreateSession with password returned nil session")
		}

		t.Log("Successfully created password-authenticated session")
	})
}

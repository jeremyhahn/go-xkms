package module

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file pins the rule that a session object lives no longer than the
// sessions of the application that created it (PKCS#11 v3.2 §4.1.3).
//
// C_CloseSession honours it one session at a time. C_CloseAllSessions and
// C_Finalize close sessions in bulk, and must not be a way for objects to
// outlive every session that could own them: AccessContext.CanAccess scopes
// object visibility to the token rather than to the creating session, so an
// orphaned session object stays fully readable by the next session opened on
// the slot.

// lifecycleFindAll returns every object the session can see. The empty template
// matches everything visible, which is what makes this a leak check rather than
// a lookup of something already known to exist.
func lifecycleFindAll(t *testing.T, m *Module, session SessionHandle) []ObjectHandle {
	t.Helper()

	require.Equal(t, CKR_OK, m.FindObjectsInit(session, nil))
	found, rv := m.FindObjects(session, 1000)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.FindObjectsFinal(session))

	return found
}

func lifecycleContains(handles []ObjectHandle, want ObjectHandle) bool {
	for _, h := range handles {
		if h == want {
			return true
		}
	}
	return false
}

// createPublicSessionKey creates a public AES session object: public so that it
// survives a logout and stays resolvable to a later session, which is what makes
// a leak observable rather than merely hidden behind an access check.
func createPublicSessionKey(t *testing.T, m *Module, session SessionHandle) ObjectHandle {
	t.Helper()

	handle, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_TOKEN, false),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	})
	require.Equal(t, CKR_OK, rv)

	return handle
}

func TestCloseAllSessionsDestroysSessionObjects(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)
	handle := createPublicSessionKey(t, m, session)

	// The precondition matters: without it a guard that made the object
	// unfindable for any reason at all would satisfy the assertion below.
	require.True(t, lifecycleContains(lifecycleFindAll(t, m, session), handle),
		"the session object must be findable while its session is open")

	require.Equal(t, CKR_OK, m.CloseAllSessions(0))

	next := loginAsNormalUser(t, m)
	assert.False(t, lifecycleContains(lifecycleFindAll(t, m, next), handle),
		"a session object must not outlive every session that could own it")
}

func TestCloseSessionDestroysSessionObjects(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)
	handle := createPublicSessionKey(t, m, session)

	require.True(t, lifecycleContains(lifecycleFindAll(t, m, session), handle))

	require.Equal(t, CKR_OK, m.CloseSession(session))

	next := loginAsNormalUser(t, m)
	assert.False(t, lifecycleContains(lifecycleFindAll(t, m, next), handle),
		"C_CloseSession must destroy the objects its session owned")
}

// TestCloseAllSessionsKeepsTokenObjects is the other half of the rule: a token
// object is not a session object and must survive. Without it, "destroy
// everything on close" would pass every assertion above while quietly deleting
// the application's persistent keys.
func TestCloseAllSessionsKeepsTokenObjects(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	session := loginAsNormalUser(t, m)

	handle, rv := m.CreateObject(session, []Attribute{
		NewUint32Attribute(CKA_CLASS, uint32(CKO_SECRET_KEY)),
		NewUint32Attribute(CKA_KEY_TYPE, uint32(CKK_AES)),
		NewBoolAttribute(CKA_TOKEN, true),
		NewBoolAttribute(CKA_PRIVATE, false),
		NewAttribute(CKA_VALUE, make([]byte, 32)),
	})
	require.Equal(t, CKR_OK, rv)

	require.Equal(t, CKR_OK, m.CloseAllSessions(0))

	next := loginAsNormalUser(t, m)
	assert.True(t, lifecycleContains(lifecycleFindAll(t, m, next), handle),
		"a token object must survive C_CloseAllSessions")
}

// TestSessionHandlesAreUniqueAcrossSlots pins CK_SESSION_HANDLE as one flat
// namespace for the whole library (PKCS#11 v3.2 §3.3).
//
// Each SessionManager used to own a private HandleTable whose counter started at
// 1, so slot 0's first session and slot 1's first session were both handle 1.
// Module.findSession and Module.CloseSession resolve a handle by ranging over
// the managers and taking the first hit, and Go randomizes map iteration -- so
// C_CloseSession(1) closed whichever the range reached first and C_Login(1)
// authenticated against an arbitrary token.
//
// Only slot 0 is ever provisioned today, which is the sole reason this was never
// observable. The managers are driven directly here so the invariant is asserted
// on its own terms rather than on that remaining true.
func TestSessionHandlesAreUniqueAcrossSlots(t *testing.T) {
	shared := NewHandleTable[*Session]()
	slotZero := NewSessionManagerWithTable(0, 0, shared)
	slotOne := NewSessionManagerWithTable(1, 0, shared)

	zeroHandle, err := slotZero.OpenSession(CKF_SERIAL_SESSION | CKF_RW_SESSION)
	require.NoError(t, err)
	oneHandle, err := slotOne.OpenSession(CKF_SERIAL_SESSION | CKF_RW_SESSION)
	require.NoError(t, err)

	assert.NotEqual(t, zeroHandle, oneHandle,
		"two slots must never issue the same CK_SESSION_HANDLE")

	t.Run("a manager does not resolve another slot's handle", func(t *testing.T) {
		_, err := slotZero.GetSession(oneHandle)
		require.Error(t, err, "slot 0 must not answer for a session on slot 1")

		_, err = slotOne.GetSession(zeroHandle)
		require.Error(t, err)
	})

	t.Run("a manager does not close another slot's session", func(t *testing.T) {
		require.Error(t, slotZero.CloseSession(oneHandle),
			"closing a foreign session would silently destroy another token's state")

		// The victim is still there.
		_, err := slotOne.GetSession(oneHandle)
		require.NoError(t, err)
	})

	t.Run("closing all of one slot leaves the other intact", func(t *testing.T) {
		slotZero.CloseAllSessions()

		_, err := slotZero.GetSession(zeroHandle)
		require.Error(t, err, "slot 0's own session must be gone")

		_, err = slotOne.GetSession(oneHandle)
		require.NoError(t, err,
			"slot 1's session must survive: the table is shared, so Clear() would "+
				"have taken it too")
	})
}

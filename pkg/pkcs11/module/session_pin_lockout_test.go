package module

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// This file pins the PIN lockout to the token rather than to the library
// instance.
//
// PKCS#11 v3.2 §3.2 describes CKF_USER_PIN_LOCKED as a property of the token,
// and §5.6.8 gives C_Login CKR_PIN_LOCKED to report it. A budget held only in
// process memory satisfies neither: C_Finalize followed by C_Initialize hands
// back a fresh three attempts, so MaxPINAttempts bounds nothing and a
// four-digit PIN falls to an offline-speed online attack.

// newPersistentTestModule returns an initialized module backed by the given
// store.
//
// A second module over the same backend is how these tests model a restart. It
// is the accurate model for what is being tested: the new module builds fresh
// SessionManagers with zeroed counters, so anything it reports about the lockout
// it must have read back from the store rather than carried in memory.
//
// The first module is deliberately not finalized first. C_Finalize closes the
// store, and the in-memory backend answers ErrClosed forever after, where a real
// restart reopens a file. Finalizing here would test the harness, not the token.
func newPersistentTestModule(t *testing.T, backend storage.Backend) *Module {
	t.Helper()

	ResetGlobalModule()
	m, err := New(WithClient(newMockClient()), WithConfig(DefaultConfig()), WithStorage(backend))
	require.NoError(t, err)
	require.Equal(t, CKR_OK, m.Initialize(nil))

	return m
}

// exhaustUserPINAttempts spends the whole lockout budget on wrong guesses and
// asserts the token ends up locked.
func exhaustUserPINAttempts(t *testing.T, m *Module, session SessionHandle) {
	t.Helper()

	var last CK_RV
	for i := 0; i < MaxPINAttempts; i++ {
		last = m.Login(session, CKU_USER, []byte("wrong-pin-9999"))
	}
	require.Equal(t, CKR_PIN_LOCKED, last, "the budget must run out within MaxPINAttempts")
}

func TestPINLockoutSurvivesFinalizeAndReinitialize(t *testing.T) {
	backend := storage.NewMemory()

	m := newPersistentTestModule(t, backend)
	session := loginAsNormalUser(t, m)
	require.Equal(t, CKR_OK, m.Logout(session))

	exhaustUserPINAttempts(t, m, session)

	// The restart. A fresh Module over the same store is what an attacker gets
	// for free by calling C_Finalize, and what an operator gets by restarting
	// the host application.
	restarted := newPersistentTestModule(t, backend)
	defer restarted.Finalize()

	next, rv := restarted.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	assert.Equal(t, CKR_PIN_LOCKED, restarted.Login(next, CKU_USER, []byte("wrong-pin-9999")),
		"a wrong PIN must not buy a fresh attempt across a restart")

	// The correct PIN is refused too: the token is locked, not merely counting.
	assert.Equal(t, CKR_PIN_LOCKED, restarted.Login(next, CKU_USER, []byte("user-pin-1234")),
		"the lockout must hold against the right PIN as well, or it is not a lockout")
}

// TestPINLockoutCounterResetsOnSuccess is the other half: a token that is not
// locked must not accumulate failures forever. Without this, a guard that
// simply never cleared the counter would satisfy every assertion above.
func TestPINLockoutCounterResetsOnSuccess(t *testing.T) {
	backend := storage.NewMemory()

	m := newPersistentTestModule(t, backend)
	session := loginAsNormalUser(t, m)
	require.Equal(t, CKR_OK, m.Logout(session))

	// One short of the limit, then a success.
	for i := 0; i < MaxPINAttempts-1; i++ {
		require.Equal(t, CKR_PIN_INCORRECT, m.Login(session, CKU_USER, []byte("wrong-pin-9999")))
	}
	require.Equal(t, CKR_OK, m.Login(session, CKU_USER, []byte("user-pin-1234")))
	require.Equal(t, CKR_OK, m.Logout(session))

	restarted := newPersistentTestModule(t, backend)
	defer restarted.Finalize()

	next, rv := restarted.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	assert.Equal(t, CKR_OK, restarted.Login(next, CKU_USER, []byte("user-pin-1234")),
		"a successful login clears the budget, and the cleared budget must persist too")
}

// TestLoginReportsUninitializedUserPIN pins the state C_InitToken leaves behind.
//
// C_InitToken resets the user PIN, and v3.2 §5.6.8 lists
// CKR_USER_PIN_NOT_INITIALIZED for exactly this. Answering CKR_PIN_INCORRECT
// instead is not merely a wrong code: it spends the lockout budget on a PIN that
// does not exist, so three logins lock a token before its user PIN was ever set,
// and C_InitPIN -- the call meant to set it -- is then locked out too.
func TestLoginReportsUninitializedUserPIN(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()

	require.Equal(t, CKR_OK, m.InitToken(0, []byte("so-pin-1234"), "Test Token"))

	session, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	for i := 0; i < MaxPINAttempts+1; i++ {
		assert.Equal(t, CKR_USER_PIN_NOT_INITIALIZED, m.Login(session, CKU_USER, []byte("1234")),
			"an unprovisioned user PIN must report its state, not consume the lockout budget")
	}

	// The SO can still provision it, which is the point: a token locked before
	// its PIN existed could never be provisioned at all.
	soSession, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(soSession, CKU_SO, []byte("so-pin-1234")))
	require.Equal(t, CKR_OK, m.InitPIN(soSession, []byte("user-pin-1234")))
	require.Equal(t, CKR_OK, m.Logout(soSession))

	require.Equal(t, CKR_OK, m.Login(session, CKU_USER, []byte("user-pin-1234")),
		"the freshly provisioned PIN must work on the first try")
}

// TestLoginDoesNotHoldTheSessionLockDuringPINDerivation pins that the Argon2id
// derivation runs with the session write lock RELEASED.
//
// verifyPin is deliberately expensive: it queues on a bounded admission gate and
// then runs a 64 MiB derivation. While that ran under m.mu, one caller's WRONG
// PIN stalled every C_OpenSession, C_CloseSession and C_Login on the token for
// its duration -- and an attacker needs no valid PIN to cause it, since a wrong
// guess costs exactly the same derivation.
//
// The lock is probed directly rather than timed. A timing assertion was tried
// first and was VACUOUS: it still passed with the derivation moved back under
// the lock, because a derivation is only tens of milliseconds and the scheduler
// hid the difference. TryLock answers the actual question -- is the lock free
// right now -- with no dependence on how fast anything runs.
func TestLoginDoesNotHoldTheSessionLockDuringPINDerivation(t *testing.T) {
	m := NewSessionManager(0, 0)
	m.SetUserPIN(mustHashPin("user-pin-1234"))

	handle, err := m.OpenSession(CKF_SERIAL_SESSION | CKF_RW_SESSION)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A wrong PIN costs the same derivation as a right one, which is what
		// makes this reachable without any credential.
		_ = m.Login(handle, CKU_USER, []byte("wrong-pin-9999"))
	}()

	// Let the goroutine reach the derivation before sampling.
	time.Sleep(2 * time.Millisecond)

	acquired := 0
	for {
		select {
		case <-done:
			// Sampling stops the moment the login returns, so nothing counted
			// here comes from the idle period afterwards.
			if acquired == 0 {
				t.Fatal("the session lock was never free while a PIN derivation was in " +
					"flight; Login still holds m.mu across verifyPin, so one wrong PIN " +
					"stalls every other session operation on the token")
			}
			return
		default:
		}

		if m.mu.TryLock() {
			acquired++
			m.mu.Unlock()
		}
		time.Sleep(time.Millisecond)
	}
}

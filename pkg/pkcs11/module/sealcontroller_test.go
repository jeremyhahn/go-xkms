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
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSealController records the passphrase it was unsealed with and its
// seal/unseal state, so a test can assert the module drives it correctly.
type fakeSealController struct {
	mu          sync.Mutex
	unsealed    bool
	unsealCalls int
	sealCalls   int
	rekeyCalls  int
	lastPass    []byte
	rekeyOld    []byte
	rekeyNew    []byte
	unsealErr   error
	sealErr     error
	rekeyErr    error
}

func (f *fakeSealController) Unseal(passphrase []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unsealCalls++
	if f.unsealErr != nil {
		return f.unsealErr
	}
	f.unsealed = true
	f.lastPass = append([]byte(nil), passphrase...)
	return nil
}

func (f *fakeSealController) Seal() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sealCalls++
	if f.sealErr != nil {
		return f.sealErr
	}
	f.unsealed = false
	return nil
}

func (f *fakeSealController) Rekey(oldPass, newPass []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rekeyCalls++
	if f.rekeyErr != nil {
		return f.rekeyErr
	}
	f.rekeyOld = append([]byte(nil), oldPass...)
	f.rekeyNew = append([]byte(nil), newPass...)
	return nil
}

func (f *fakeSealController) snapshot() (unsealed bool, unsealCalls, sealCalls int, lastPass []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.unsealed, f.unsealCalls, f.sealCalls, append([]byte(nil), f.lastPass...)
}

func (f *fakeSealController) rekeySnapshot() (calls int, old, new []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rekeyCalls, append([]byte(nil), f.rekeyOld...), append([]byte(nil), f.rekeyNew...)
}

// createTestModuleWithSeal builds an initialized module wired to the given seal
// controller, provisioning the token exactly as loginAsNormalUser does but
// without logging in (the tests drive login/logout themselves).
func createTestModuleWithSeal(t *testing.T, sc SealController) *Module {
	t.Helper()
	ResetGlobalModule()
	t.Cleanup(ResetGlobalModule)

	m, err := New(WithClient(newMockClient()), WithConfig(DefaultConfig()), WithSealController(sc))
	require.NoError(t, err)
	require.Equal(t, CKR_OK, m.Initialize(nil))

	require.Equal(t, CKR_OK, m.InitToken(0, []byte("so-pin-1234"), "Seal Token"))
	so, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(so, CKU_SO, []byte("so-pin-1234")))
	require.Equal(t, CKR_OK, m.InitPIN(so, []byte("user-pin-1234")))
	require.Equal(t, CKR_OK, m.Logout(so))
	require.Equal(t, CKR_OK, m.CloseSession(so))
	return m
}

// The SO login/logout used to provision the token must NOT unseal the private
// barrier: the SO administers the token and cannot see private objects, so
// sealing under the SO PIN would make the token unusable. Only the user login
// unseals.
func TestSealController_SOLoginDoesNotUnseal(t *testing.T) {
	sc := &fakeSealController{}
	m := createTestModuleWithSeal(t, sc)
	defer m.Finalize()

	_, unsealCalls, _, _ := sc.snapshot()
	assert.Zero(t, unsealCalls, "provisioning under the SO PIN must not unseal the private barrier")
}

func TestSealController_UserLoginUnseals_LogoutReseals(t *testing.T) {
	sc := &fakeSealController{}
	m := createTestModuleWithSeal(t, sc)
	defer m.Finalize()

	session, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	require.Equal(t, CKR_OK, m.Login(session, CKU_USER, []byte("user-pin-1234")))
	unsealed, unsealCalls, _, lastPass := sc.snapshot()
	assert.True(t, unsealed, "the user login must unseal the private barrier")
	assert.Equal(t, 1, unsealCalls)
	assert.Equal(t, []byte("user-pin-1234"), lastPass, "the barrier must be unsealed with the USER PIN")

	require.Equal(t, CKR_OK, m.Logout(session))
	unsealed, _, sealCalls, _ := sc.snapshot()
	assert.False(t, unsealed, "logout must reseal the private barrier")
	assert.GreaterOrEqual(t, sealCalls, 1)
}

func TestSealController_FinalizeReseals(t *testing.T) {
	sc := &fakeSealController{}
	m := createTestModuleWithSeal(t, sc)

	session, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(session, CKU_USER, []byte("user-pin-1234")))

	require.Equal(t, CKR_OK, m.Finalize())
	unsealed, _, sealCalls, _ := sc.snapshot()
	assert.False(t, unsealed, "finalize must reseal so no unsealed key survives")
	assert.GreaterOrEqual(t, sealCalls, 1)
}

// An unseal failure at login is an at-rest fault, not an auth one: the module
// must roll the login back and report CKR_DEVICE_ERROR rather than present an
// authenticated session that cannot reach its keys.
func TestSealController_UnsealFailureRollsBackLogin(t *testing.T) {
	sc := &fakeSealController{unsealErr: errors.New("barrier unavailable")}
	m := createTestModuleWithSeal(t, sc)
	defer m.Finalize()

	session, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)

	rv = m.Login(session, CKU_USER, []byte("user-pin-1234"))
	assert.Equal(t, CKR_DEVICE_ERROR, rv, "an unseal failure must fail the login")

	// The rollback logged the session out, so a fresh login is accepted (rather
	// than CKR_USER_ALREADY_LOGGED_IN), proving the failed login did not leave
	// the token authenticated.
	sc.mu.Lock()
	sc.unsealErr = nil
	sc.mu.Unlock()
	rv = m.Login(session, CKU_USER, []byte("user-pin-1234"))
	assert.Equal(t, CKR_OK, rv, "after rollback the token must accept a fresh login")
}

// A user C_SetPIN must rekey the private barrier from the old PIN to the new so
// the key material stays reachable after the change, and it must pass the exact
// old/new PINs through.
func TestSealController_UserSetPINRekeys(t *testing.T) {
	sc := &fakeSealController{}
	m := createTestModuleWithSeal(t, sc)
	defer m.Finalize()

	session, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(session, CKU_USER, []byte("user-pin-1234")))

	require.Equal(t, CKR_OK, m.SetPIN(session, []byte("user-pin-1234"), []byte("user-pin-5678")))

	calls, old, newp := sc.rekeySnapshot()
	assert.Equal(t, 1, calls, "a user PIN change must rekey the private barrier")
	assert.Equal(t, []byte("user-pin-1234"), old)
	assert.Equal(t, []byte("user-pin-5678"), newp)
}

// An SO C_SetPIN changes the SO PIN, which never keys the private barrier, so it
// must NOT rekey.
func TestSealController_SOSetPINDoesNotRekey(t *testing.T) {
	sc := &fakeSealController{}
	m := createTestModuleWithSeal(t, sc)
	defer m.Finalize()

	so, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(so, CKU_SO, []byte("so-pin-1234")))

	require.Equal(t, CKR_OK, m.SetPIN(so, []byte("so-pin-1234"), []byte("so-pin-9999")))

	calls, _, _ := sc.rekeySnapshot()
	assert.Zero(t, calls, "changing the SO PIN must not rekey the private barrier")
}

// A rekey failure must fail C_SetPIN and leave the PIN unchanged (the old PIN
// still logs in), so the token and barrier never diverge.
func TestSealController_RekeyFailureFailsSetPIN(t *testing.T) {
	sc := &fakeSealController{rekeyErr: errors.New("rekey unavailable")}
	m := createTestModuleWithSeal(t, sc)
	defer m.Finalize()

	session, rv := m.OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	require.Equal(t, CKR_OK, rv)
	require.Equal(t, CKR_OK, m.Login(session, CKU_USER, []byte("user-pin-1234")))

	rv = m.SetPIN(session, []byte("user-pin-1234"), []byte("user-pin-5678"))
	assert.Equal(t, CKR_DEVICE_ERROR, rv, "a rekey failure must fail C_SetPIN")

	// The PIN was not changed: logout, then the OLD pin still logs in.
	require.Equal(t, CKR_OK, m.Logout(session))
	sc.mu.Lock()
	sc.unsealErr = nil
	sc.mu.Unlock()
	assert.Equal(t, CKR_OK, m.Login(session, CKU_USER, []byte("user-pin-1234")),
		"a failed rekey must leave the old PIN valid")
}

// A nil controller (the default) means no module-driven sealing: login/logout
// must behave exactly as before, with no attempt to seal.
func TestSealController_NilIsNoOp(t *testing.T) {
	m := initializeTestModule(t)
	defer m.Finalize()
	session := loginAsNormalUser(t, m)
	require.Equal(t, CKR_OK, m.Logout(session))
}

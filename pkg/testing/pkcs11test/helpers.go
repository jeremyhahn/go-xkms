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

package pkcs11test

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// createInitializedModule creates a fresh module from the factory and initializes it.
func (s *Suite) createInitializedModule(t *testing.T) (*module.Module, func()) {
	t.Helper()
	m, cleanup := s.factory(t)
	rv := m.Initialize(nil)
	requireRV(t, module.CKR_OK, rv, "Initialize failed")
	return m, func() {
		m.Finalize()
		cleanup()
	}
}

// openRWSession opens a read-write session on slot 0.
func openRWSession(t *testing.T, m *module.Module) module.SessionHandle {
	t.Helper()
	handle, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION|module.CKF_RW_SESSION)
	requireRV(t, module.CKR_OK, rv, "OpenSession RW failed")
	return handle
}

// openROSession opens a read-only session on slot 0.
func openROSession(t *testing.T, m *module.Module) module.SessionHandle {
	t.Helper()
	handle, rv := m.OpenSession(0, module.CKF_SERIAL_SESSION)
	requireRV(t, module.CKR_OK, rv, "OpenSession RO failed")
	return handle
}

// initToken initializes the token on slot 0 with default test credentials.
func initToken(t *testing.T, m *module.Module) {
	t.Helper()
	rv := m.InitToken(0, []byte("12345678"), "test-token")
	requireRV(t, module.CKR_OK, rv, "InitToken failed")
}

// suiteUserPIN returns the user PIN this suite authenticates with.
//
// The suite provisions its own token when it finds an unprovisioned one, but it
// also runs against a daemon that has already auto-initialized the token from
// XKMS_PKCS11_USER_PIN. In that case the PIN in force is the environment's, not
// the literal this suite would have chosen, and logging in with the literal
// fails with CKR_PIN_INCORRECT -- a failure that says nothing about the code
// under test. Reading the same variable the daemon read keeps the two in step.
func suiteUserPIN() []byte {
	if pin := os.Getenv("XKMS_PKCS11_USER_PIN"); pin != "" {
		return []byte(pin)
	}
	return []byte(defaultSuiteUserPIN)
}

// suiteSOPIN returns the security-officer PIN, on the same basis as
// suiteUserPIN.
func suiteSOPIN() []byte {
	if pin := os.Getenv("XKMS_PKCS11_SO_PIN"); pin != "" {
		return []byte(pin)
	}
	return []byte(defaultSuiteSOPIN)
}

const (
	// defaultSuiteUserPIN and defaultSuiteSOPIN are used when the suite
	// provisions the token itself.
	defaultSuiteUserPIN = "userpin"
	defaultSuiteSOPIN   = "12345678"
)

// initTokenAndPIN initializes the token and sets the user PIN.
func initTokenAndPIN(t *testing.T, m *module.Module) {
	t.Helper()
	initToken(t, m)

	// Open RW session and login as SO to set user PIN
	sh := openRWSession(t, m)
	rv := m.Login(sh, module.CKU_SO, suiteSOPIN())
	requireRV(t, module.CKR_OK, rv, "Login as SO failed")

	rv = m.InitPIN(sh, suiteUserPIN())
	requireRV(t, module.CKR_OK, rv, "InitPIN failed")

	rv = m.Logout(sh)
	requireRV(t, module.CKR_OK, rv, "Logout failed")

	rv = m.CloseSession(sh)
	requireRV(t, module.CKR_OK, rv, "CloseSession failed")
}

// loginAsUser logs into the session as a normal user.
func loginAsUser(t *testing.T, m *module.Module, sh module.SessionHandle) {
	t.Helper()
	// Login state is token-wide, so a session opened on an already
	// authenticated token is logged in the moment it opens.
	if rv := m.Login(sh, module.CKU_USER, suiteUserPIN()); rv != module.CKR_USER_ALREADY_LOGGED_IN {
		requireRV(t, module.CKR_OK, rv, "Login as user failed")
	}
}

// openAuthenticatedRWSession provisions the token and returns a read-write
// session with the normal user logged in.
//
// The token advertises CKF_LOGIN_REQUIRED, so key generation, key management
// and any operation on a private object are refused until the user has
// authenticated. Tests that exercise those operations must start from an
// authenticated session; tests that deliberately exercise the unauthenticated
// state should use openRWSession instead.
func openAuthenticatedRWSession(t *testing.T, m *module.Module) module.SessionHandle {
	t.Helper()
	provisionToken(t, m)
	sh := openRWSession(t, m)

	// The token's login state is shared by every session, so a second session
	// on an already-authenticated token is logged in the moment it opens.
	if info, rv := m.GetTokenInfo(0); rv == module.CKR_OK &&
		info.Flags.Has(module.CKF_USER_PIN_INITIALIZED) {
		if rv := m.Login(sh, module.CKU_USER, suiteUserPIN()); rv != module.CKR_OK &&
			rv != module.CKR_USER_ALREADY_LOGGED_IN {
			t.Fatalf("Login as user failed: %v", rv)
		}
	}
	return sh
}

// provisionToken initializes the token and its user PIN if that has not already
// happened. C_InitToken refuses to run while any session is open, so it must be
// idempotent: a test that opens several authenticated sessions provisions on the
// first call and reuses that state afterwards.
func provisionToken(t *testing.T, m *module.Module) {
	t.Helper()

	if info, rv := m.GetTokenInfo(0); rv == module.CKR_OK &&
		info.Flags.Has(module.CKF_USER_PIN_INITIALIZED) {
		return
	}
	initTokenAndPIN(t, m)
}

// createSecretKeyObject creates a test AES secret key object in the given session.
func createSecretKeyObject(t *testing.T, m *module.Module, sh module.SessionHandle) module.ObjectHandle {
	t.Helper()
	template := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, "test-aes-key"),
		module.NewAttribute(module.CKA_VALUE, []byte("0123456789ABCDEF")),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewBoolAttribute(module.CKA_SIGN, true),
		module.NewBoolAttribute(module.CKA_VERIFY, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_WRAP, true),
		module.NewBoolAttribute(module.CKA_UNWRAP, true),
		module.NewBoolAttribute(module.CKA_DERIVE, true),
		module.NewBoolAttribute(module.CKA_SIGN_RECOVER, true),
		module.NewBoolAttribute(module.CKA_VERIFY_RECOVER, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
		module.NewBoolAttribute(module.CKA_COPYABLE, true),
		module.NewBoolAttribute(module.CKA_DESTROYABLE, true),
	}
	handle, rv := m.CreateObject(sh, template)
	requireRV(t, module.CKR_OK, rv, "CreateObject secret key failed")
	return handle
}

// createDataObject creates a test data object in the given session.
func createDataObject(t *testing.T, m *module.Module, sh module.SessionHandle, label string) module.ObjectHandle {
	t.Helper()
	template := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_DATA)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewAttribute(module.CKA_VALUE, []byte("test-data-value")),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
		module.NewBoolAttribute(module.CKA_COPYABLE, true),
		module.NewBoolAttribute(module.CKA_DESTROYABLE, true),
	}
	handle, rv := m.CreateObject(sh, template)
	requireRV(t, module.CKR_OK, rv, "CreateObject data failed")
	return handle
}

// generateSecretKey generates a real AES-256 secret key using C_GenerateKey.
// Unlike createSecretKeyObject, this creates a backend key suitable for
// cryptographic operations in integration tests against a real xkms server.
//
// The key is created with CKA_SENSITIVE CK_FALSE and CKA_EXTRACTABLE CK_TRUE,
// which PKCS#11 v3.2 §4.9 footnote 7 makes the one combination whose CKA_VALUE
// the token may reveal. The conformance tests need that value: reproducing a
// ciphertext with an AES-GCM implementation outside the module is the only way
// to tell a real encryption apart from one that returns its input. Tests that
// need a protected key state that in their own template.
func generateSecretKey(t *testing.T, m *module.Module, sh module.SessionHandle) module.ObjectHandle {
	t.Helper()
	template := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		module.NewStringAttribute(module.CKA_LABEL, "test-aes-gen"),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewBoolAttribute(module.CKA_SIGN, true),
		module.NewBoolAttribute(module.CKA_VERIFY, true),
		module.NewBoolAttribute(module.CKA_WRAP, true),
		module.NewBoolAttribute(module.CKA_UNWRAP, true),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_DERIVE, true),
		module.NewBoolAttribute(module.CKA_SIGN_RECOVER, true),
		module.NewBoolAttribute(module.CKA_VERIFY_RECOVER, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
		module.NewBoolAttribute(module.CKA_COPYABLE, true),
		module.NewBoolAttribute(module.CKA_DESTROYABLE, true),
	}
	mechanism := &module.Mechanism{Type: module.CKM_AES_KEY_GEN}
	handle, rv := m.GenerateKey(sh, mechanism, template)
	requireRV(t, module.CKR_OK, rv, "GenerateKey AES failed")
	return handle
}

// generateRSAKeyPair generates a real RSA-2048 key pair using C_GenerateKeyPair.
// Unlike createRSAPublicKeyObject/createRSAPrivateKeyObject, this creates backend
// keys suitable for cryptographic operations in integration tests against a real
// xkms server.
func generateRSAKeyPair(t *testing.T, m *module.Module, sh module.SessionHandle) (pubHandle, privHandle module.ObjectHandle) {
	t.Helper()
	pubTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PUBLIC_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
		module.NewUint32Attribute(module.CKA_MODULUS_BITS, 2048),
		module.NewStringAttribute(module.CKA_LABEL, "test-rsa-gen-pub"),
		module.NewAttribute(module.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_VERIFY, true),
		module.NewBoolAttribute(module.CKA_VERIFY_RECOVER, true),
		module.NewBoolAttribute(module.CKA_WRAP, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
		module.NewBoolAttribute(module.CKA_COPYABLE, true),
		module.NewBoolAttribute(module.CKA_DESTROYABLE, true),
	}
	privTemplate := []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_PRIVATE_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_RSA)),
		module.NewStringAttribute(module.CKA_LABEL, "test-rsa-gen-priv"),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
		module.NewBoolAttribute(module.CKA_SIGN, true),
		module.NewBoolAttribute(module.CKA_SIGN_RECOVER, true),
		module.NewBoolAttribute(module.CKA_DERIVE, true),
		module.NewBoolAttribute(module.CKA_UNWRAP, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
		module.NewBoolAttribute(module.CKA_TOKEN, false),
		module.NewBoolAttribute(module.CKA_MODIFIABLE, true),
		module.NewBoolAttribute(module.CKA_COPYABLE, true),
		module.NewBoolAttribute(module.CKA_DESTROYABLE, true),
	}
	mechanism := &module.Mechanism{Type: module.CKM_RSA_PKCS_KEY_PAIR_GEN}
	pubHandle, privHandle, rv := m.GenerateKeyPair(sh, mechanism, pubTemplate, privTemplate)
	requireRV(t, module.CKR_OK, rv, "GenerateKeyPair RSA failed")
	return pubHandle, privHandle
}

// suiteGCMIV returns a fixed 12-byte AES-GCM IV for conformance fixtures.
// CKM_AES_GCM carries its IV in CK_GCM_PARAMS, and decryption cannot proceed
// without one.
func suiteGCMIV() []byte {
	return []byte("suite-gcm-iv")
}

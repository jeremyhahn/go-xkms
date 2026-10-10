// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The personal-vault endpoints driven through a real XKMSService over a real
// TenantPasswordStoreManager and BarrierRegistry (newPasswordFixture).

// vaultPassphrase is the passphrase the vault tests enroll.
const vaultPassphrase = "correct horse battery staple"

// passphraseCred returns a passphrase credential.
func passphraseCred(passphrase string) transport.PasswordVaultCredential {
	return transport.PasswordVaultCredential{Factor: "passphrase", Passphrase: passphrase}
}

// enroll enrolls cred on identity's vault, requiring 201.
func (f *passwordFixture) enroll(t *testing.T, identity *auth.Identity, cred transport.PasswordVaultCredential) transport.PasswordVaultEnrollResponse {
	t.Helper()
	w := f.do(t, identity, http.MethodPost, "/api/v1/password-vault/factors", jsonBody(t, cred))
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var resp transport.PasswordVaultEnrollResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// unlockWith posts an unlock with cred as identity.
func (f *passwordFixture) unlockWith(t *testing.T, identity *auth.Identity, cred transport.PasswordVaultCredential) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(t, identity, http.MethodPost, "/api/v1/password-vault/unlock", jsonBody(t, cred))
}

func TestVaultHandlers_PassphraseLifecycle(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)

	before := f.vaultStatus(t, alice)
	assert.False(t, before.Initialized)
	assert.False(t, before.Unlocked)

	enrolled := f.enroll(t, alice, passphraseCred(vaultPassphrase))
	assert.NotEmpty(t, enrolled.RecoveryCode, "the first enrollment issues the recovery code")
	assert.Equal(t, "passphrase", enrolled.Factor.Factor)

	after := f.vaultStatus(t, alice)
	assert.True(t, after.Initialized)
	assert.True(t, after.Unlocked, "the first enrollment opens the session")

	f.lock(t, alice)
	rejected := f.unlockWith(t, alice, passphraseCred("not the passphrase"))
	assert.Equal(t, http.StatusUnauthorized, rejected.Code)
	assert.Equal(t, "Credential rejected", errorMessage(t, rejected))
	assert.True(t, f.status(t, alice).IsLocked)

	ok := f.unlockWith(t, alice, passphraseCred(vaultPassphrase))
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())
	assert.False(t, f.status(t, alice).IsLocked)
}

func TestVaultHandlers_PasskeyEnrollAndUnlock(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	passkey := passkeyFor(alice)
	enrolled := f.enroll(t, alice, passkey)
	assert.Equal(t, passkey.CredentialID, enrolled.Factor.CredentialID)

	// The status carries what a client needs to evaluate hmac-secret: the
	// credential ID and PRF salt survive the base64 JSON round trip.
	var listed bool
	for _, factor := range f.vaultStatus(t, alice).Factors {
		if factor.Factor == "passkey" {
			listed = true
			assert.Equal(t, passkey.CredentialID, factor.CredentialID)
			assert.Equal(t, passkey.PRFSalt, factor.PRFSalt)
		}
	}
	assert.True(t, listed)

	f.lock(t, alice)
	wrong := passkeyFor(alice)
	wrong.Secret = make([]byte, 32)
	assert.Equal(t, http.StatusUnauthorized, f.unlockWith(t, alice, wrong).Code)

	ok := f.unlockWith(t, alice, transport.PasswordVaultCredential{
		Factor: "passkey", CredentialID: passkey.CredentialID, Secret: passkey.Secret,
	})
	require.Equal(t, http.StatusOK, ok.Code, ok.Body.String())
}

func TestVaultHandlers_EnrollErrors(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)

	short := f.do(t, alice, http.MethodPost, "/api/v1/password-vault/factors", jsonBody(t, passphraseCred("short")))
	assert.Equal(t, http.StatusBadRequest, short.Code)

	malformed := f.do(t, alice, http.MethodPost, "/api/v1/password-vault/factors", `{bad`)
	assert.Equal(t, http.StatusBadRequest, malformed.Code)
	assert.Equal(t, "Invalid request body", errorMessage(t, malformed))

	f.enroll(t, alice, passkeyFor(alice))
	duplicate := f.do(t, alice, http.MethodPost, "/api/v1/password-vault/factors", jsonBody(t, passkeyFor(alice)))
	assert.Equal(t, http.StatusConflict, duplicate.Code)
	assert.Equal(t, "Passkey already enrolled", errorMessage(t, duplicate))

	f.lock(t, alice)
	locked := f.do(t, alice, http.MethodPost, "/api/v1/password-vault/factors", jsonBody(t, passkeyFor(user(tenantA, "other-key"))))
	assert.Equal(t, http.StatusLocked, locked.Code, "a later enrollment needs the session open")
}

func TestVaultHandlers_Rotate(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	enrolled := f.enroll(t, alice, passkeyFor(alice))

	rotated := passkeyFor(alice)
	rotated.Secret = []byte("0123456789abcdef0123456789abcdef")
	w := f.do(t, alice, http.MethodPut, "/api/v1/password-vault/factors/"+enrolled.Factor.ID, jsonBody(t, rotated))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp transport.PasswordVaultEnrollResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Empty(t, resp.RecoveryCode)

	f.lock(t, alice)
	assert.Equal(t, http.StatusUnauthorized, f.unlockWith(t, alice, passkeyFor(alice)).Code, "the old secret stops working")
	require.Equal(t, http.StatusOK, f.unlockWith(t, alice, rotated).Code)

	unknown := f.do(t, alice, http.MethodPut, "/api/v1/password-vault/factors/no-such-factor", jsonBody(t, rotated))
	assert.Equal(t, http.StatusNotFound, unknown.Code)

	wrongType := f.do(t, alice, http.MethodPut, "/api/v1/password-vault/factors/"+resp.Factor.ID, jsonBody(t, passphraseCred(vaultPassphrase)))
	assert.Equal(t, http.StatusBadRequest, wrongType.Code, "a rotation keeps the factor type")

	malformed := f.do(t, alice, http.MethodPut, "/api/v1/password-vault/factors/"+resp.Factor.ID, `{bad`)
	assert.Equal(t, http.StatusBadRequest, malformed.Code)

	f.lock(t, alice)
	locked := f.do(t, alice, http.MethodPut, "/api/v1/password-vault/factors/"+resp.Factor.ID, jsonBody(t, rotated))
	assert.Equal(t, http.StatusLocked, locked.Code)
}

func TestVaultHandlers_RemoveFactor(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	first := f.enroll(t, alice, passkeyFor(user(tenantA, "key-one")))
	second := f.enroll(t, alice, passkeyFor(user(tenantA, "key-two")))

	removed := f.do(t, alice, http.MethodDelete, "/api/v1/password-vault/factors/"+second.Factor.ID, "")
	assert.Equal(t, http.StatusNoContent, removed.Code, removed.Body.String())

	last := f.do(t, alice, http.MethodDelete, "/api/v1/password-vault/factors/"+first.Factor.ID, "")
	assert.Equal(t, http.StatusConflict, last.Code)
	assert.Equal(t, "Cannot remove the last unlock factor", errorMessage(t, last))

	gone := f.do(t, alice, http.MethodDelete, "/api/v1/password-vault/factors/"+second.Factor.ID, "")
	assert.Equal(t, http.StatusNotFound, gone.Code)

	// The recovery code is listed as a factor but is not removable.
	for _, factor := range f.vaultStatus(t, alice).Factors {
		if factor.Factor == "recovery" {
			w := f.do(t, alice, http.MethodDelete, "/api/v1/password-vault/factors/"+factor.ID, "")
			assert.Equal(t, http.StatusBadRequest, w.Code)
		}
	}
}

func TestVaultHandlers_RecoverIsOneTime(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice := user(tenantA, userA)
	enrolled := f.enroll(t, alice, passkeyFor(user(tenantA, "lost-key")))
	f.lock(t, alice)

	recoverWith := func(code string, cred transport.PasswordVaultCredential) *httptest.ResponseRecorder {
		return f.do(t, alice, http.MethodPost, "/api/v1/password-vault/recover",
			jsonBody(t, transport.PasswordVaultRecoverRequest{RecoveryCode: code, PasswordVaultCredential: cred}))
	}

	w := recoverWith(enrolled.RecoveryCode, passkeyFor(user(tenantA, "new-key")))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var recovered transport.PasswordVaultEnrollResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&recovered))
	assert.NotEmpty(t, recovered.RecoveryCode)
	assert.NotEqual(t, enrolled.RecoveryCode, recovered.RecoveryCode)
	assert.True(t, f.vaultStatus(t, alice).Unlocked, "recovery opens the session")

	f.lock(t, alice)
	spent := recoverWith(enrolled.RecoveryCode, passkeyFor(user(tenantA, "third-key")))
	assert.Equal(t, http.StatusUnauthorized, spent.Code, "a used recovery code is spent")

	empty := recoverWith("", passkeyFor(user(tenantA, "third-key")))
	assert.Equal(t, http.StatusBadRequest, empty.Code)

	malformed := f.do(t, alice, http.MethodPost, "/api/v1/password-vault/recover", `{bad`)
	assert.Equal(t, http.StatusBadRequest, malformed.Code)

	require.Equal(t, http.StatusOK, f.unlockWith(t, alice, passkeyFor(user(tenantA, "new-key"))).Code)
}

// One user's vault operations never read or change another user's vault.
func TestVaultHandlers_UsersAreIsolated(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	alice, bob := user(tenantA, userA), user(tenantA, userB)
	aliceFactor := f.enroll(t, alice, passkeyFor(alice))

	assert.False(t, f.vaultStatus(t, bob).Initialized, "Alice's enrollment does not initialize Bob's vault")
	assert.Equal(t, http.StatusPreconditionFailed, f.unlockWith(t, bob, passkeyFor(alice)).Code,
		"Alice's passkey is not a factor of Bob's vault")

	f.enroll(t, bob, passkeyFor(bob))
	w := f.do(t, bob, http.MethodDelete, "/api/v1/password-vault/factors/"+aliceFactor.Factor.ID, "")
	assert.Equal(t, http.StatusNotFound, w.Code, "Bob cannot address Alice's factor")

	// The same subject in another tenant has a vault of its own.
	assert.False(t, f.vaultStatus(t, user(tenantB, userA)).Initialized)

	f.lock(t, alice)
	require.Equal(t, http.StatusOK, f.unlockWith(t, alice, passkeyFor(alice)).Code)
}

// A request without an identity has no personal vault.
func TestVaultHandlers_NoIdentityIsNotImplemented(t *testing.T) {
	t.Parallel()

	f := newPasswordFixture(t)
	cred := jsonBody(t, passkeyFor(user(tenantA, userA)))

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/password-vault", ""},
		{http.MethodPost, "/api/v1/password-vault/factors", cred},
		{http.MethodPut, "/api/v1/password-vault/factors/f1", cred},
		{http.MethodDelete, "/api/v1/password-vault/factors/f1", ""},
		{http.MethodPost, "/api/v1/password-vault/recover", `{"recovery_code":"c","factor":"passphrase","passphrase":"correct horse"}`},
	} {
		w := f.do(t, nil, tc.method, tc.path, tc.body)
		assert.Equal(t, http.StatusNotImplemented, w.Code, tc.method+" "+tc.path)
	}
}

func TestVaultHandlers_NotConfiguredAndSealed(t *testing.T) {
	t.Parallel()

	t.Run("no password store configured", func(t *testing.T) {
		t.Parallel()

		router := passwordRouter(NewPasswordHandlers(&xkms.XKMSService{}))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/password-vault", nil)
		req = req.WithContext(auth.WithIdentity(req.Context(), user(tenantA, userA)))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("sealed tenant", func(t *testing.T) {
		t.Parallel()

		f := newPasswordFixture(t)
		f.stores.Seal(tenantA)
		alice := user(tenantA, userA)

		assert.Equal(t, http.StatusServiceUnavailable, f.do(t, alice, http.MethodGet, "/api/v1/password-vault", "").Code)
		w := f.do(t, alice, http.MethodPost, "/api/v1/password-vault/factors", jsonBody(t, passkeyFor(alice)))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPasswordWriteVaultError_Mapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want int
	}{
		{staticpw.ErrVaultInvalidCredential, http.StatusBadRequest},
		{staticpw.ErrVaultRecoveryFactor, http.StatusBadRequest},
		{staticpw.ErrVaultNotInitialized, http.StatusPreconditionFailed},
		{staticpw.ErrVaultCredentialRejected, http.StatusUnauthorized},
		{staticpw.ErrVaultFactorNotFound, http.StatusNotFound},
		{staticpw.ErrVaultLastFactor, http.StatusConflict},
		{staticpw.ErrVaultPasskeyExists, http.StatusConflict},
		{staticpw.ErrStoreLocked, http.StatusLocked},
		{xkms.ErrOperationNotSupported, http.StatusNotImplemented},
		{xkms.ErrNotConfigured, http.StatusServiceUnavailable},
		{seal.ErrTenantSealed, http.StatusServiceUnavailable},
		{seal.ErrTenantNotFound, http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			passwordWriteVaultError(w, errors.Join(errors.New("context"), tc.err), "fallback")
			assert.Equal(t, tc.want, w.Code)
			assert.NotEqual(t, "fallback", errorMessage(t, w))
		})
	}

	t.Run("unknown error uses the fallback without its detail", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		passwordWriteVaultError(w, errors.New("disk offline at /var/lib/xkms"), "Failed to enroll vault factor")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		msg := errorMessage(t, w)
		assert.Equal(t, "Failed to enroll vault factor", msg)
		assert.False(t, strings.Contains(msg, "/var/lib"))
	})
}

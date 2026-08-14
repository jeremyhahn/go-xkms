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

package quic

import (
	"context"
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
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// testUserPIN is the PIN the stub servicer treats as provisioned and correct.
const testUserPIN = "123456"

// unlockServicerStub stands in for *xkms.XKMSService in unlock handler tests.
// It reproduces XKMSService.PasswordStoreUnlock's contract: the user PIN is
// verified before the tenant store is unlocked, and every rejection path
// returns the same typed sentinel the real servicer returns. The real PIN
// verification itself is covered in pkg/xkms; what these tests pin is that the
// handler routes through the servicer at all, so a rejection leaves the store
// locked instead of unlocking with no credential.
type unlockServicerStub struct {
	// provisionedPIN is the PIN the deployment has set. An empty value models
	// a deployment with no PIN backend or no user PIN.
	provisionedPIN string

	// unlocked records whether the stub reached the point of unlocking.
	unlocked bool

	// called records whether the handler delegated to the servicer at all.
	called bool
}

func (s *unlockServicerStub) PasswordStoreUnlock(_ context.Context, req *transport.PasswordStoreUnlockRequest) error {
	s.called = true

	if s.provisionedPIN == "" {
		return xkms.ErrPasswordStoreUserPINNotProvisioned
	}
	if req.UserPIN == "" {
		return xkms.ErrPasswordStoreUserPINRequired
	}
	if req.UserPIN != s.provisionedPIN {
		return errors.New("pin: verification failed, 2 attempts remaining")
	}

	s.unlocked = true
	return nil
}

// unlockRequest builds an unlock request carrying a tenant identity and the
// given body. An empty body models a client that sent no PIN at all.
func unlockRequest(body string, tenantID string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	} else {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", strings.NewReader(body))
	}
	identity := &auth.Identity{Subject: "test-user", TenantID: tenantID}
	return req.WithContext(auth.WithIdentity(req.Context(), identity))
}

// TestQUICUnlockHandler_NoPINIsRejected is the regression test for the unlock
// bypass: the handler used to call TenantPasswordStoreManager.UnlockTenant
// directly, so any authenticated tenant user could open the tenant password
// store with no credential whatsoever. The handler must now route through the
// servicer.
func TestQUICUnlockHandler_NoPINIsRejected(t *testing.T) {
	servicer := &unlockServicerStub{provisionedPIN: testUserPIN}
	handlers := NewPasswordHandlers(nil, &staticpw.TenantPasswordStoreManager{}, servicer)

	w := httptest.NewRecorder()
	handlers.UnlockHandler(w, unlockRequest("", "tenant-1"))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.True(t, servicer.called, "handler must delegate to the servicer, not unlock directly")
	assert.False(t, servicer.unlocked, "a PIN-less unlock must not reach the unlock step")

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Contains(t, resp["error"], "User PIN is required")
}

// TestQUICUnlockHandler_SystemTenantIDRejected proves the password store
// unlock path treats a "system"-tenant caller the same as an empty-tenant
// caller: it has no per-tenant password store to unlock, so it is rejected.
// This is the opposite polarity from the tenant *scope gates*
// (middleware_tenant.go): those pass a system-scoped caller through, this
// rejects it, because a concrete tenant store is required here.
func TestQUICUnlockHandler_SystemTenantIDRejected(t *testing.T) {
	servicer := &unlockServicerStub{provisionedPIN: testUserPIN}
	handlers := NewPasswordHandlers(nil, &staticpw.TenantPasswordStoreManager{}, servicer)

	w := httptest.NewRecorder()
	handlers.UnlockHandler(w, unlockRequest(`{"user_pin":"123456"}`, "system"))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, servicer.called, "a system-tenant caller must be rejected before reaching the servicer")
}

// TestQUICUnlockHandler_WrongPINIsRejected proves a bad PIN is reported as an
// authentication failure and does not leak the PIN backend's message, which
// can carry retry counters and lockout state.
func TestQUICUnlockHandler_WrongPINIsRejected(t *testing.T) {
	servicer := &unlockServicerStub{provisionedPIN: testUserPIN}
	handlers := NewPasswordHandlers(nil, &staticpw.TenantPasswordStoreManager{}, servicer)

	w := httptest.NewRecorder()
	handlers.UnlockHandler(w, unlockRequest(`{"user_pin":"999999"}`, "tenant-1"))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, servicer.unlocked, "a wrong PIN must not unlock the store")

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "User PIN verification failed", resp["error"])
	assert.NotContains(t, resp["error"], "attempts remaining")
}

// TestQUICLockHandler_SystemTenantIDRejected mirrors
// TestQUICUnlockHandler_SystemTenantIDRejected for the lock path.
func TestQUICLockHandler_SystemTenantIDRejected(t *testing.T) {
	handlers := NewPasswordHandlers(nil, &staticpw.TenantPasswordStoreManager{}, &unlockServicerStub{provisionedPIN: testUserPIN})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/lock", nil)
	identity := &auth.Identity{Subject: "test-user", TenantID: "system"}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	handlers.LockHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestQUICUnlockHandler_UnprovisionedPINIsRejected proves a deployment with no
// user PIN reports the condition instead of unlocking without a credential.
func TestQUICUnlockHandler_UnprovisionedPINIsRejected(t *testing.T) {
	servicer := &unlockServicerStub{} // no provisioned PIN
	handlers := NewPasswordHandlers(nil, &staticpw.TenantPasswordStoreManager{}, servicer)

	w := httptest.NewRecorder()
	handlers.UnlockHandler(w, unlockRequest(`{"user_pin":"123456"}`, "tenant-1"))

	assert.Equal(t, http.StatusPreconditionFailed, w.Code)
	assert.False(t, servicer.unlocked)
}

// TestQUICUnlockHandler_NoServicerDoesNotUnlock proves the handler fails closed
// when the composition root did not wire the service layer: it must report
// "requires server integration" rather than falling back to the uncredentialed
// manager path.
func TestQUICUnlockHandler_NoServicerDoesNotUnlock(t *testing.T) {
	handlers := NewPasswordHandlers(nil, &staticpw.TenantPasswordStoreManager{}, nil)

	w := httptest.NewRecorder()
	handlers.UnlockHandler(w, unlockRequest(`{"user_pin":"123456"}`, "tenant-1"))

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

// TestQUICUnlockHandler_MalformedBodyIsRejected proves a body that is present
// but not decodable is a client error rather than a silent PIN-less unlock.
func TestQUICUnlockHandler_MalformedBodyIsRejected(t *testing.T) {
	servicer := &unlockServicerStub{provisionedPIN: testUserPIN}
	handlers := NewPasswordHandlers(nil, &staticpw.TenantPasswordStoreManager{}, servicer)

	w := httptest.NewRecorder()
	handlers.UnlockHandler(w, unlockRequest(`{"user_pin":`, "tenant-1"))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.False(t, servicer.called, "a malformed body must be rejected before the servicer is reached")
}

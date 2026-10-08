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

package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
	pkgwebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// securityFixture is a handler over stores the test can seed directly.
type securityFixture struct {
	h      *Handler
	users  pkgwebauthn.UserStore
	creds  pkgwebauthn.CredentialStore
	stores *webauthntest.Stores
}

func newSecurityFixture(t *testing.T, allowPublic bool) *securityFixture {
	t.Helper()
	stores := webauthntest.NewStores(t)
	users, creds := stores.Users, stores.Credentials
	svc, err := pkgwebauthn.NewService(pkgwebauthn.ServiceParams{
		Config: &pkgwebauthn.Config{
			RPID:                    "example.com",
			RPDisplayName:           "Example",
			RPOrigins:               []string{"https://example.com"},
			AllowPublicRegistration: &allowPublic,
		},
		UserStore:       users,
		SessionStore:    pkgwebauthn.NewMemorySessionStore(),
		CredentialStore: creds,
	})
	require.NoError(t, err)
	return &securityFixture{h: NewHandler(svc), users: users, creds: creds, stores: stores}
}

// account creates email's account holding one credential.
func (f *securityFixture) account(t *testing.T, email string) pkgwebauthn.User {
	t.Helper()
	ctx := context.Background()
	user, err := f.users.Create(ctx, email, email)
	require.NoError(t, err)
	cred := &pkgwebauthn.Credential{ID: []byte("cred-" + email), UserID: user.WebAuthnID()}
	require.NoError(t, f.creds.Save(ctx, cred))
	user.AddCredential(cred)
	require.NoError(t, f.users.Save(ctx, user))
	return user
}

// identityFor is the identity a WebAuthn-minted session token carries.
func identityFor(user pkgwebauthn.User) *auth.Identity {
	return &auth.Identity{
		Subject:  base64.RawURLEncoding.EncodeToString(user.WebAuthnID()),
		Metadata: map[string]string{"email": user.Email()},
	}
}

func post(handler http.HandlerFunc, path, body string, identity *auth.Identity) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if identity != nil {
		req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	return resp
}

// TestBeginRegistration_AccountWithCredentialRefused is go-xkms#1294 on the
// wire: the public route answers 403 registration_refused.
func TestBeginRegistration_AccountWithCredentialRefused(t *testing.T) {
	f := newSecurityFixture(t, true)
	f.account(t, "victim@example.com")

	rec := post(f.h.BeginRegistration, "/registration/begin", `{"email":"victim@example.com"}`, nil)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, rec.Header().Get(HeaderSessionID))
	assert.Equal(t, ErrorCodeRegistrationRefused, decodeError(t, rec).Error)
}

// TestBeginRegistration_RefusalsIndistinguishable is go-xkms#1296: with
// public registration off, an unknown email and an account with a passkey
// get byte-identical responses.
func TestBeginRegistration_RefusalsIndistinguishable(t *testing.T) {
	f := newSecurityFixture(t, false)
	f.account(t, "known@example.com")

	known := post(f.h.BeginRegistration, "/registration/begin", `{"email":"known@example.com"}`, nil)
	unknown := post(f.h.BeginRegistration, "/registration/begin", `{"email":"unknown@example.com"}`, nil)

	assert.Equal(t, http.StatusForbidden, known.Code)
	assert.Equal(t, known.Code, unknown.Code)
	assert.Equal(t, known.Header(), unknown.Header())
	assert.Equal(t, known.Body.String(), unknown.Body.String())
}

// TestBeginAddCredential_OwnSession adds a passkey to the session's account.
func TestBeginAddCredential_OwnSession(t *testing.T) {
	f := newSecurityFixture(t, false)
	user := f.account(t, "owner@example.com")

	rec := post(f.h.BeginAddCredential, "/credentials/begin", "", identityFor(user))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotEmpty(t, rec.Header().Get(HeaderSessionID))
	var options map[string]map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&options))
	assert.Len(t, options["publicKey"]["excludeCredentials"], 1, "the existing passkey is excluded")
}

// TestBeginAddCredential_Unauthenticated answers 401 without a session.
func TestBeginAddCredential_Unauthenticated(t *testing.T) {
	f := newSecurityFixture(t, true)

	rec := post(f.h.BeginAddCredential, "/credentials/begin", "", nil)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, ErrorCodeUnauthenticated, decodeError(t, rec).Error)
}

// TestBeginAddCredential_ForeignSessionRefused proves a session cannot reach
// another account, however its identity is shaped.
func TestBeginAddCredential_ForeignSessionRefused(t *testing.T) {
	f := newSecurityFixture(t, true)
	victim := f.account(t, "victim@example.com")
	attacker := f.account(t, "attacker@example.com")

	mixed := identityFor(victim)
	mixed.Metadata["email"] = attacker.Email()
	notWebAuthn := &auth.Identity{Subject: "alice", Metadata: map[string]string{"email": victim.Email()}}

	for name, identity := range map[string]*auth.Identity{"mixed": mixed, "not webauthn": notWebAuthn} {
		rec := post(f.h.BeginAddCredential, "/credentials/begin", "", identity)
		assert.Equal(t, http.StatusForbidden, rec.Code, name)
		assert.Equal(t, ErrorCodeSessionAccountMismatch, decodeError(t, rec).Error, name)
	}

	creds, err := f.creds.GetByUserID(context.Background(), victim.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, creds, 1)
}

// TestBeginAddCredential_WrongMethod answers 405.
func TestBeginAddCredential_WrongMethod(t *testing.T) {
	f := newSecurityFixture(t, true)
	req := httptest.NewRequest(http.MethodGet, "/credentials/begin", nil)
	rec := httptest.NewRecorder()
	f.h.BeginAddCredential(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestBeginLogin_UnknownEmailIndistinguishable is go-xkms#1296 on the wire:
// an unknown email gets the same status, the same headers and the same
// option fields as a known one, and no user identifier.
func TestBeginLogin_UnknownEmailIndistinguishable(t *testing.T) {
	f := newSecurityFixture(t, true)
	f.account(t, "known@example.com")

	known := post(f.h.BeginLogin, "/login/begin", `{"email":"known@example.com"}`, nil)
	unknown := post(f.h.BeginLogin, "/login/begin", `{"email":"unknown@example.com"}`, nil)

	require.Equal(t, http.StatusOK, known.Code)
	assert.Equal(t, known.Code, unknown.Code)
	assert.Equal(t, headerNames(known.Header()), headerNames(unknown.Header()))
	assert.Empty(t, known.Header().Get("X-User-Id"))
	assert.Empty(t, unknown.Header().Get("X-User-Id"))

	var knownBody, unknownBody map[string]map[string]any
	require.NoError(t, json.NewDecoder(known.Body).Decode(&knownBody))
	require.NoError(t, json.NewDecoder(unknown.Body).Decode(&unknownBody))
	assert.Equal(t, fieldNames(knownBody["publicKey"]), fieldNames(unknownBody["publicKey"]))
	assert.NotEmpty(t, unknownBody["publicKey"]["allowCredentials"])
}

// TestHandleServiceError_SecurityErrors maps the errors this change adds.
func TestHandleServiceError_SecurityErrors(t *testing.T) {
	h := newTestHandler(t)
	cases := []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{pkgwebauthn.ErrRegistrationRefused, http.StatusForbidden, ErrorCodeRegistrationRefused},
		{pkgwebauthn.ErrSessionAccountMismatch, http.StatusForbidden, ErrorCodeSessionAccountMismatch},
		{pkgwebauthn.WrapError("save credential", pkgwebauthn.ErrCredentialAlreadyExists), http.StatusConflict, ErrorCodeCredentialExists},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.handleServiceError(rec, tc.err)
		assert.Equal(t, tc.wantStatus, rec.Code, tc.err.Error())
		assert.Equal(t, tc.wantCode, decodeError(t, rec).Error, tc.err.Error())
	}
}

func headerNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func fieldNames(m map[string]any) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

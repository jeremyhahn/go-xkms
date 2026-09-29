//go:build codec_json

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

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/require"
)

// createTestAccountWithTenant is createTestAccount with an explicit
// TenantID, for tests exercising tenant resolution.
func createTestAccountWithTenant(t *testing.T, service *RestService, key *TestKey, tenantID string) *entities.ACMEAccount {
	ctx := context.Background()

	accountDAO, err := service.storageFactory.AccountDAO()
	require.NoError(t, err)

	pubKeyPEM, err := xkmssdk.EncodePublicKeyPEM(key.PublicKey)
	require.NoError(t, err)

	accountID, err := AccountIDFromPublicKey(key.PublicKey)
	require.NoError(t, err)

	account := &entities.ACMEAccount{
		ID:                   accountID,
		Status:               common.StatusValid,
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
		Key:                  string(pubKeyPEM),
		CreatedAt:            time.Now(),
		Orders:               fmt.Sprintf("%s/acme/account/%d/orders", service.baseRESTURI, accountID),
		URL:                  fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, accountID),
		TenantID:             tenantID,
	}

	require.NoError(t, accountDAO.Save(ctx, account))
	return account
}

// TestTenantAuthMiddleware_ResolvesVerifiedTenant proves that a POST request
// carrying a JWS whose "kid" names an account resolves that account's
// TenantID into the request context, and that the handler's own parseKID
// call (the replay-nonce is single-use, so it cannot re-verify) sees the
// identical, already-verified account instead of failing.
func TestTenantAuthMiddleware_ResolvesVerifiedTenant(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccountWithTenant(t, service, key, "tenant-a")

	url := fmt.Sprintf("%s/acme/new-order", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	var gotTenant, gotClientID string
	var gotAccount *entities.ACMEAccount
	var gotErr error
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = server.TenantIDFromContext(r.Context())
		gotClientID = server.ClientID(r)
		gotAccount, _, gotErr = service.parseKID(r.Context(), r)
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	service.TenantAuthMiddleware(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "tenant-a", gotTenant)
	require.NoError(t, gotErr)
	require.NotNil(t, gotAccount)
	require.Equal(t, account.ID, gotAccount.ID)
	require.Equal(t, strconv.FormatUint(account.ID, 10), gotClientID,
		"a verified kid must key the per-account rate-limit bucket")
}

// TestTenantAuthMiddleware_HeaderCannotSpoofTenant proves that a
// client-asserted X-Tenant-ID header never influences the resolved tenant:
// it is ignored both when a verified kid names a different (real) tenant
// and when no kid is present at all.
func TestTenantAuthMiddleware_HeaderCannotSpoofTenant(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccountWithTenant(t, service, key, "tenant-real")

	url := fmt.Sprintf("%s/acme/new-order", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)
	req.Header.Set("X-Tenant-ID", "tenant-attacker")

	var gotTenant string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = server.TenantIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	service.TenantAuthMiddleware(next).ServeHTTP(rec, req)

	require.Equal(t, "tenant-real", gotTenant, "the verified kid's tenant must win over X-Tenant-ID")

	// No kid at all (new-account's JWK-embedded JWS): the header still never
	// contributes a tenant.
	newAccountKey := generateTestKey(t)
	newAccountURL := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)
	newAccountReq := createJWSRequest(t, service, newAccountKey, newAccountURL, map[string]interface{}{}, false, 0)
	newAccountReq.Header.Set("X-Tenant-ID", "tenant-attacker")

	gotTenant = "unset"
	rec = httptest.NewRecorder()
	service.TenantAuthMiddleware(next).ServeHTTP(rec, newAccountReq)
	require.Equal(t, "", gotTenant, "a request with no kid must never adopt a client-asserted tenant")
}

// TestTenantAuthMiddleware_InvalidSignatureNoTenant proves that a kid
// claiming an account it cannot prove ownership of (signed with the wrong
// key) never resolves a tenant, and that the resulting error is cached and
// replayed to the handler's own parseKID call unchanged — not silently
// turned into badNonce by a second, doomed verification attempt against an
// already-consumed replay-nonce.
func TestTenantAuthMiddleware_InvalidSignatureNoTenant(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	realKey := generateTestKey(t)
	account := createTestAccountWithTenant(t, service, realKey, "tenant-a")

	// Signed by a different key than the one on file for this account: the
	// signature verification inside parseKID must fail.
	attackerKey := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-order", service.baseRESTURI)
	req := createJWSRequest(t, service, attackerKey, url, map[string]interface{}{}, true, account.ID)

	var gotTenant, gotClientID string
	var gotErr error
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = server.TenantIDFromContext(r.Context())
		gotClientID = server.ClientID(r)
		_, _, gotErr = service.parseKID(r.Context(), r)
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	service.TenantAuthMiddleware(next).ServeHTTP(rec, req)

	require.Equal(t, "", gotTenant, "a request that fails verification must never resolve a tenant")
	require.ErrorIs(t, gotErr, ErrInvalidJWSSignature)
	require.Equal(t, server.ClientIP(req), gotClientID,
		"an unverified kid must never key a rate-limit bucket")
}

// TestTenantAuthMiddleware_NoKIDSkipsResolution proves that a JWK-embedded
// JWS (new-account, which names no existing account) is never routed
// through parseKID: the body and replay-nonce are left untouched for the
// handler's own (parseJWS) verification.
func TestTenantAuthMiddleware_NoKIDSkipsResolution(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, false, 0)

	var cached bool
	var jwk any
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, cached = authenticatedJWSFromContext(r.Context())
		gotJWK, _, err := service.parseJWS(r)
		require.NoError(t, err)
		jwk = gotJWK
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	service.TenantAuthMiddleware(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.False(t, cached, "a kid-less request must never populate the parseKID cache")
	require.NotNil(t, jwk, "parseJWS must still be able to read the untouched body")
}

// TestTenantAuthMiddleware_GETSkipsResolution proves that a GET request
// (directory, new-nonce, ca-bundle) is never routed through tenant
// resolution: there is no JWS to verify, so the middleware must not attempt
// to read a body at all.
func TestTenantAuthMiddleware_GETSkipsResolution(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, service.baseRESTURI+"/acme/directory", nil)

	var cached bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, cached = authenticatedJWSFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	service.TenantAuthMiddleware(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.False(t, cached)
}

// TestPeekJWSKeyID_KID proves that a JWS whose protected header names an
// account kid is recognized without consuming anything.
func TestPeekJWSKeyID_KID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-order", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, 42)

	body := make([]byte, req.ContentLength)
	_, err := req.Body.Read(body)
	require.True(t, err == nil || err.Error() == "EOF")

	kid, ok := peekJWSKeyID(body)
	require.True(t, ok)
	require.Equal(t, fmt.Sprintf("%s/acme/account/42", service.baseRESTURI), kid)
}

// TestPeekJWSKeyID_NoKID proves that a JWK-embedded JWS (no account exists
// yet) and a malformed body both report ok=false.
func TestPeekJWSKeyID_NoKID(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	key := generateTestKey(t)
	url := fmt.Sprintf("%s/acme/new-account", service.baseRESTURI)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, false, 0)

	body := make([]byte, req.ContentLength)
	_, err := req.Body.Read(body)
	require.True(t, err == nil || err.Error() == "EOF")

	_, ok := peekJWSKeyID(body)
	require.False(t, ok, "a JWK-embedded JWS must never report a kid")

	_, ok = peekJWSKeyID([]byte("not a jws"))
	require.False(t, ok, "a malformed body must never report a kid")
}

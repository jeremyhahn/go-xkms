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
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/require"
)

// setupTestServiceWithFailedValidationLimiter is setupTestService with an
// explicit Params.FailedValidationRateLimiter, for tests exercising the RFC
// 8555 Section 6.6 failed-validation category (ChallengeHandler).
func setupTestServiceWithFailedValidationLimiter(t *testing.T, limiter *server.TenantRateLimiter) (*RestService, func()) {
	t.Helper()

	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)

	factory, err := objstore.NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	params := &Params{
		BaseRESTURI:                 "https://acme.test.example.com",
		CA:                          &MockCA{},
		CAAIdentities:               []string{"acme.test.example.com"},
		ChallengeMap:                make(map[string]common.ChallengeVerifierFunc),
		FailedValidationRateLimiter: limiter,
		Logger:                      logger,
		StorageFactory:              factory,
		TermsOfService:              "https://acme.test.example.com/tos",
	}

	service, err := NewRestService(params)
	require.NoError(t, err)

	return service.(*RestService), func() {}
}

// TestChallengeHandler_FailedValidationRateLimitTriggers proves that
// repeated failed challenge validations for the same account exhaust the
// RFC 8555 Section 6.6 failed-validation quota: attempts within the budget
// receive the normal "invalid" challenge response, and the attempt that
// exceeds it receives the RFC 8555 rateLimited problem document (HTTP 429,
// Retry-After) instead.
func TestChallengeHandler_FailedValidationRateLimitTriggers(t *testing.T) {
	limiter := server.NewTenantFailedValidationRateLimiter(
		&server.TenantRateLimiterConfig{
			DefaultConfig: &server.RateLimitConfig{
				FailedValidationRate: &server.RateLimit{MaxRequests: 2, Interval: time.Hour},
			},
		},
		server.TenantRateLimiterFromRequestContext(),
	)
	t.Cleanup(limiter.Stop)

	service, cleanup := setupTestServiceWithFailedValidationLimiter(t, limiter)
	defer cleanup()

	service.challengeMap["http-01"] = func(_ *net.Resolver, _ common.CertificateAuthority, _, _, _, _ string) error {
		return caerrors.VerificationFailureError("validation failed")
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	identifier := entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "example.com"}

	attempt := func() *httptest.ResponseRecorder {
		order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
		authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})
		url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
		req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)
		resp := httptest.NewRecorder()
		service.ChallengeHandler(resp, req)
		return resp
	}

	for i := 0; i < 2; i++ {
		resp := attempt()
		require.Equal(t, http.StatusOK, resp.Code, "attempt %d within the failed-validation budget", i+1)
	}

	resp := attempt()
	require.Equal(t, http.StatusTooManyRequests, resp.Code, "the attempt exceeding the failed-validation budget")
	require.Equal(t, "application/problem+json", resp.Header().Get("Content-Type"))
	require.NotEmpty(t, resp.Header().Get("Retry-After"))

	var acmeErr entities.Error
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&acmeErr))
	require.Equal(t, "urn:ietf:params:acme:error:rateLimited", acmeErr.Type)
}

// TestChallengeHandler_FailedValidationRateLimitDisabled proves the
// error/edge path: a nil FailedValidationRateLimiter (the category disabled)
// never rate-limits, however many times validation fails for the account —
// ChallengeHandler must not panic on the nil limiter.
func TestChallengeHandler_FailedValidationRateLimitDisabled(t *testing.T) {
	service, cleanup := setupTestServiceWithFailedValidationLimiter(t, nil)
	defer cleanup()

	service.challengeMap["http-01"] = func(_ *net.Resolver, _ common.CertificateAuthority, _, _, _, _ string) error {
		return caerrors.VerificationFailureError("validation failed")
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	identifier := entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "example.com"}

	for i := 0; i < 4; i++ {
		order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
		authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})
		url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
		req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)
		resp := httptest.NewRecorder()
		service.ChallengeHandler(resp, req)
		require.Equal(t, http.StatusOK, resp.Code, "attempt %d with the failed-validation category disabled", i+1)
	}
}

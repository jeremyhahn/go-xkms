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

package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	acmeserver "github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// discardLogger is a *slog.Logger that writes nowhere, for tests that only
// care about buildACMERouterLimiters' return value, not its log lines.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestBuildACMERouterLimiters_AllEnabled verifies that the default
// (fully enabled) acme.rate_limit configuration constructs every limiter:
// the per-tenant overall quota and all four RFC 8555 Section 6.6 categories
// (go-xkms#886).
func TestBuildACMERouterLimiters_AllEnabled(t *testing.T) {
	limiters := buildACMERouterLimiters(&config.ACMERateLimitConfig{}, discardLogger())
	t.Cleanup(func() {
		for _, l := range limiters.stoppableLimiters() {
			l.Stop()
		}
	})

	if limiters.tenant == nil {
		t.Error("tenant limiter = nil, want non-nil with the default config")
	}
	if limiters.newAccount == nil {
		t.Error("newAccount limiter = nil, want non-nil with the default config")
	}
	if limiters.newOrder == nil {
		t.Error("newOrder limiter = nil, want non-nil with the default config")
	}
	if limiters.certificate == nil {
		t.Error("certificate limiter = nil, want non-nil with the default config")
	}
	if limiters.failedValidation == nil {
		t.Error("failedValidation limiter = nil, want non-nil with the default config")
	}
}

// TestBuildACMERouterLimiters_AllDisabled verifies the error/edge path: an
// operator who explicitly disables every category gets a limiter set with
// every field nil, rather than buildACMERouterLimiters silently keeping one
// enabled or panicking.
func TestBuildACMERouterLimiters_AllDisabled(t *testing.T) {
	disabled := false
	cfg := &config.ACMERateLimitConfig{
		Tenant:           config.ACMECategoryRateLimitConfig{Enabled: &disabled},
		NewAccount:       config.ACMECategoryRateLimitConfig{Enabled: &disabled},
		NewOrder:         config.ACMECategoryRateLimitConfig{Enabled: &disabled},
		Certificate:      config.ACMECategoryRateLimitConfig{Enabled: &disabled},
		FailedValidation: config.ACMECategoryRateLimitConfig{Enabled: &disabled},
	}
	limiters := buildACMERouterLimiters(cfg, discardLogger())

	if limiters.tenant != nil {
		t.Error("tenant limiter != nil, want nil when disabled")
	}
	if limiters.newAccount != nil {
		t.Error("newAccount limiter != nil, want nil when disabled")
	}
	if limiters.newOrder != nil {
		t.Error("newOrder limiter != nil, want nil when disabled")
	}
	if limiters.certificate != nil {
		t.Error("certificate limiter != nil, want nil when disabled")
	}
	if limiters.failedValidation != nil {
		t.Error("failedValidation limiter != nil, want nil when disabled")
	}
	if got := limiters.stoppableLimiters(); len(got) != 0 {
		t.Errorf("stoppableLimiters() = %v, want empty when every limiter is disabled", got)
	}
}

// TestAcmeRouterLimiters_WrapMethodsNilSafe verifies that every wrap* helper
// — and stoppableLimiters — is safe to call on both a nil *acmeRouterLimiters
// and one whose fields are nil (every category disabled): each must pass the
// handler through unwrapped rather than panic.
func TestAcmeRouterLimiters_WrapMethodsNilSafe(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	for _, limiters := range []*acmeRouterLimiters{nil, {}} {
		for _, wrap := range []func(http.Handler) http.Handler{
			limiters.wrapNewAccount, limiters.wrapNewOrder, limiters.wrapCertificate,
		} {
			called = false
			rec := httptest.NewRecorder()
			wrap(next).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/acme/x", nil))
			if !called {
				t.Errorf("wrap(next) on limiters=%#v did not invoke next", limiters)
			}
			if rec.Code != http.StatusOK {
				t.Errorf("wrap(next) on limiters=%#v = %d, want 200", limiters, rec.Code)
			}
		}
		if got := limiters.stoppableLimiters(); got != nil {
			t.Errorf("stoppableLimiters() on limiters=%#v = %v, want nil", limiters, got)
		}
	}
}

// TestAcmeRouterLimiters_StoppableLimiters verifies that every configured
// TenantRateLimiter (tenant, newOrder, certificate, failedValidation) is
// returned for Shutdown to Stop, and that the per-IP newAccount middleware
// (which owns no goroutine) is correctly excluded.
func TestAcmeRouterLimiters_StoppableLimiters(t *testing.T) {
	limiters := buildACMERouterLimiters(&config.ACMERateLimitConfig{}, discardLogger())
	stoppable := limiters.stoppableLimiters()
	t.Cleanup(func() {
		for _, l := range stoppable {
			l.Stop()
		}
	})

	if len(stoppable) != 4 {
		t.Fatalf("stoppableLimiters() returned %d limiters, want 4 (tenant, newOrder, certificate, failedValidation)", len(stoppable))
	}
}

// TestTenantSharedClientKey verifies that tenantSharedClientKey always
// returns the same constant regardless of the request, which is what makes
// the per-tenant overall quota a single bucket shared across every account
// of a tenant rather than one bucket per account (go-xkms#886).
func TestTenantSharedClientKey(t *testing.T) {
	reqA := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
	reqA.Header.Set("X-Forwarded-For", "10.0.0.1")
	reqB := httptest.NewRequest(http.MethodPost, "/acme/new-order", nil)
	reqB.Header.Set("X-Forwarded-For", "10.0.0.2")

	if got := tenantSharedClientKey(reqA); got != "" {
		t.Errorf("tenantSharedClientKey(reqA) = %q, want empty", got)
	}
	if got := tenantSharedClientKey(reqB); got != tenantSharedClientKey(reqA) {
		t.Errorf("tenantSharedClientKey must return the same key for every request: reqA=%q reqB=%q",
			tenantSharedClientKey(reqA), got)
	}
}

// stubTenantRestService extends stubRestService with a TenantAuthMiddleware
// that resolves the tenant from a test-only X-Test-Verified-Tenant header
// instead of a verified JWS kid. It exists ONLY to test that buildACMERouter
// wires TenantAuthMiddleware before the per-tenant overall quota in the
// middleware chain — pkg/acme/server/handlers.TenantAuthMiddleware (the real
// implementation, exercised in pkg/acme/server/handlers/tenant_auth_test.go)
// is what actually resolves a tenant from an authenticated source in
// production; this stub must never be mistaken for that guarantee.
type stubTenantRestService struct {
	stubRestService
}

func (s *stubTenantRestService) TenantAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tenant := r.Header.Get("X-Test-Verified-Tenant"); tenant != "" {
			r = r.WithContext(acmeserver.WithTenantID(r.Context(), tenant))
		}
		next.ServeHTTP(w, r)
	})
}

// TestBuildACMERouter_TenantQuotaSharedAcrossAccounts is an integration test
// of the router wiring (go-xkms#886): with the per-tenant overall quota
// mounted, two requests carrying the same resolved tenant but different
// simulated accounts (different KIDs/IPs, irrelevant to the shared bucket)
// exhaust one shared two-request budget, and a third is refused with the RFC
// 8555 rateLimited problem document — proving TenantAuthMiddleware runs
// before, and the quota keys on, the resolved tenant rather than per-request
// client identity.
func TestBuildACMERouter_TenantQuotaSharedAcrossAccounts(t *testing.T) {
	svc := &stubTenantRestService{}
	tenantLimiter := acmeserver.NewTenantRateLimiter(
		&acmeserver.TenantRateLimiterConfig{
			DefaultConfig: &acmeserver.RateLimitConfig{
				OverallRequestRate: &acmeserver.RateLimit{MaxRequests: 2, Interval: time.Minute},
			},
		},
		acmeserver.TenantRateLimiterFromRequestContext(),
		tenantSharedClientKey,
		"overall",
	)
	t.Cleanup(tenantLimiter.Stop)

	router := buildACMERouter(svc, "/acme", nil, &acmeRouterLimiters{tenant: tenantLimiter})
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	post := func(account string) *http.Response {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/acme/new-order", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("X-Test-Verified-Tenant", "tenant-shared")
		req.Header.Set("X-Test-Account", account) // irrelevant to the shared bucket key
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /acme/new-order (%s): %v", account, err)
		}
		return resp
	}

	resp := post("account-a")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("account-a (1st): got %d, want 204", resp.StatusCode)
	}

	resp = post("account-b")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("account-b (2nd, same tenant): got %d, want 204", resp.StatusCode)
	}

	resp = post("account-a")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("account-a (3rd): got %d, want 429 (tenant's shared budget exhausted)", resp.StatusCode)
	}
}

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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	acmeserver "github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	acmesdk "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// TestStartACMEServer_Disabled verifies that startACMEServer is a no-op when
// the ACME configuration is absent or disabled. No listener should be
// created and no error should be returned.
func TestStartACMEServer_Disabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{"acme_nil", &config.Config{}},
		{"acme_disabled", &config.Config{ACME: &config.ACMEConfig{Enabled: false}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			as, err := startACMEServer(nil, tc.cfg, logger)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if as != nil {
				t.Fatalf("expected nil acmeServer when disabled, got %#v", as)
			}
			// Shutting down a nil acmeServer must be safe.
			if err := as.Shutdown(context.Background()); err != nil {
				t.Fatalf("Shutdown(nil) returned error: %v", err)
			}
		})
	}
}

// TestACMEConfig_Validate exercises the validation rules for ACMEConfig.
func TestACMEConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *config.ACMEConfig
		wantErr error
	}{
		{"nil_is_ok", nil, nil},
		{"disabled_is_ok", &config.ACMEConfig{Enabled: false}, nil},
		{
			"missing_addr",
			&config.ACMEConfig{Enabled: true},
			config.ErrACMEMissingHTTPSAddr,
		},
		{
			"missing_external_url",
			&config.ACMEConfig{Enabled: true, HTTPSAddr: ":8443"},
			config.ErrACMEMissingExternalURL,
		},
		{
			"missing_keystore_backend",
			&config.ACMEConfig{Enabled: true, HTTPSAddr: ":8443", ExternalURL: "https://acme.example.com"},
			config.ErrACMEMissingKeystoreBackend,
		},
		{
			"missing_caa_identities",
			&config.ACMEConfig{
				Enabled:         true,
				HTTPSAddr:       ":8443",
				ExternalURL:     "https://acme.example.com",
				KeystoreBackend: "software",
			},
			config.ErrACMEMissingCAAIdentities,
		},
		{
			// The ACME listener always uses dedicated TLS material (go-xkms#694:
			// the reuse_tls option was deleted, never having been functional),
			// so cert/key files are unconditionally required once the earlier
			// fields are set.
			"missing_tls",
			&config.ACMEConfig{
				Enabled:         true,
				HTTPSAddr:       ":8443",
				ExternalURL:     "https://acme.example.com",
				KeystoreBackend: "software",
				CAAIdentities:   []string{"acme.example.com"},
			},
			config.ErrACMEMissingTLS,
		},
		{
			"tls_present_and_challenge_enabled_is_ok",
			&config.ACMEConfig{
				Enabled:         true,
				HTTPSAddr:       ":8443",
				ExternalURL:     "https://acme.example.com",
				KeystoreBackend: "software",
				CAAIdentities:   []string{"acme.example.com"},
				TLS:             config.ACMETLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
				Challenges:      config.ACMEChallengesConfig{HTTP01: true},
			},
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestBuildChallengeMap_Selection verifies that buildChallengeMap registers
// verifiers only for challenge types that have been enabled.
func TestBuildChallengeMap_Selection(t *testing.T) {
	m, _ := buildChallengeMap(config.ACMEChallengesConfig{HTTP01: true, DNS01: false}, config.ACMEResilienceConfig{}, nil, nil)
	if _, ok := m[common.ChallengeTypeHTTP01]; !ok {
		t.Fatalf("expected http-01 verifier to be registered")
	}
	if _, ok := m[common.ChallengeTypeDNS01]; ok {
		t.Fatalf("expected dns-01 verifier to be absent when disabled")
	}

	m, _ = buildChallengeMap(config.ACMEChallengesConfig{HTTP01: false, DNS01: true}, config.ACMEResilienceConfig{}, nil, nil)
	if _, ok := m[common.ChallengeTypeHTTP01]; ok {
		t.Fatalf("expected http-01 verifier to be absent when disabled")
	}
	if _, ok := m[common.ChallengeTypeDNS01]; !ok {
		t.Fatalf("expected dns-01 verifier to be registered")
	}

	// The attestation challenges register as attesting verifiers, never in
	// the plain verifier map: a plain function cannot report the identity the
	// device attested (go-xkms#828).
	m, attesting := buildChallengeMap(config.ACMEChallengesConfig{Enroll01: true, Endorse01: true, DeviceAttest01: true}, config.ACMEResilienceConfig{}, nil, testDeviceAttestVerifier(t))
	for _, challengeType := range []string{common.ChallengeTypeEnroll01, common.ChallengeTypeEndorse01, common.ChallengeTypeDeviceAttest01} {
		if _, ok := attesting[challengeType]; !ok {
			t.Fatalf("expected %s attesting verifier to be registered", challengeType)
		}
		if _, ok := m[challengeType]; ok {
			t.Fatalf("%s must not be registered as a plain verifier function", challengeType)
		}
	}
	if len(m) != 0 {
		t.Fatalf("expected no plain verifiers when only attestation enabled, got %d", len(m))
	}

	// Only the enabled attestation challenges register.
	_, attesting = buildChallengeMap(config.ACMEChallengesConfig{HTTP01: true, Enroll01: true}, config.ACMEResilienceConfig{}, nil, nil)
	if _, ok := attesting[common.ChallengeTypeEnroll01]; !ok || len(attesting) != 1 {
		t.Fatalf("expected only enroll-01 attesting verifier, got %d", len(attesting))
	}

	// The enroll-01 verifier rejects a CA that does not implement the TCG
	// verification surface (a nil/placeholder CA fails the type assertion).
	_, err := attesting[common.ChallengeTypeEnroll01].VerifyAttested(nil, nil, common.AttestationChallenge{
		IdentifierType: common.AuthzTypePermanentIdentifier, IdentifierValue: "device", DialTarget: "device",
		Port: "8080", Token: "tok", KeyAuthorization: "ka",
	})
	if !errors.Is(err, acmesdk.ErrACMEEnrollCAUnsupported) {
		t.Fatalf("enroll-01 with unsupported CA = %v, want ErrACMEEnrollCAUnsupported", err)
	}
}

// TestBuildChallengeMap_AllowPrivateTargets proves
// acme.challenges.allow_private_targets reaches the shared challenge
// client: off (the default), an http-01 target on loopback is refused at
// dial time; on, the same target is validated.
func TestBuildChallengeMap_AllowPrivateTargets(t *testing.T) {
	const keyAuth = "tok.thumbprint"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, keyAuth)
	}))
	defer ts.Close()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("split %s: %v", ts.URL, err)
	}

	refusing, _ := buildChallengeMap(config.ACMEChallengesConfig{HTTP01: true}, config.ACMEResilienceConfig{}, nil, nil)
	err = refusing[common.ChallengeTypeHTTP01](nil, nil, host, port, "tok", keyAuth)
	var verr *validation.Error
	if !errors.As(err, &verr) || verr.Kind != validation.KindTargetRefused {
		t.Fatalf("default http-01 verifier against loopback = %v, want a KindTargetRefused *validation.Error", err)
	}

	allowing, _ := buildChallengeMap(config.ACMEChallengesConfig{HTTP01: true, AllowPrivateTargets: true}, config.ACMEResilienceConfig{}, nil, nil)
	if err := allowing[common.ChallengeTypeHTTP01](nil, nil, host, port, "tok", keyAuth); err != nil {
		t.Fatalf("http-01 verifier with allow_private_targets = %v, want nil", err)
	}
}

// closedLoopbackPort returns a 127.0.0.1 port nothing listens on, so a
// connection to it fails the way an unreachable public target does.
func closedLoopbackPort(t *testing.T) string {
	t.Helper()
	return closedPortOn(t, "127.0.0.1")
}

// closedPortOn returns a port nothing listens on for the given loopback
// host, so a connection to it fails the way an unreachable public target
// does. host lets a test pick a target host distinct from another target in
// the same test (127.0.0.0/8 is entirely loopback on Linux).
func closedPortOn(t *testing.T, host string) string {
	t.Helper()
	listener, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split %s: %v", listener.Addr().String(), err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

// TestBuildChallengeMap_WrapsVerifiersWithBreaker verifies that, given a
// non-nil circuit breaker Manager, buildChallengeMap wraps the http-01 and
// dns-01 verifiers with per-target breaker groups on that Manager, named
// "http01" and "dns01" -- one breaker per validation target rather than one
// breaker shared by every target. This is the regression test for
// go-xkms#1189/#1190: a target whose verifier always fails trips only its
// own breaker, so a different target under the same challenge type still
// reaches the verifier.
func TestBuildChallengeMap_WrapsVerifiersWithBreaker(t *testing.T) {
	breakers := circuitbreaker.NewManager()
	resilience := config.ACMEResilienceConfig{
		HTTP01: config.ACMECircuitBreakerConfig{MaxFailures: 1, ResetTimeoutSeconds: 3600},
		DNS01:  config.ACMECircuitBreakerConfig{MaxFailures: 1, ResetTimeoutSeconds: 3600},
	}

	m, _ := buildChallengeMap(
		config.ACMEChallengesConfig{HTTP01: true, DNS01: true, AllowPrivateTargets: true},
		resilience,
		breakers,
		nil,
	)

	// http01.Verify against a target nothing listens on returns a connection
	// error, which trips "bad.example.com"'s own breaker on the first call.
	port := closedLoopbackPort(t)
	httpVerify, ok := m[common.ChallengeTypeHTTP01]
	if !ok {
		t.Fatalf("expected http-01 verifier to be registered")
	}
	if err := httpVerify(nil, nil, "127.0.0.1", port, "tok", "ka"); err == nil {
		t.Fatalf("http-01 verifier against a closed port = nil, want a connection error")
	}
	if err := httpVerify(nil, nil, "127.0.0.1", port, "tok", "ka"); !errors.Is(err, circuitbreaker.ErrCircuitOpen) {
		t.Fatalf("second http-01 verifier call for the same target = %v, want ErrCircuitOpen", err)
	}

	// dns-01 has no DNS service configured, so every call fails with
	// dns01.ErrDNSServiceNotInitialized -- enough to trip "example.com"'s
	// own dns01 breaker without a real network dependency.
	dnsVerify, ok := m[common.ChallengeTypeDNS01]
	if !ok {
		t.Fatalf("expected dns-01 verifier to be registered")
	}
	if err := dnsVerify(nil, nil, "example.com", "80", "tok", "ka"); err == nil {
		t.Fatalf("dns-01 verifier with no DNS service = nil, want an error")
	}
	if err := dnsVerify(nil, nil, "example.com", "80", "tok", "ka"); !errors.Is(err, circuitbreaker.ErrCircuitOpen) {
		t.Fatalf("second dns-01 verifier call for the same target = %v, want ErrCircuitOpen", err)
	}
}

// TestBuildChallengeMap_BreakerIsolatedPerTarget verifies go-xkms#1189
// directly: an http-01 target that always fails must not stall validation
// for a different, healthy target sharing the same breaker group.
func TestBuildChallengeMap_BreakerIsolatedPerTarget(t *testing.T) {
	const keyAuth = "tok.thumbprint"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, keyAuth)
	}))
	defer ts.Close()
	healthyHost, healthyPort, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("split %s: %v", ts.URL, err)
	}
	// A distinct loopback host from healthyHost (httptest.NewServer always
	// binds 127.0.0.1): breakers are keyed by host, so a same-host,
	// different-port target would share healthyHost's breaker instead of
	// proving isolation between two different targets.
	const failingHost = "127.0.0.2"
	failingPort := closedPortOn(t, failingHost)

	breakers := circuitbreaker.NewManager()
	resilience := config.ACMEResilienceConfig{
		HTTP01: config.ACMECircuitBreakerConfig{MaxFailures: 1, ResetTimeoutSeconds: 3600},
	}
	m, _ := buildChallengeMap(
		config.ACMEChallengesConfig{HTTP01: true, AllowPrivateTargets: true},
		resilience,
		breakers,
		nil,
	)
	verify := m[common.ChallengeTypeHTTP01]

	// The failing target's breaker trips on its first call.
	if err := verify(nil, nil, failingHost, failingPort, "tok", keyAuth); err == nil {
		t.Fatalf("verify against a closed port = nil, want a connection error")
	}
	if err := verify(nil, nil, failingHost, failingPort, "tok", keyAuth); !errors.Is(err, circuitbreaker.ErrCircuitOpen) {
		t.Fatalf("second call for the failing target = %v, want ErrCircuitOpen", err)
	}

	// A different, healthy target must still validate successfully: it is
	// not behind the failing target's now-open breaker.
	if err := verify(nil, nil, healthyHost, healthyPort, "tok", keyAuth); err != nil {
		t.Fatalf("verify against a healthy, different target = %v, want nil", err)
	}
}

// stubRestService implements handlers.RestServicer for router-wiring tests.
// Each handler records whether it was invoked so tests can assert that the
// mux routes requests to the expected endpoint.
type stubRestService struct {
	directoryCalled atomic.Bool
	newNonceCalled  atomic.Bool
	newOrderCalled  atomic.Bool
	healthCalled    atomic.Bool
}

func (s *stubRestService) AccountHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) AuthorizationHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) CABundleHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) CertificateHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) ChallengeHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) HealthHandler(w http.ResponseWriter, _ *http.Request) {
	s.healthCalled.Store(true)
	w.WriteHeader(http.StatusOK)
}

func (s *stubRestService) DirectoryHandler(w http.ResponseWriter, _ *http.Request) {
	s.directoryCalled.Store(true)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"newNonce":   "https://acme.example.com/acme/new-nonce",
		"newAccount": "https://acme.example.com/acme/new-account",
		"newOrder":   "https://acme.example.com/acme/new-order",
		"revokeCert": "https://acme.example.com/acme/revoke-cert",
		"keyChange":  "https://acme.example.com/acme/key-change",
	})
}

func (s *stubRestService) KeyChangeHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) NewAccountHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) NewNonceHandler(w http.ResponseWriter, _ *http.Request) {
	s.newNonceCalled.Store(true)
	w.Header().Set("Replay-Nonce", "test-nonce")
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) NewOrderHandler(w http.ResponseWriter, _ *http.Request) {
	s.newOrderCalled.Store(true)
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) OrderFinalizeHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) OrderHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) OrdersListHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *stubRestService) RevokeCertHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// TenantAuthMiddleware is a pass-through: these router-wiring tests exercise
// route dispatch, not tenant resolution (see tenant_auth_test.go in
// pkg/acme/server/handlers for that).
func (s *stubRestService) TenantAuthMiddleware(next http.Handler) http.Handler {
	return next
}

// Compile-time assertion that stubRestService satisfies handlers.RestServicer.
var _ handlers.RestServicer = (*stubRestService)(nil)

// TestBuildACMERouter_DirectoryEndpoint verifies that buildACMERouter
// produces a gorilla/mux router that dispatches GET /acme/directory to the
// DirectoryHandler and returns a valid ACME directory JSON document. This
// exercises the route wiring without requiring a full CA/storage bootstrap.
func TestBuildACMERouter_DirectoryEndpoint(t *testing.T) {
	svc := &stubRestService{}
	router := buildACMERouter(svc, "/acme", nil, nil)

	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/acme/directory")
	if err != nil {
		t.Fatalf("GET /acme/directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected HTTP 200, got %d: %s", resp.StatusCode, string(body))
	}
	if !svc.directoryCalled.Load() {
		t.Fatalf("DirectoryHandler was not invoked")
	}

	var directory map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&directory); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	for _, field := range []string{"newNonce", "newAccount", "newOrder", "revokeCert", "keyChange"} {
		if _, ok := directory[field]; !ok {
			t.Fatalf("expected %q in directory, got %+v", field, directory)
		}
	}
}

// TestBuildACMERouter_OversizedBodyIs413 verifies buildACMERouter mounts
// acmeserver.RequestBodyMiddleware: a POST body one byte over
// acmeserver.MaxRequestBodySize is refused with 413 and a "malformed"
// problem before the handler runs, while a normal body still reaches it.
func TestBuildACMERouter_OversizedBodyIs413(t *testing.T) {
	svc := &stubRestService{}
	ts := httptest.NewServer(buildACMERouter(svc, "/acme", nil, nil))
	t.Cleanup(ts.Close)

	oversized := strings.Repeat("a", int(acmeserver.MaxRequestBodySize)+1)
	resp, err := http.Post(ts.URL+"/acme/new-order", "application/jose+json", strings.NewReader(oversized))
	if err != nil {
		t.Fatalf("POST /acme/new-order: %v", err)
	}
	var problem entities.Error
	decodeErr := json.NewDecoder(resp.Body).Decode(&problem)
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Fatalf("close response body: %v", closeErr)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected HTTP 413, got %d", resp.StatusCode)
	}
	if decodeErr != nil {
		t.Fatalf("decode problem: %v", decodeErr)
	}
	if problem.Type != "urn:ietf:params:acme:error:"+common.ErrTypeMalformedError {
		t.Fatalf("expected a malformed problem, got %q", problem.Type)
	}
	if svc.newOrderCalled.Load() {
		t.Fatal("an oversized request must not reach NewOrderHandler")
	}

	resp, err = http.Post(ts.URL+"/acme/new-order", "application/jose+json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /acme/new-order: %v", err)
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Fatalf("close response body: %v", closeErr)
	}
	if !svc.newOrderCalled.Load() {
		t.Fatal("a normal-sized request must reach NewOrderHandler")
	}
}

// TestBuildACMERouter_HealthEndpoint verifies that GET /acme/health routes
// to HealthHandler, the resilience status endpoint added for #735.
func TestBuildACMERouter_HealthEndpoint(t *testing.T) {
	svc := &stubRestService{}
	router := buildACMERouter(svc, "/acme", nil, nil)

	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/acme/health")
	if err != nil {
		t.Fatalf("GET /acme/health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected HTTP 200, got %d: %s", resp.StatusCode, string(body))
	}
	if !svc.healthCalled.Load() {
		t.Fatalf("HealthHandler was not invoked")
	}
}

// TestBuildACMERouter_RouteMethods verifies that methods are correctly
// enforced on ACME routes. In particular, GET /acme/new-nonce should
// succeed while GET /acme/new-order should be rejected (POST-only).
func TestBuildACMERouter_RouteMethods(t *testing.T) {
	svc := &stubRestService{}
	router := buildACMERouter(svc, "/acme", nil, nil)
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	// new-nonce accepts GET per RFC 8555.
	resp, err := http.Get(ts.URL + "/acme/new-nonce")
	if err != nil {
		t.Fatalf("GET /acme/new-nonce: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on GET new-nonce, got %d", resp.StatusCode)
	}
	if !svc.newNonceCalled.Load() {
		t.Fatalf("NewNonceHandler was not invoked")
	}

	// new-order requires POST; GET must be rejected.
	resp, err = http.Get(ts.URL + "/acme/new-order")
	if err != nil {
		t.Fatalf("GET /acme/new-order: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET new-order, got %d", resp.StatusCode)
	}
	if svc.newOrderCalled.Load() {
		t.Fatalf("NewOrderHandler should not have been invoked on GET")
	}

	// POST is accepted.
	resp, err = http.Post(ts.URL+"/acme/new-order", "application/jose+json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /acme/new-order: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on POST new-order, got %d", resp.StatusCode)
	}
	if !svc.newOrderCalled.Load() {
		t.Fatalf("NewOrderHandler was not invoked on POST")
	}
}

// TestBuildACMERouter_RateLimit verifies that buildACMERouter enforces the
// rate-limit middleware it is given (go-xkms#882): requests from a single
// client up to the configured cap reach the handler, and the request that
// exceeds the cap is refused with the RFC 8555 Section 6.6 rateLimited
// problem document (HTTP 429, Retry-After, urn:ietf:params:acme:error:
// rateLimited) instead of reaching NewOrderHandler.
func TestBuildACMERouter_RateLimit(t *testing.T) {
	svc := &stubRestService{}
	rateLimitMiddleware := acmeserver.NewClientRateLimiterMiddleware(1, time.Minute, nil)
	router := buildACMERouter(svc, "/acme", rateLimitMiddleware, nil)
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	// First request from this client is within the cap and reaches the handler.
	resp, err := http.Post(ts.URL+"/acme/new-order", "application/jose+json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /acme/new-order (1st): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on the 1st POST new-order, got %d", resp.StatusCode)
	}
	if !svc.newOrderCalled.Load() {
		t.Fatalf("NewOrderHandler was not invoked for the request within the cap")
	}
	svc.newOrderCalled.Store(false)

	// Second request from the same client exceeds the cap.
	resp, err = http.Post(ts.URL+"/acme/new-order", "application/jose+json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /acme/new-order (2nd): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on the 2nd POST new-order, got %d", resp.StatusCode)
	}
	if svc.newOrderCalled.Load() {
		t.Fatalf("NewOrderHandler must not be invoked once the client is rate limited")
	}
	if got := resp.Header.Get("Retry-After"); got != "60" {
		t.Fatalf("expected Retry-After: 60, got %q", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("expected Content-Type: application/problem+json, got %q", got)
	}
	var acmeErr entities.Error
	if err := json.NewDecoder(resp.Body).Decode(&acmeErr); err != nil {
		t.Fatalf("decode rate-limited body: %v", err)
	}
	if acmeErr.Type != "urn:ietf:params:acme:error:rateLimited" {
		t.Fatalf("expected type urn:ietf:params:acme:error:rateLimited, got %q", acmeErr.Type)
	}
}

// TestBuildACMERouter_RateLimit_Disabled verifies the error/edge path: a nil
// rate-limit middleware (acme.rate_limit.enabled=false) mounts the router
// unthrottled, so buildACMERouter itself never silently drops requests when
// no limiter is configured — the enable/disable decision lives entirely in
// startACMEServer, which logs the disabled case loudly.
func TestBuildACMERouter_RateLimit_Disabled(t *testing.T) {
	svc := &stubRestService{}
	router := buildACMERouter(svc, "/acme", nil, nil)
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	for i := 0; i < 5; i++ {
		resp, err := http.Post(ts.URL+"/acme/new-order", "application/jose+json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("POST /acme/new-order (%d): %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204 on request %d with no rate limiter mounted, got %d", i, resp.StatusCode)
		}
	}
}

// TestBuildACMETLSConfig_Success verifies that the TLS builder loads a valid
// dedicated cert/key pair and applies the configured minimum TLS version.
func TestBuildACMETLSConfig_Success(t *testing.T) {
	certPath, keyPath := writeACMETestCertAndKey(t, t.TempDir())

	tlsCfg, err := buildACMETLSConfig(&config.ACMEConfig{
		TLS: config.ACMETLSConfig{
			CertFile:   certPath,
			KeyFile:    keyPath,
			MinVersion: "TLS1.2",
		},
	})
	if err != nil {
		t.Fatalf("buildACMETLSConfig() error = %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("tlsCfg.Certificates = %d entries, want 1", len(tlsCfg.Certificates))
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("tlsCfg.MinVersion = %#x, want TLS1.2", tlsCfg.MinVersion)
	}
}

// TestBuildACMETLSConfig_MissingCertFile verifies that the TLS builder
// fails when the configured certificate file does not exist, rather than
// silently starting the listener without TLS material.
func TestBuildACMETLSConfig_MissingCertFile(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writeACMETestCertAndKey(t, dir)

	_, err := buildACMETLSConfig(&config.ACMEConfig{
		TLS: config.ACMETLSConfig{
			CertFile: filepath.Join(dir, "does-not-exist.pem"),
			KeyFile:  keyPath,
		},
	})
	if err == nil {
		t.Fatal("expected error for a missing certificate file")
	}
}

// writeACMETestCertAndKey writes a self-signed ECDSA certificate and private
// key to PEM files inside dir, returning their paths.
func writeACMETestCertAndKey(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("writeACMETestCertAndKey: ecdsa.GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "acme.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"acme.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("writeACMETestCertAndKey: CreateCertificate: %v", err)
	}

	certPath = filepath.Join(dir, "acme-cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writeACMETestCertAndKey: WriteFile cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("writeACMETestCertAndKey: MarshalECPrivateKey: %v", err)
	}

	keyPath = filepath.Join(dir, "acme-key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writeACMETestCertAndKey: WriteFile key: %v", err)
	}

	return certPath, keyPath
}

// TestBuildACMETLSConfig_RejectsUnparseableClientCA proves that a
// client_cas file with no PEM certificate blocks fails with the typed
// ErrACMENoClientCAPEM sentinel, reachable with errors.Is, rather than an
// inline error (#700).
func TestBuildACMETLSConfig_RejectsUnparseableClientCA(t *testing.T) {
	dir := t.TempDir()

	certFile, keyFile := writeTestCertKeyPair(t, dir)

	garbageCA := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(garbageCA, []byte("not a PEM certificate"), 0o600); err != nil {
		t.Fatalf("write garbage client CA: %v", err)
	}

	_, err := buildACMETLSConfig(&config.ACMEConfig{
		TLS: config.ACMETLSConfig{
			CertFile:   certFile,
			KeyFile:    keyFile,
			ClientAuth: "require_and_verify",
			ClientCAs:  []string{garbageCA},
		},
	})
	if err == nil {
		t.Fatal("expected error for a client CA file with no PEM certificates")
	}
	if !errors.Is(err, ErrACMENoClientCAPEM) {
		t.Errorf("err = %v, want errors.Is match against ErrACMENoClientCAPEM", err)
	}
}

// writeTestCertKeyPair writes a minimal self-signed certificate and its
// private key, PEM-encoded, under dir, and returns their paths.
func writeTestCertKeyPair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "acme-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certFile, keyFile
}

// TestBuildClusterPreSignHooks_GatedOff verifies that the SPIFFE URI-SAN hook
// registry is nil when cluster ACME enrollment is not enabled, so ordinary ACME
// issuance registers no cluster-specific pre-sign extensions.
func TestBuildClusterPreSignHooks_GatedOff(t *testing.T) {
	// Cluster disabled entirely.
	got, err := buildClusterPreSignHooks(&config.Config{})
	if err != nil || got != nil {
		t.Errorf("cluster disabled: got %v, %v, want nil, nil", got, err)
	}
	// Cluster enabled but ACME enrollment off.
	cfg := &config.Config{Cluster: config.ClusterConfig{Enabled: true}}
	got, err = buildClusterPreSignHooks(cfg)
	if err != nil || got != nil {
		t.Errorf("ACME enrollment off: got %v, %v, want nil, nil", got, err)
	}
}

// clusterACMEConfig is a cluster with ACME enrollment on and two members.
func clusterACMEConfig() *config.Config {
	return &config.Config{Cluster: config.ClusterConfig{
		Enabled: true,
		Peers:   "1=10.0.0.1:8301,2=10.0.0.2:8301",
		RaftEnrollment: config.RaftEnrollmentConfig{
			TrustDomain: "cluster.example.org",
			ACME:        config.RaftACMEEnrollmentConfig{Enabled: true},
		},
	}}
}

// TestBuildClusterPreSignHooks_Enabled verifies that enabling cluster ACME
// enrollment registers exactly one pre-sign hook (the SPIFFE URI-SAN hook).
func TestBuildClusterPreSignHooks_Enabled(t *testing.T) {
	registry, err := buildClusterPreSignHooks(clusterACMEConfig())
	if err != nil {
		t.Fatalf("buildClusterPreSignHooks: %v", err)
	}
	if registry == nil {
		t.Fatal("expected a non-nil pre-sign hook registry")
	}
	if got := registry.Count(); got != 1 {
		t.Errorf("registry.Count() = %d, want 1", got)
	}
}

// TestBuildClusterPreSignHooks_MalformedPeersRefused verifies a cluster.peers
// the membership cannot be read from fails ACME start-up rather than leaving
// the hook with no members to stamp.
func TestBuildClusterPreSignHooks_MalformedPeersRefused(t *testing.T) {
	cfg := clusterACMEConfig()
	cfg.Cluster.Peers = "not-a-peer"
	registry, err := buildClusterPreSignHooks(cfg)
	if err == nil {
		t.Fatal("expected an error for a malformed cluster.peers")
	}
	if registry != nil {
		t.Errorf("registry = %v, want nil on error", registry)
	}
}

// TestBuildClusterPreSignHooks_StampsEnrolledMembersOnly executes the
// registered SPIFFE URI-SAN hook against synthetic TCG-CSR-IDEVID orders and
// proves it embeds spiffe://<trustDomain>/node/<raftAddr> for a cluster.peers
// member enroll-01 validated, and nothing for any other order.
func TestBuildClusterPreSignHooks_StampsEnrolledMembersOnly(t *testing.T) {
	registry, err := buildClusterPreSignHooks(clusterACMEConfig())
	if err != nil {
		t.Fatalf("buildClusterPreSignHooks: %v", err)
	}

	orderFor := func(permanentID string) *entities.ACMEOrder {
		return &entities.ACMEOrder{
			Identifiers: []entities.ACMEIdentifier{
				{Type: common.AuthzTypePermanentIdentifier, Value: permanentID},
			},
		}
	}
	enrolled := []string{common.ChallengeTypeEnroll01}

	exts, err := registry.Execute(&handlers.OrderPreSignHookContext{
		Context:             context.Background(),
		Order:               orderFor("10.0.0.2:8301"),
		IsTCGCSR:            true,
		ValidatedChallenges: enrolled,
	})
	if err != nil {
		t.Fatalf("registry.Execute: %v", err)
	}
	if len(exts) != 1 {
		t.Fatalf("registry.Execute returned %d extensions, want 1", len(exts))
	}
	wantURI := "spiffe://cluster.example.org/node/10.0.0.2:8301"
	if !strings.Contains(string(exts[0].Value), wantURI) {
		t.Errorf("extension value = %x, want it to embed URI %q", exts[0].Value, wantURI)
	}

	refused := []struct {
		name string
		ctx  *handlers.OrderPreSignHookContext
	}{
		{"non-member", &handlers.OrderPreSignHookContext{
			Order: orderFor("10.0.0.9:8301"), IsTCGCSR: true, ValidatedChallenges: enrolled,
		}},
		{"member host on another port", &handlers.OrderPreSignHookContext{
			Order: orderFor("10.0.0.2:9999"), IsTCGCSR: true, ValidatedChallenges: enrolled,
		}},
		{"endorse-01", &handlers.OrderPreSignHookContext{
			Order: orderFor("10.0.0.2:8301"), IsTCGCSR: true,
			ValidatedChallenges: []string{common.ChallengeTypeEndorse01},
		}},
		{"standard CSR", &handlers.OrderPreSignHookContext{
			Order: orderFor("10.0.0.2:8301"), IsTCGCSR: false, ValidatedChallenges: enrolled,
		}},
	}
	for _, tt := range refused {
		tt.ctx.Context = context.Background()
		exts, err := registry.Execute(tt.ctx)
		if err != nil {
			t.Fatalf("%s: registry.Execute: %v", tt.name, err)
		}
		if len(exts) != 0 {
			t.Errorf("%s: registry.Execute returned %d extensions, want 0", tt.name, len(exts))
		}
	}
}

// TestBuildACMERouter_CertificateRouteMatchesHexSerials pins the
// certificate route to the ID form order finalize actually issues: the
// serial number in hexadecimal (cert.SerialNumber.Text(16)). A decimal-only
// route answered an un-routed 404 for every serial containing a-f, which
// is most 128-bit random serials (go-xkms#1125).
func TestBuildACMERouter_CertificateRouteMatchesHexSerials(t *testing.T) {
	ts := httptest.NewServer(buildACMERouter(&stubRestService{}, "/acme", nil, nil))
	t.Cleanup(ts.Close)

	tests := []struct {
		name string
		id   string
		want int
	}{
		{name: "lower-case hex serial", id: "3f9a0c7be21d44", want: http.StatusNoContent},
		{name: "upper-case hex serial", id: "3F9A0C7BE21D44", want: http.StatusNoContent},
		{name: "all-digit serial", id: "1234567890", want: http.StatusNoContent},
		{name: "non-hex id is not routed", id: "xyz-not-hex", want: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Post(ts.URL+"/acme/cert/"+tt.id, "application/jose+json", nil)
			if err != nil {
				t.Fatalf("POST /acme/cert/%s: %v", tt.id, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tt.want {
				t.Fatalf("POST /acme/cert/%s: status %d, want %d", tt.id, resp.StatusCode, tt.want)
			}
		})
	}
}

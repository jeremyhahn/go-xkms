// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package rest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// assertAuditUnavailableErr is the sentinel used by failingAuthAuditLogger in
// every test in this file, so the assertion on writeErr wrapping stays
// identical across success/deny/logout scenarios.
var assertAuditUnavailableErr = errors.New("audit backend unavailable")

// mockAuthAuditLogger records every audit event it receives.
type mockAuthAuditLogger struct {
	mu     sync.Mutex
	events []*audit.Event
}

func (m *mockAuthAuditLogger) Log(_ context.Context, event *audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockAuthAuditLogger) Close() error { return nil }

func (m *mockAuthAuditLogger) Events() []*audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*audit.Event, len(m.events))
	copy(cp, m.events)
	return cp
}

// failingAuthAuditLogger always fails to persist, so the REST auth
// write-failure handling can be exercised without a real backend.
type failingAuthAuditLogger struct {
	err error
}

func (f *failingAuthAuditLogger) Log(_ context.Context, _ *audit.Event) error {
	return f.err
}

func (f *failingAuthAuditLogger) Close() error { return nil }

var _ audit.Logger = (*mockAuthAuditLogger)(nil)
var _ audit.Logger = (*failingAuthAuditLogger)(nil)

// =============================================================================
// auth.login.piv
// =============================================================================

func TestPIVLogin_EmitsAuditEvent_OnSuccess(t *testing.T) {
	auditLog := &mockAuthAuditLogger{}
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true, AllowUnattested: true}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{
			Username: "alice", Role: "admin", TenantID: "system", Enabled: true,
		}}
		c.AuditLogger = auditLog
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequest(cert))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	events := auditLog.Events()
	require.NotEmpty(t, events)
	last := events[len(events)-1]
	assert.Equal(t, "auth.login.piv", last.Action)
	assert.Equal(t, audit.OutcomeAllow, last.Outcome)
	assert.Equal(t, "alice", last.Subject)
}

func TestPIVLogin_AuditWriteFailure_FailsLoginAndReturnsNoToken(t *testing.T) {
	auditErr := assertAuditUnavailableErr
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true, AllowUnattested: true}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{
			Username: "alice", Role: "admin", TenantID: "system", Enabled: true,
		}}
		c.AuditLogger = &failingAuthAuditLogger{err: auditErr}
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequest(cert))
	require.Equal(t, http.StatusInternalServerError, w.Code,
		"a failed audit write on a successful login must refuse the request rather than hand back an unaudited session")

	var resp authTokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Empty(t, resp.AccessToken, "no token must be returned to the caller when its grant could not be audited")
}

func TestPIVLogin_DenyOutcome_IsStillAudited(t *testing.T) {
	auditLog := &mockAuthAuditLogger{}
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true, AllowUnattested: true}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{Username: "alice", Enabled: false}}
		c.AuditLogger = auditLog
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequest(cert))
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	events := auditLog.Events()
	require.NotEmpty(t, events)
	last := events[len(events)-1]
	assert.Equal(t, "auth.login.piv", last.Action)
	assert.Equal(t, audit.OutcomeDeny, last.Outcome)
}

func TestPIVLogin_DenyOutcome_AuditWriteFailure_Returns500(t *testing.T) {
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true, AllowUnattested: true}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{Username: "alice", Enabled: false}}
		c.AuditLogger = &failingAuthAuditLogger{err: assertAuditUnavailableErr}
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequest(cert))
	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"an unaudited refusal must not be reported as a normal 401")
}

// =============================================================================
// auth.logout
// =============================================================================

func TestAuthLogout_EmitsAuditEvent_OnSuccess(t *testing.T) {
	auditLog := &mockAuthAuditLogger{}
	server := newAuthTestServer(t, func(c *Config) {
		c.AuditLogger = auditLog
	})

	pair, err := server.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "alice"})
	require.NoError(t, err)

	body, _ := json.Marshal(authRefreshRequest{RefreshToken: pair.RefreshToken})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(body))
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{Subject: "alice"}))

	w := httptest.NewRecorder()
	server.handleAuthLogout(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)

	events := auditLog.Events()
	require.NotEmpty(t, events)
	last := events[len(events)-1]
	assert.Equal(t, "auth.logout", last.Action)
	assert.Equal(t, audit.OutcomeAllow, last.Outcome)
	assert.Equal(t, "alice", last.Subject)
}

func TestAuthLogout_AuditWriteFailure_FailsLogout(t *testing.T) {
	server := newAuthTestServer(t, func(c *Config) {
		c.AuditLogger = &failingAuthAuditLogger{err: assertAuditUnavailableErr}
	})

	pair, err := server.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "alice"})
	require.NoError(t, err)

	body, _ := json.Marshal(authRefreshRequest{RefreshToken: pair.RefreshToken})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(body))
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{Subject: "alice"}))

	w := httptest.NewRecorder()
	server.handleAuthLogout(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code,
		"a failed audit write must fail the logout response even though the token was already revoked")
}

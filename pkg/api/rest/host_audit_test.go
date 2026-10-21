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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// hostPIVLoginRefused builds a host surface through NewHostServer whose only
// user is bound to a PIV certificate but permits only WebAuthn, then attempts
// a PIV login with that certificate and returns the response code. The
// refusal is the method-not-permitted path of handlePIVLogin.
func hostPIVLoginRefused(t *testing.T, auditLogger qrdbsdk.NodeAuditLogger) int {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	client, ft := newFakeQRDBClient(t)
	ctx := context.Background()
	user, err := ft.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username:             "alice",
		TenantID:             "system",
		WithoutEmailLoginKey: true,
	})
	require.NoError(t, err)
	// The fake hands back its stored record; the policy is set on it
	// directly because the fake's CreateUser carries no AuthMethods.
	user.AuthMethods = []string{"webauthn"}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)
	_, err = ft.AddCertBinding(ctx, user.ID, qrdbsdk.ComputeSPKIThumbprint(cert), 0)
	require.NoError(t, err)

	srv, err := NewHostServer(ctx, &HostConfig{
		XKMSService: svc,
		QRDBClient:  client,
		PIVLogin:    &PIVLoginOptions{Enabled: true, AllowUnattested: true},
		AuditLogger: auditLogger,
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, pivRequest(cert))
	return w.Code
}

// TestNewHostServer_AuditLoggerRecordsRefusal proves a host-supplied audit
// logger receives the refusal reason a hosted module would otherwise
// discard (go-xkms#1618).
func TestNewHostServer_AuditLoggerRecordsRefusal(t *testing.T) {
	auditLog := &mockAuthAuditLogger{}
	code := hostPIVLoginRefused(t, auditLog)
	assert.Equal(t, http.StatusUnauthorized, code)

	events := auditLog.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "auth.login.piv", events[0].Action)
	assert.Equal(t, audit.OutcomeDeny, events[0].Outcome)
	assert.Equal(t, "alice", events[0].Subject)
	assert.Equal(t, "method not permitted", events[0].Details["reason"])
}

// TestNewHostServer_NilAuditLoggerStillServes proves the nil default keeps
// today's behaviour: the same refusal is answered, with no audit sink.
func TestNewHostServer_NilAuditLoggerStillServes(t *testing.T) {
	assert.Equal(t, http.StatusUnauthorized, hostPIVLoginRefused(t, nil))
}

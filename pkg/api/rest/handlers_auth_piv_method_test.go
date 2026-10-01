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


package rest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// pivLoginAs performs a PIV login as an account with the given permitted
// authentication methods.
func pivLoginAs(t *testing.T, methods []string) (int, *mockAuthAuditLogger) {
	t.Helper()
	auditLog := &mockAuthAuditLogger{}
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true, AllowUnattested: true}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{
			Username: "alice", Roles: []string{"admin"}, TenantID: "system", Enabled: true,
			AuthMethods: methods,
		}}
		c.AuditLogger = auditLog
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	w := doAuthRequest(t, server, pivRequest(generateTestCertificate(t, key)))
	return w.Code, auditLog
}

// TestPIVLogin_EnforcesThePermittedMethodPolicy proves the PIV login, the
// issuer of the session tokens qrdb's chain accepts with an unobservable
// method, enforces the account's permitted-method policy when it mints:
// an account that may not log in with a certificate gets no token.
func TestPIVLogin_EnforcesThePermittedMethodPolicy(t *testing.T) {
	code, auditLog := pivLoginAs(t, []string{"webauthn"})
	assert.Equal(t, http.StatusUnauthorized, code)
	events := auditLog.Events()
	require.NotEmpty(t, events)
	assert.Equal(t, audit.OutcomeDeny, events[len(events)-1].Outcome)

	code, _ = pivLoginAs(t, []string{"webauthn", "mtls"})
	assert.Equal(t, http.StatusOK, code, "a policy that permits certificate login mints")

	code, _ = pivLoginAs(t, nil)
	assert.Equal(t, http.StatusOK, code, "an empty policy states no restriction")
}

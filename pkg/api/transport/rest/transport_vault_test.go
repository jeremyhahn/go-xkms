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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
)

// vaultRoutes are the personal-vault routes as the server's route table
// registers them, with the handler each is served by.
var vaultRoutes = []struct {
	method, pattern string
	handler         func(*restapi.PasswordHandlers) http.HandlerFunc
}{
	{http.MethodPost, "/api/v1/passwords/unlock", func(h *restapi.PasswordHandlers) http.HandlerFunc { return h.UnlockHandler }},
	{http.MethodPost, "/api/v1/passwords/lock", func(h *restapi.PasswordHandlers) http.HandlerFunc { return h.LockHandler }},
	{http.MethodGet, wire.PasswordVaultPath, func(h *restapi.PasswordHandlers) http.HandlerFunc { return h.VaultStatusHandler }},
	{http.MethodPost, wire.PasswordVaultFactorsPath, func(h *restapi.PasswordHandlers) http.HandlerFunc { return h.VaultEnrollHandler }},
	{http.MethodPut, wire.PasswordVaultFactorsPath + "/{id}", func(h *restapi.PasswordHandlers) http.HandlerFunc { return h.VaultRotateHandler }},
	{http.MethodDelete, wire.PasswordVaultFactorsPath + "/{id}", func(h *restapi.PasswordHandlers) http.HandlerFunc { return h.VaultRemoveFactorHandler }},
	{http.MethodPost, wire.PasswordVaultRecoverPath, func(h *restapi.PasswordHandlers) http.HandlerFunc { return h.VaultRecoverHandler }},
}

// newVaultServer serves the real password handlers over a real XKMSService
// (vaultservice) as the authenticated user subject, and returns a transport
// connected to it.
func newVaultServer(t *testing.T, subject string) *Transport {
	t.Helper()
	handlers := restapi.NewPasswordHandlers(vaultservice.New(t).Service)
	identity := &auth.Identity{Subject: subject, TenantID: vaultservice.Tenant}

	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), identity)))
		})
	})
	router.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"status": "ok"}))
	})
	for _, route := range vaultRoutes {
		router.Method(route.method, route.pattern, route.handler(handlers))
	}

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return connectFullMock(t, srv)
}

// TestPasswordVault_RoutesMatchTheServer proves the paths this transport
// calls are the ones the server's route table registers.
func TestPasswordVault_RoutesMatchTheServer(t *testing.T) {
	registered := map[string]bool{}
	for _, spec := range restapi.Routes() {
		registered[spec.Method+" "+spec.Pattern] = true
	}
	for _, route := range vaultRoutes {
		assert.True(t, registered[route.method+" "+route.pattern], "%s %s is not registered", route.method, route.pattern)
	}
}

// TestPasswordVault_Lifecycle drives the whole vault lifecycle through this
// transport, the REST handlers and the real service.
func TestPasswordVault_Lifecycle(t *testing.T) {
	tr := newVaultServer(t, "alice")
	vaulttest.RunLifecycle(t, context.Background(), tr)
}

// TestPasswordVault_ServerErrorsReachTheCaller proves a refusal carries the
// server's reason to the caller.
func TestPasswordVault_ServerErrorsReachTheCaller(t *testing.T) {
	tr := newVaultServer(t, "alice")
	ctx := context.Background()

	err := tr.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: "f"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "No vault factor is enrolled")

	_, err = tr.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: vaulttest.Passkey("first")})
	require.NoError(t, err)
	err = tr.PasswordVaultRemoveFactor(ctx, &transport.PasswordVaultRemoveFactorRequest{FactorID: "no-such-factor"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Vault factor not found")
}

func TestPasswordVault_NotConnected(t *testing.T) {
	for name, call := range vaulttest.Calls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}

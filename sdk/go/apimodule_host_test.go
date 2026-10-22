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

package xkms

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/hostdeps"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestServiceModule_HostCompositionThroughSDK mounts the module the way a
// downstream host does -- through this SDK's re-exports only -- and proves
// the options reach the composition: the supplied CA turns its feature on,
// and the dependencies left out (the platform sealer, and the TPM2 backend
// the TPM policy service needs) are reported as typed
// ServiceModuleFeatureDisabledErrors.
func TestServiceModule_HostCompositionThroughSDK(t *testing.T) {
	svc := hostdeps.NewService(t)
	// The host's own node: a real in-memory standalone qrdb node, which
	// serves the database the CA keeps its certificates in.
	cfg := &config.Config{Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()}}
	ds, err := datastore.Open(context.Background(), cfg, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ds.Close()) })
	client := ds.Client()

	module, err := NewServiceModule(func() *pkgxkms.XKMSService { return svc },
		WithServiceModuleQRDBClient(func() *qrdbsdk.Client { return client }),
		WithServiceModulePINBackend(hostdeps.NewPINBackend(t, "so-pin-123456", "user-pin-654321")),
		WithServiceModuleCredentialStrategy("manual"),
		WithServiceModuleCA(hostdeps.NewCAConfig("SDK Host Root")),
	)
	require.NoError(t, err)
	assert.Nil(t, module.HostStores(), "nothing composes before first use")

	var handler http.HandlerFunc
	registrar := qrdbsdk.NewModuleHTTPRegistrar(chi.NewRouter(),
		func(method, pattern string, _ qrdbsdk.Permission, h http.HandlerFunc) {
			if method == http.MethodGet && pattern == "/api/v1/ca/certificate" {
				handler = h
			}
		},
		func(string, string, http.HandlerFunc) {},
		func(string, string, http.HandlerFunc) {})
	module.RegisterHTTP(registrar)
	require.NotNil(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificate", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(),
		&auth.Identity{Subject: "admin", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"admin"}}))
	w := httptest.NewRecorder()
	handler(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "SDK Host Root")

	stores := module.HostStores()
	require.NotNil(t, stores)
	assert.NotNil(t, stores.CA)
	assert.Nil(t, stores.TPMPolicies)
	assert.NotNil(t, stores.PIN)

	var off []ServiceModuleFeature
	for _, reason := range stores.Disabled {
		var disabled *ServiceModuleFeatureDisabledError
		require.True(t, errors.As(reason, &disabled), "untyped reason: %v", reason)
		off = append(off, disabled.Feature)
	}
	assert.ElementsMatch(t, []ServiceModuleFeature{
		ServiceModuleFeatureTenantPasswords,
		ServiceModuleFeaturePlatformStore,
		ServiceModuleFeatureTPMPolicies,
		// The test host supplies no barrier registry, which OIDC
		// credentials need.
		ServiceModuleFeatureOIDCCredentials,
	}, off)
}

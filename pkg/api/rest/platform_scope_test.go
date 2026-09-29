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
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// REST side of go-xkms#1226 and #1227: every platform-global route is refused
// to a tenant-local Admin with the tenant binding's not-found answer, and
// still served to the platform identity.

const platformScopeREST = "pkcs11-pin"

// platformScopeRoute is one platform-global REST route.
type platformScopeRoute struct {
	method string
	path   string
	body   string
}

// platformScopeRoutes is every REST route #1226 and #1227 name, with a body
// that passes each handler's own request validation.
var platformScopeRoutes = map[string]platformScopeRoute{
	"platform put":       {http.MethodPut, "/platform/secrets/" + platformScopeREST, `{"secret":"` + base64.StdEncoding.EncodeToString([]byte("overwritten")) + `"}`},
	"platform get":       {http.MethodGet, "/platform/secrets/" + platformScopeREST, ""},
	"platform delete":    {http.MethodDelete, "/platform/secrets/" + platformScopeREST, ""},
	"platform list":      {http.MethodGet, "/platform/secrets", ""},
	"platform reseal":    {http.MethodPost, "/platform/secrets/" + platformScopeREST + "/reseal", ""},
	"platform status":    {http.MethodGet, "/platform/status", ""},
	"credentials submit": {http.MethodPost, "/credentials/submit", `{"name":"pkcs11-pin","value":"c2VjcmV0"}`},
	"credentials list":   {http.MethodGet, "/credentials/", ""},

	"barrier initialize":        {http.MethodPost, "/barrier/initialize", `{"password_b64":"` + base64.StdEncoding.EncodeToString([]byte("passphrase")) + `"}`},
	"barrier unseal":            {http.MethodPost, "/barrier/unseal", `{"password_b64":"` + base64.StdEncoding.EncodeToString([]byte("passphrase")) + `"}`},
	"barrier seal":              {http.MethodPost, "/barrier/seal", ""},
	"barrier status":            {http.MethodGet, "/barrier/status", ""},
	"barrier shamir initialize": {http.MethodPost, "/barrier/shamir/initialize", `{"secret":"passphrase"}`},
	"barrier unseal share":      {http.MethodPost, "/barrier/shamir/unseal-share", `{"share":"s"}`},
	"barrier unseal shares":     {http.MethodPost, "/barrier/shamir/unseal-shares", `{"shares":["a","b"]}`},
	"barrier rekey":             {http.MethodPost, "/barrier/rekey", `{"threshold":2,"total":3}`},
	"barrier recovery generate": {http.MethodPost, "/barrier/recovery/generate", `{"threshold":2,"total":3}`},
	"barrier recovery recover":  {http.MethodPost, "/barrier/recovery/recover", `{"keys":["a","b"]}`},
	"barrier recovery delete":   {http.MethodDelete, "/barrier/recovery/keys", ""},
	"barrier root token":        {http.MethodPost, "/barrier/recovery/root-token", `{"shares":["a","b"]}`},

	"pin so set":        {http.MethodPost, "/pin/so/set", `{"current_so_pin":"so-pin-123456","new_so_pin":"so-pin-654321"}`},
	"pin user set":      {http.MethodPost, "/pin/user/set", `{"so_pin":"so-pin-123456","new_user_pin":"user-pin-654321"}`},
	"pin so change":     {http.MethodPost, "/pin/so/change", `{"current_so_pin":"so-pin-123456","new_so_pin":"so-pin-654321"}`},
	"pin user change":   {http.MethodPost, "/pin/user/change", `{"current_user_pin":"user-pin-123456","new_user_pin":"user-pin-654321"}`},
	"pin so verify":     {http.MethodPost, "/pin/so/verify", `{"pin":"so-pin-123456"}`},
	"pin user verify":   {http.MethodPost, "/pin/user/verify", `{"pin":"user-pin-123456"}`},
	"pin lockout":       {http.MethodGet, "/pin/lockout", ""},
	"pin lockout reset": {http.MethodPost, "/pin/lockout/reset", `{"so_pin":"so-pin-123456"}`},

	"piv list":        {http.MethodGet, "/piv/slots?backend=software", ""},
	"piv get cert":    {http.MethodGet, "/piv/slots/9a/certificate?backend=software&format=pem", ""},
	"piv store cert":  {http.MethodPost, "/piv/slots/9a/certificate", `{"backend":"software","certificate":"eA==","format":"pem"}`},
	"piv delete cert": {http.MethodDelete, "/piv/slots/9a/certificate?backend=software", ""},
	"piv generate":    {http.MethodPost, "/piv/slots/9a/generate", `{"backend":"software","algorithm":"ecdsap256","subject":"server"}`},
	"piv import":      {http.MethodPost, "/piv/slots/9a/import", `{"backend":"software","certificate":"eA==","format":"pem"}`},
	"piv export":      {http.MethodGet, "/piv/slots/9a/export?backend=software&format=pem", ""},
	"piv csr":         {http.MethodPost, "/piv/slots/9a/csr", `{"backend":"software","subject":"server"}`},

	"tenant tpm mode get": {http.MethodGet, "/tenants/tenant-b/tpm", ""},
	"tenant tpm mode set": {http.MethodPut, "/tenants/tenant-b/tpm", `{"mode":"none"}`},
	"tenant vtpm status":  {http.MethodGet, "/tenants/tenant-b/tpm/vtpm", ""},
	"tenant vtpm start":   {http.MethodPost, "/tenants/tenant-b/tpm/vtpm/start", ""},
	"tenant vtpm stop":    {http.MethodPost, "/tenants/tenant-b/tpm/vtpm/stop", ""},
}

// newPlatformScopeService returns an XKMSService composed with the
// platform-global state behind the routes: an unsealed system barrier, a PIN
// backend with both PINs set, a platform store holding one credential, a TPM
// policy service (whose tenant TPM mode and vTPM routes are platform-scoped)
// and a manual credential service.
func newPlatformScopeService(t *testing.T) *xkms.XKMSService {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	barrier, err := seal.NewBarrier(logger, storage.NewMemory(), seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	creds := seal.MustCredentials([]byte("passphrase"))
	defer creds.Secret.Destroy()
	require.NoError(t, barrier.Initialize(ctx, creds))
	if barrier.IsSealed() {
		require.NoError(t, barrier.Unseal(ctx, creds))
	}

	hashCfg := qrdbsdk.DefaultHashConfig()
	hashCfg.Time, hashCfg.Memory, hashCfg.Threads = 1, 8*1024, 1
	pins, err := qrdbsdk.NewSoftwareBackend(nil, hashCfg)
	require.NoError(t, err)
	require.NoError(t, pins.SetSOPIN("", "so-pin-123456"))
	require.NoError(t, pins.SetUserPIN("so-pin-123456", "user-pin-123456"))

	store, err := seal.NewPlatformStore(storage.NewMemory(), logger)
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, platformScopeREST, []byte("platform-secret")))

	policies, _ := tpmpolicytest.NewOffline(t)

	credSvc, err := credentialspkg.New(&credentialspkg.Config{Strategy: credentialspkg.StrategyManual}, nil, nil, logger)
	require.NoError(t, err)

	svc := &xkms.XKMSService{}
	svc.SetBarrier(barrier)
	svc.SetPINManager(pins)
	svc.SetPlatformStore(store)
	svc.SetTPMPolicyService(policies)
	svc.SetCredentialService(credSvc)
	return svc
}

// platformScopeRouter mounts every platform-global route over svc, exactly
// as NewServer wires them, with identity injected into each request's
// context.
func platformScopeRouter(t *testing.T, svc *xkms.XKMSService, identity *auth.Identity) http.Handler {
	t.Helper()
	h := NewHandlerContext("test")
	h.SetXKMSService(svc)
	platform := NewSealStoreHandlers(svc)
	tpm := NewTPMPolicyHandlers(svc)
	creds := NewCredentialHandlers(svc, nil)

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(auth.WithIdentity(req.Context(), identity)))
		})
	})
	r.Put("/platform/secrets/{name}", platform.PutSecretHandler)
	r.Get("/platform/secrets/{name}", platform.GetSecretHandler)
	r.Delete("/platform/secrets/{name}", platform.DeleteSecretHandler)
	r.Get("/platform/secrets", platform.ListSecretsHandler)
	r.Post("/platform/secrets/{name}/reseal", platform.ResealSecretHandler)
	r.Get("/platform/status", platform.StatusHandler)
	r.Post("/credentials/submit", creds.HandleSubmit)
	r.Get("/credentials/", creds.HandleList)

	r.Post("/barrier/initialize", h.BarrierInitializeHandler)
	r.Post("/barrier/unseal", h.BarrierUnsealHandler)
	r.Post("/barrier/seal", h.BarrierSealHandler)
	r.Get("/barrier/status", h.BarrierStatusHandler)
	r.Post("/barrier/shamir/initialize", h.BarrierInitializeShamirHandler)
	r.Post("/barrier/shamir/unseal-share", h.BarrierUnsealShareHandler)
	r.Post("/barrier/shamir/unseal-shares", h.BarrierUnsealSharesHandler)
	r.Post("/barrier/rekey", h.BarrierRekeyHandler)
	r.Post("/barrier/recovery/generate", h.BarrierGenerateRecoveryKeysHandler)
	r.Post("/barrier/recovery/recover", h.BarrierRecoverWithKeysHandler)
	r.Delete("/barrier/recovery/keys", h.BarrierDeleteRecoveryKeysHandler)
	r.Post("/barrier/recovery/root-token", h.BarrierGenerateRootTokenHandler)

	r.Post("/pin/so/set", h.SetSOPINHandler)
	r.Post("/pin/user/set", h.SetUserPINHandler)
	r.Post("/pin/so/change", h.ChangeSOPINHandler)
	r.Post("/pin/user/change", h.ChangeUserPINHandler)
	r.Post("/pin/so/verify", h.VerifySOPINHandler)
	r.Post("/pin/user/verify", h.VerifyUserPINHandler)
	r.Get("/pin/lockout", h.GetLockoutStatusHandler)
	r.Post("/pin/lockout/reset", h.ResetLockoutHandler)

	r.Get("/piv/slots", h.ListPIVSlotsHandler)
	r.Get("/piv/slots/{slot}/certificate", h.GetPIVCertificateHandler)
	r.Post("/piv/slots/{slot}/certificate", h.StorePIVCertificateHandler)
	r.Delete("/piv/slots/{slot}/certificate", h.DeletePIVCertificateHandler)
	r.Post("/piv/slots/{slot}/generate", h.GeneratePIVKeyHandler)
	r.Post("/piv/slots/{slot}/import", h.ImportPIVCertificateHandler)
	r.Get("/piv/slots/{slot}/export", h.ExportPIVCertificateHandler)
	r.Post("/piv/slots/{slot}/csr", h.GeneratePIVCSRHandler)

	r.Get("/tenants/{tenantID}/tpm", tpm.GetTenantModeHandler)
	r.Put("/tenants/{tenantID}/tpm", tpm.SetTenantModeHandler)
	r.Get("/tenants/{tenantID}/tpm/vtpm", tpm.VTPMStatusHandler)
	r.Post("/tenants/{tenantID}/tpm/vtpm/start", tpm.VTPMStartHandler)
	r.Post("/tenants/{tenantID}/tpm/vtpm/stop", tpm.VTPMStopHandler)
	return r
}

func servePlatformScope(t *testing.T, h http.Handler, route platformScopeRoute) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if route.body != "" {
		body = strings.NewReader(route.body)
	}
	req := httptest.NewRequest(route.method, route.path, body)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

var (
	platformScopeTenantAdmin = &auth.Identity{Subject: "admin@tenant-a", TenantID: "tenant-a", Roles: []string{"admin"}}
	platformScopeSystemAdmin = &auth.Identity{Subject: "so@example.com", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"admin"}}
)

// TestPlatformScopeREST_TenantAdminRefused: each route answers a tenant Admin
// with 404 and the unknown-tenant message, exactly as a genuine miss reads.
func TestPlatformScopeREST_TenantAdminRefused(t *testing.T) {
	svc := newPlatformScopeService(t)
	for name, route := range platformScopeRoutes {
		t.Run(name, func(t *testing.T) {
			w := servePlatformScope(t, platformScopeRouter(t, svc, platformScopeTenantAdmin), route)
			assert.Equal(t, http.StatusNotFound, w.Code, "body: %s", w.Body.String())
			assert.Contains(t, w.Body.String(), qrdbsdk.ErrTenantMissing.Error())
		})
	}
}

// TestPlatformScopeREST_SystemAdminServed: the platform identity passes the
// gate on every route. Past the gate some routes fail on their own
// preconditions (an initialized barrier cannot be initialized again); none may
// answer with the binding's refusal, so the routes share one service.
func TestPlatformScopeREST_SystemAdminServed(t *testing.T) {
	svc := newPlatformScopeService(t)
	for name, route := range platformScopeRoutes {
		t.Run(name, func(t *testing.T) {
			w := servePlatformScope(t, platformScopeRouter(t, svc, platformScopeSystemAdmin), route)
			assert.NotContains(t, w.Body.String(), qrdbsdk.ErrTenantMissing.Error(), "status %d", w.Code)
		})
	}
}

// TestPlatformScopeREST_SystemAdminReadsTheCredential proves the platform
// identity is actually served, not merely unrefused.
func TestPlatformScopeREST_SystemAdminReadsTheCredential(t *testing.T) {
	svc := newPlatformScopeService(t)
	w := servePlatformScope(t, platformScopeRouter(t, svc, platformScopeSystemAdmin), platformScopeRoutes["platform get"])
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), base64.StdEncoding.EncodeToString([]byte("platform-secret")))
}

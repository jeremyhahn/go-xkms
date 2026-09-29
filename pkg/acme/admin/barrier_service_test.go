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

package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The admin plane's /admin/barrier/* routes operate the system barrier only
// through the XKMSService (go-xkms#1244), so the service's platform-scope
// check (go-xkms#1227) refuses a tenant-scoped caller on every route. These
// tests run the admin service and handlers over a real XKMSService holding a
// real passphrase barrier.

const barrierPassphrase = "admin-barrier-passphrase"

// newBarrierXKMSService returns an XKMSService composed with a real
// passphrase barrier; initialized reports whether the barrier is initialized
// and unsealed before it is returned.
func newBarrierXKMSService(t *testing.T, initialized bool) (*xkms.XKMSService, *seal.Barrier) {
	t.Helper()
	barrier, err := seal.NewBarrier(discardLogger(), storage.NewMemory(), seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	if initialized {
		ctx := context.Background()
		creds := seal.MustCredentials([]byte(barrierPassphrase))
		defer creds.Secret.Destroy()
		require.NoError(t, barrier.Initialize(ctx, creds))
		if barrier.IsSealed() {
			require.NoError(t, barrier.Unseal(ctx, creds))
		}
	}
	svc := &xkms.XKMSService{}
	svc.SetBarrier(barrier)
	return svc, barrier
}

// barrierRouteBodies is a request body for every barrier route that passes
// the handler's own validation, so a refusal can only come from the service.
var barrierRouteBodies = map[string]string{
	"/admin/barrier/initialize":          `{"secret":"attacker-secret"}`,
	"/admin/barrier/unseal":              `{"secret":"attacker-secret"}`,
	"/admin/barrier/shamir/initialize":   `{"secret":"attacker-secret","threshold":2,"total_shares":3}`,
	"/admin/barrier/shamir/unseal-share": `{"share":"s"}`,
	"/admin/barrier/rekey":               `{"threshold":2,"total":3}`,
	"/admin/barrier/recovery/generate":   `{"threshold":2,"total":3}`,
	"/admin/barrier/recovery/recover":    `{"keys":["a","b"]}`,
	"/admin/barrier/root-token":          `{"shares":["a","b"]}`,
}

// barrierRouter mounts the barrier routes over svc behind gate.
func barrierRouter(svc SystemBarrier, gate *PermissionGate) *mux.Router {
	router := mux.NewRouter()
	NewBarrierHandlers(NewBarrierService(svc, discardLogger()), discardLogger()).RegisterRoutes(router, nil, gate)
	return router
}

// serveBarrierRoute dispatches one barrier request as user.
func serveBarrierRoute(router http.Handler, user *AuthenticatedUser, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(barrierRouteBodies[path]))
	req = req.WithContext(withUser(req.Context(), user))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// tenantBarrierAdmin holds every built-in role of tenant-a that carries a
// seal:* or barrier:* grant, so qrdb's authorizer admits it to every barrier
// route: the reproduction of go-xkms#1244.
var tenantBarrierAdmin = &AuthenticatedUser{
	UserID:   "admin@tenant-a",
	Username: "admin@tenant-a",
	TenantID: "tenant-a",
	Roles:    []string{qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameCustodian},
}

// platformBarrierAdmin is an administrator of the reserved system tenant.
var platformBarrierAdmin = &AuthenticatedUser{
	UserID:   "admin@system",
	Username: "admin@system",
	TenantID: qrdbsdk.SystemTenantID,
	Roles:    []string{qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameSO},
}

// TestBarrierRoutes_TenantAdminRefused is the go-xkms#1244 regression: a
// tenant Admin that qrdb's grants admit to every barrier route is refused on
// each one exactly as a caller lacking the grant, and the system barrier is
// left untouched.
func TestBarrierRoutes_TenantAdminRefused(t *testing.T) {
	gates := map[string]func() *PermissionGate{
		// The canonical qrdb grants: proves the gate alone admits the caller.
		"qrdb gate": newEnforcingGate,
		// No RBAC at all: the service's scope check is the only control left.
		"rbac disabled": newPermissiveGate,
	}
	for gateName, newGate := range gates {
		svc, barrier := newBarrierXKMSService(t, true)
		router := barrierRouter(svc, newGate())
		for _, tc := range barrierRouteCases {
			t.Run(gateName+"/"+tc.name, func(t *testing.T) {
				rec := serveBarrierRoute(router, tenantBarrierAdmin, tc.method, tc.path)
				assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
				assert.Contains(t, rec.Body.String(), problemForbidden)
				assert.False(t, barrier.IsSealed(), "a tenant Admin changed the system barrier's seal state")
			})
		}
	}
}

// TestBarrierRoutes_TenantGateAdmitsEveryRoute pins the premise of the
// regression above: without the service's scope check, qrdb's own grants
// admit a tenant Admin to every barrier route, so the refusal cannot be left
// to the gate.
func TestBarrierRoutes_TenantGateAdmitsEveryRoute(t *testing.T) {
	gate := newEnforcingGate()
	ctx := withUser(context.Background(), tenantBarrierAdmin)
	for _, tc := range barrierRouteCases {
		assert.NoError(t, gate.Authorize(ctx, tc.resource, tc.action), tc.name)
	}
}

// TestBarrierRoutes_PlatformAdminSealUnsealRoundTrip proves the platform
// identity keeps the barrier: status, seal, unseal with the passphrase, and
// the recovery-key status all reach the real barrier.
func TestBarrierRoutes_PlatformAdminSealUnsealRoundTrip(t *testing.T) {
	svc, barrier := newBarrierXKMSService(t, true)
	router := barrierRouter(svc, newEnforcingGate())

	rec := serveBarrierRoute(router, platformBarrierAdmin, http.MethodGet, "/admin/barrier/status")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"enabled":true`)
	assert.Contains(t, rec.Body.String(), `"sealed":false`)

	rec = serveBarrierRoute(router, platformBarrierAdmin, http.MethodPost, "/admin/barrier/seal")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, barrier.IsSealed())

	rec = serveBarrierRoute(router, platformBarrierAdmin, http.MethodGet, "/admin/barrier/status")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"sealed":true`)

	req := httptest.NewRequest(http.MethodPost, "/admin/barrier/unseal",
		strings.NewReader(`{"secret":"`+barrierPassphrase+`"}`))
	req = req.WithContext(withUser(req.Context(), platformBarrierAdmin))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.False(t, barrier.IsSealed())

	rec = serveBarrierRoute(router, platformBarrierAdmin, http.MethodGet, "/admin/barrier/recovery/status")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"has_recovery_keys":false`)
}

// TestBarrierRoutes_PlatformAdminWrongPassphrase proves a failed unseal is
// the barrier's answer, not a refusal, and leaves the barrier sealed.
func TestBarrierRoutes_PlatformAdminWrongPassphrase(t *testing.T) {
	svc, barrier := newBarrierXKMSService(t, true)
	router := barrierRouter(svc, newEnforcingGate())
	require.NoError(t, barrier.Seal())

	rec := serveBarrierRoute(router, platformBarrierAdmin, http.MethodPost, "/admin/barrier/unseal")
	assert.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.True(t, barrier.IsSealed())
}

// TestBarrierService_TenantCallerRefused checks the service layer directly:
// every operation answers a tenant caller with a *PlatformScopeError that
// reads as ErrForbidden.
func TestBarrierService_TenantCallerRefused(t *testing.T) {
	xs, barrier := newBarrierXKMSService(t, true)
	svc := NewBarrierService(xs, discardLogger())
	ctx := callerCtx("tenant-a")

	ops := map[string]func() error{
		"status": func() error { _, err := svc.Status(ctx); return err },
		"initialize": func() error {
			return svc.Initialize(ctx, &BarrierInitializeRequest{Secret: "s"})
		},
		"seal": func() error { return svc.Seal(ctx) },
		"unseal": func() error {
			return svc.Unseal(ctx, &BarrierUnsealRequest{Secret: "s"})
		},
		"initialize-shamir": func() error {
			_, err := svc.InitializeShamir(ctx, &BarrierInitializeShamirRequest{Secret: "s", Threshold: 2, TotalShares: 3})
			return err
		},
		"unseal-share": func() error {
			_, err := svc.UnsealWithShare(ctx, &BarrierUnsealShareRequest{Share: "s"})
			return err
		},
		"rekey": func() error {
			_, err := svc.Rekey(ctx, &BarrierRekeyRequest{Threshold: 2, Total: 3})
			return err
		},
		"generate-recovery-keys": func() error {
			_, err := svc.GenerateRecoveryKeys(ctx, &BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
			return err
		},
		"recover-with-keys": func() error {
			return svc.RecoverWithKeys(ctx, &BarrierRecoverWithKeysRequest{Keys: []string{"a"}})
		},
		"has-recovery-keys": func() error { _, err := svc.HasRecoveryKeys(ctx); return err },
		"generate-root-token": func() error {
			_, err := svc.GenerateRootToken(ctx, &BarrierGenerateRootTokenRequest{Shares: []string{"a"}})
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			err := op()
			var scopeErr *PlatformScopeError
			require.ErrorAs(t, err, &scopeErr)
			assert.Equal(t, "tenant-a", scopeErr.CallerTenantID)
			assert.Equal(t, "barrier "+name, scopeErr.Op)
			assert.ErrorIs(t, err, ErrForbidden)
			assert.False(t, barrier.IsSealed())
		})
	}
}

// TestBarrierService_NotConfigured: a server with no system barrier reports
// a disabled barrier on status and refuses mutations with
// *BarrierNotEnabledError; a tenant caller is still refused first.
func TestBarrierService_NotConfigured(t *testing.T) {
	svc := NewBarrierService(&xkms.XKMSService{}, discardLogger())

	status, err := svc.Status(platformCtx())
	require.NoError(t, err)
	assert.False(t, status.Enabled)
	assert.Equal(t, BarrierModeEmbedded, status.Mode)

	var notEnabled *BarrierNotEnabledError
	require.ErrorAs(t, svc.Seal(platformCtx()), &notEnabled)
	assert.Equal(t, "seal", notEnabled.Operation)

	var scopeErr *PlatformScopeError
	_, err = svc.Status(callerCtx("tenant-a"))
	require.ErrorAs(t, err, &scopeErr)
}

// TestBarrierService_NotInitialized maps the barrier's not-initialized answer
// (seal.ErrNotInitialized) to *BarrierNotInitializedError, which the handlers
// answer 409.
func TestBarrierService_NotInitialized(t *testing.T) {
	notInitialized := fixedBarrier{err: seal.ErrNotInitialized}
	svc := NewBarrierService(notInitialized, discardLogger())

	var notInit *BarrierNotInitializedError
	require.ErrorAs(t, svc.Unseal(platformCtx(), &BarrierUnsealRequest{Secret: barrierPassphrase}), &notInit)

	rec := serveBarrierRoute(barrierRouter(notInitialized, newEnforcingGate()), platformBarrierAdmin,
		http.MethodPost, "/admin/barrier/root-token")
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "barrier-not-initialized")
}

// TestBarrierService_InitializeThenUnseal drives a real initialization
// through the admin service and then a seal/unseal cycle.
func TestBarrierService_InitializeThenUnseal(t *testing.T) {
	xs, barrier := newBarrierXKMSService(t, false)
	svc := NewBarrierService(xs, discardLogger())
	ctx := platformCtx()

	require.NoError(t, svc.Initialize(ctx, &BarrierInitializeRequest{Secret: barrierPassphrase}))
	if barrier.IsSealed() {
		require.NoError(t, svc.Unseal(ctx, &BarrierUnsealRequest{Secret: barrierPassphrase}))
	}
	status, err := svc.Status(ctx)
	require.NoError(t, err)
	assert.True(t, status.Enabled)
	assert.False(t, status.Sealed)
	assert.NotEmpty(t, status.InitializedAt)

	var barrierErr *BarrierError
	require.ErrorAs(t, svc.Initialize(ctx, &BarrierInitializeRequest{Secret: barrierPassphrase}), &barrierErr)
	assert.Equal(t, "initialize", barrierErr.Operation)
	assert.ErrorIs(t, barrierErr, seal.ErrAlreadyInitialized)
}

// fixedBarrier is a SystemBarrier answering every operation with canned
// results or err, for the response-mapping and error-wrapping paths a real
// passphrase barrier cannot reach (the share-free Shamir operations need
// enrolled Security Officers).
type fixedBarrier struct {
	err error
}

func (f fixedBarrier) BarrierStatus(context.Context) (*transport.BarrierStatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &transport.BarrierStatusResponse{Sealed: true, Strategy: "shamir", HardwareBacked: true, InitializedAt: "2026-01-02T03:04:05Z"}, nil
}

func (f fixedBarrier) BarrierInitialize(context.Context, *transport.BarrierInitializeRequest) error {
	return f.err
}

func (f fixedBarrier) BarrierSeal(context.Context) error { return f.err }

func (f fixedBarrier) BarrierUnseal(context.Context, *transport.BarrierUnsealRequest) error {
	return f.err
}

func (f fixedBarrier) BarrierInitializeShamir(_ context.Context, req *transport.BarrierInitializeShamirRequest) (*transport.BarrierInitializeShamirResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &transport.BarrierInitializeShamirResponse{Threshold: req.Threshold, TotalShares: req.TotalShares, ShareCount: req.TotalShares}, nil
}

func (f fixedBarrier) BarrierUnsealWithShare(context.Context, *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &transport.BarrierUnsealShareResponse{Required: 3, Submitted: 1}, nil
}

func (f fixedBarrier) BarrierRekey(_ context.Context, req *transport.BarrierRekeyRequest) (*transport.BarrierRekeyResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &transport.BarrierRekeyResponse{Threshold: req.Threshold, TotalShares: req.Total, ShareCount: req.Total}, nil
}

func (f fixedBarrier) BarrierGenerateRecoveryKeys(_ context.Context, req *transport.BarrierGenerateRecoveryKeysRequest) (*transport.BarrierRecoveryKeysResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &transport.BarrierRecoveryKeysResponse{Threshold: req.Threshold, TotalShares: req.Total, ShareCount: req.Total}, nil
}

func (f fixedBarrier) BarrierRecoverWithKeys(context.Context, *transport.BarrierRecoverWithKeysRequest) error {
	return f.err
}

func (f fixedBarrier) BarrierHasRecoveryKeys(context.Context) (*transport.BarrierHasRecoveryKeysResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &transport.BarrierHasRecoveryKeysResponse{HasKeys: true}, nil
}

func (f fixedBarrier) BarrierGenerateRootToken(context.Context, *transport.BarrierGenerateRootTokenRequest) (*transport.BarrierRootTokenResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &transport.BarrierRootTokenResponse{Token: "root", CreatedAt: "2026-01-02T03:04:05Z"}, nil
}

// TestBarrierService_ResponseMapping checks each transport response is
// carried onto the admin response field for field.
func TestBarrierService_ResponseMapping(t *testing.T) {
	svc := NewBarrierService(fixedBarrier{}, discardLogger())
	ctx := platformCtx()

	status, err := svc.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, &BarrierStatusResponse{
		Mode: BarrierModeEmbedded, Enabled: true, Sealed: true, Strategy: "shamir",
		HardwareBacked: true, InitializedAt: "2026-01-02T03:04:05Z",
	}, status)

	shamir, err := svc.InitializeShamir(ctx, &BarrierInitializeShamirRequest{Secret: "s", Threshold: 2, TotalShares: 5})
	require.NoError(t, err)
	assert.Equal(t, &BarrierInitializeShamirResponse{Threshold: 2, TotalShares: 5, ShareCount: 5}, shamir)

	share, err := svc.UnsealWithShare(ctx, &BarrierUnsealShareRequest{Share: "s"})
	require.NoError(t, err)
	assert.Equal(t, &BarrierUnsealShareResponse{Required: 3, Submitted: 1}, share)

	rekey, err := svc.Rekey(ctx, &BarrierRekeyRequest{Threshold: 3, Total: 4})
	require.NoError(t, err)
	assert.Equal(t, &BarrierRekeyResponse{Threshold: 3, TotalShares: 4, ShareCount: 4}, rekey)

	recovery, err := svc.GenerateRecoveryKeys(ctx, &BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3})
	require.NoError(t, err)
	assert.Equal(t, &BarrierRecoveryKeysResponse{Threshold: 2, Total: 3, ShareCount: 3}, recovery)

	hasKeys, err := svc.HasRecoveryKeys(ctx)
	require.NoError(t, err)
	assert.True(t, hasKeys)

	token, err := svc.GenerateRootToken(ctx, &BarrierGenerateRootTokenRequest{Shares: []string{"a"}})
	require.NoError(t, err)
	assert.Equal(t, &BarrierRootTokenResponse{Token: "root", CreatedAt: "2026-01-02T03:04:05Z"}, token)

	require.NoError(t, svc.Initialize(ctx, &BarrierInitializeRequest{Secret: "s"}))
	require.NoError(t, svc.Seal(ctx))
	require.NoError(t, svc.Unseal(ctx, &BarrierUnsealRequest{Secret: "s"}))
	require.NoError(t, svc.RecoverWithKeys(ctx, &BarrierRecoverWithKeysRequest{Keys: []string{"a"}}))
}

// TestBarrierService_ErrorWrapping: every operation wraps an unclassified
// barrier failure in a *BarrierError naming the operation.
func TestBarrierService_ErrorWrapping(t *testing.T) {
	cause := errors.New("barrier: backend unavailable")
	svc := NewBarrierService(fixedBarrier{err: cause}, discardLogger())
	ctx := platformCtx()

	ops := map[string]func() error{
		"status":     func() error { _, err := svc.Status(ctx); return err },
		"initialize": func() error { return svc.Initialize(ctx, &BarrierInitializeRequest{Secret: "s"}) },
		"seal":       func() error { return svc.Seal(ctx) },
		"unseal":     func() error { return svc.Unseal(ctx, &BarrierUnsealRequest{Secret: "s"}) },
		"initialize-shamir": func() error {
			_, err := svc.InitializeShamir(ctx, &BarrierInitializeShamirRequest{Secret: "s"})
			return err
		},
		"unseal-share": func() error {
			_, err := svc.UnsealWithShare(ctx, &BarrierUnsealShareRequest{Share: "s"})
			return err
		},
		"rekey": func() error { _, err := svc.Rekey(ctx, &BarrierRekeyRequest{}); return err },
		"generate-recovery-keys": func() error {
			_, err := svc.GenerateRecoveryKeys(ctx, &BarrierGenerateRecoveryKeysRequest{})
			return err
		},
		"recover-with-keys": func() error {
			return svc.RecoverWithKeys(ctx, &BarrierRecoverWithKeysRequest{})
		},
		"has-recovery-keys": func() error { _, err := svc.HasRecoveryKeys(ctx); return err },
		"generate-root-token": func() error {
			_, err := svc.GenerateRootToken(ctx, &BarrierGenerateRootTokenRequest{})
			return err
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			var barrierErr *BarrierError
			require.ErrorAs(t, op(), &barrierErr)
			assert.Equal(t, name, barrierErr.Operation)
			assert.ErrorIs(t, barrierErr, cause)
		})
	}
}

// TestBarrierErrors checks the admin barrier error types render and unwrap.
func TestBarrierErrors(t *testing.T) {
	inner := errors.New("connection refused")
	barrierErr := &BarrierError{Operation: "status", Err: inner}
	assert.Equal(t, "admin: barrier status: connection refused", barrierErr.Error())
	assert.Equal(t, inner, barrierErr.Unwrap())

	assert.Equal(t, "admin: barrier not initialized", (&BarrierNotInitializedError{}).Error())
	assert.Contains(t, (&BarrierNotEnabledError{Operation: "seal"}).Error(), `"seal"`)
}

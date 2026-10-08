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
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
)

// Platform-scope tests for go-xkms#1226 and #1227. The sealed platform store,
// credential submission, the token PINs, the server's PIV
// card and the tenants' TPM modes are platform-global state: the RBAC gate admits a
// tenant-local Admin to all of them (its ScopeSelf grants resolve against its
// own tenant), so the service's requirePlatformScope is what confines them to
// a cross-tenant identity. These tests drive the service directly so no
// transport check can mask a missing service-layer one.

const (
	platformScopeSecretName = "credentials/pkcs11-pin"
	platformScopeSOPIN      = "so-pin-123456"
	platformScopeUserPIN    = "user-pin-123456"
	platformScopeTPMTenant  = "tenant-b"
)

// newPlatformScopeService returns an XKMSService composed with every
// platform-global subsystem over in-memory state: a software PIN backend with both PINs set; a platform store
// holding one secret; a TPM policy service; a manual
// credential service; and a PIV manager over the "software" store.
func newPlatformScopeService(t *testing.T) *XKMSService {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A light Argon2id cost keeps the per-operation fixture fast; the PIN
	// semantics under test do not depend on the work factor.
	hashCfg := qrdbsdk.DefaultHashConfig()
	hashCfg.Time, hashCfg.Memory, hashCfg.Threads = 1, 8*1024, 1
	pins, err := qrdbsdk.NewSoftwareBackend(nil, hashCfg)
	require.NoError(t, err)
	require.NoError(t, pins.SetSOPIN("", platformScopeSOPIN))
	require.NoError(t, pins.SetUserPIN(platformScopeSOPIN, platformScopeUserPIN))

	store, err := seal.NewPlatformStore(storage.NewMemory(), logger)
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, platformScopeSecretName, []byte("platform-secret")))

	policies, _ := tpmpolicytest.NewOffline(t)

	credSvc, err := credentialspkg.New(&credentialspkg.Config{Strategy: credentialspkg.StrategyManual}, nil, nil, logger)
	require.NoError(t, err)

	setupPIVForOps(t, nil)

	svc := &XKMSService{}
	svc.SetPINManager(pins)
	svc.SetPlatformStore(store)
	svc.SetTPMPolicyService(policies)
	svc.SetCredentialService(credSvc)
	return svc
}

// platformScopedOp invokes one platform-global service operation.
type platformScopedOp func(ctx context.Context, svc *XKMSService) error

// platformScopedOps is every platform-global XKMSService operation #1226 and
// #1227 name. A new operation on one of these subsystems belongs here.
var platformScopedOps = map[string]platformScopedOp{
	// Sealed platform store (#1226).
	"SealStorePut": func(ctx context.Context, s *XKMSService) error {
		return s.SealStorePut(ctx, &transport.SealStorePutRequest{Name: platformScopeSecretName, Secret: []byte("overwritten")})
	},
	"SealStoreGet": func(ctx context.Context, s *XKMSService) error {
		_, err := s.SealStoreGet(ctx, &transport.SealStoreGetRequest{Name: platformScopeSecretName})
		return err
	},
	"SealStoreDelete": func(ctx context.Context, s *XKMSService) error {
		return s.SealStoreDelete(ctx, &transport.SealStoreDeleteRequest{Name: platformScopeSecretName})
	},
	"SealStoreList": func(ctx context.Context, s *XKMSService) error {
		_, err := s.SealStoreList(ctx)
		return err
	},
	"SealStoreReseal": func(ctx context.Context, s *XKMSService) error {
		return s.SealStoreReseal(ctx, &transport.SealStoreResealRequest{Name: platformScopeSecretName})
	},
	"SealStoreStatus": func(ctx context.Context, s *XKMSService) error {
		_, err := s.SealStoreStatus(ctx)
		return err
	},

	// Credential submission (#1226).
	"SubmitCredential": func(ctx context.Context, s *XKMSService) error {
		_, err := s.SubmitCredential(ctx, &transport.CredentialSubmitRequest{Name: "pkcs11-pin", Value: "c2VjcmV0"})
		return err
	},

	"ListCredentials": func(ctx context.Context, s *XKMSService) error {
		_, err := s.ListCredentials(ctx)
		return err
	},

	// Token PINs (#1227).
	"SetSOPIN": func(ctx context.Context, s *XKMSService) error {
		return s.SetSOPIN(ctx, &transport.SetSOPINRequest{CurrentSOPIN: platformScopeSOPIN, NewSOPIN: "so-pin-654321"})
	},
	"SetUserPIN": func(ctx context.Context, s *XKMSService) error {
		return s.SetUserPIN(ctx, &transport.SetUserPINRequest{SOPIN: platformScopeSOPIN, NewUserPIN: "user-pin-654321"})
	},
	"ChangeSOPIN": func(ctx context.Context, s *XKMSService) error {
		return s.ChangeSOPIN(ctx, &transport.ChangeSOPINRequest{CurrentSOPIN: platformScopeSOPIN, NewSOPIN: "so-pin-654321"})
	},
	"ChangeUserPIN": func(ctx context.Context, s *XKMSService) error {
		return s.ChangeUserPIN(ctx, &transport.ChangeUserPINRequest{CurrentUserPIN: platformScopeUserPIN, NewUserPIN: "user-pin-654321"})
	},
	"VerifySOPIN": func(ctx context.Context, s *XKMSService) error {
		return s.VerifySOPIN(ctx, &transport.VerifySOPINRequest{SOPIN: platformScopeSOPIN})
	},
	"VerifyUserPIN": func(ctx context.Context, s *XKMSService) error {
		return s.VerifyUserPIN(ctx, &transport.VerifyUserPINRequest{UserPIN: platformScopeUserPIN})
	},
	"GetLockoutStatus": func(ctx context.Context, s *XKMSService) error {
		_, err := s.GetLockoutStatus(ctx)
		return err
	},
	"ResetLockout": func(ctx context.Context, s *XKMSService) error {
		return s.ResetLockout(ctx, &transport.ResetLockoutRequest{SOPIN: platformScopeSOPIN})
	},

	// The server's PIV card (#1227).
	"ListPIVSlots": func(ctx context.Context, s *XKMSService) error {
		_, err := s.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{Backend: "software"})
		return err
	},
	"GetPIVCertificate": func(ctx context.Context, s *XKMSService) error {
		_, err := s.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{Backend: "software", Slot: "9a", Format: "pem"})
		return err
	},
	"StorePIVCertificate": func(ctx context.Context, s *XKMSService) error {
		return s.StorePIVCertificate(ctx, &transport.StorePIVCertificateRequest{Backend: "software", Slot: "9a", Certificate: []byte("x"), Format: "pem"})
	},
	"DeletePIVCertificate": func(ctx context.Context, s *XKMSService) error {
		return s.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{Backend: "software", Slot: "9a"})
	},
	"GeneratePIVKey": func(ctx context.Context, s *XKMSService) error {
		_, err := s.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{Backend: "software", Slot: "9a", Algorithm: "ecdsap256", Subject: "server"})
		return err
	},
	"ImportPIVCertificate": func(ctx context.Context, s *XKMSService) error {
		return s.ImportPIVCertificate(ctx, &transport.StorePIVCertificateRequest{Backend: "software", Slot: "9a", Certificate: []byte("x"), Format: "pem"})
	},
	"ExportPIVCertificate": func(ctx context.Context, s *XKMSService) error {
		_, err := s.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{Backend: "software", Slot: "9a", Format: "pem"})
		return err
	},
	"GeneratePIVCSR": func(ctx context.Context, s *XKMSService) error {
		_, err := s.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{Backend: "software", Slot: "9a", Subject: "server"})
		return err
	},

	// A tenant's TPM mode and vTPM: the physical TPM is the platform's.
	"GetTenantTPMMode": func(ctx context.Context, s *XKMSService) error {
		_, err := s.GetTenantTPMMode(ctx, platformScopeTPMTenant)
		return err
	},
	"SetTenantTPMMode": func(ctx context.Context, s *XKMSService) error {
		_, err := s.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: platformScopeTPMTenant, Mode: "none"})
		return err
	},
	"TenantVTPMStatus": func(ctx context.Context, s *XKMSService) error {
		_, err := s.TenantVTPMStatus(ctx, platformScopeTPMTenant)
		return err
	},
	"TenantVTPMStart": func(ctx context.Context, s *XKMSService) error {
		_, err := s.TenantVTPMStart(ctx, platformScopeTPMTenant)
		return err
	},
	"TenantVTPMStop": func(ctx context.Context, s *XKMSService) error {
		_, err := s.TenantVTPMStop(ctx, platformScopeTPMTenant)
		return err
	},
}

// TestPlatformScope_TenantAdminRefusedOnEveryOperation is the #1226/#1227
// exploit: a tenant-local Admin reaches every platform-global operation. Each
// must be refused with the binding's not-found refusal before it touches
// state.
func TestPlatformScope_TenantAdminRefusedOnEveryOperation(t *testing.T) {
	svc := newPlatformScopeService(t)
	for name, op := range platformScopedOps {
		t.Run(name, func(t *testing.T) {
			requireBindingRefusal(t, op(tenantCtx("tenant-a"), svc), name)
		})
	}
}

// TestPlatformScope_RefusalLeavesPlatformStateUntouched proves the refusal
// happens before the operation: after a tenant Admin's attempts to read,
// overwrite and delete the platform credential, take over the PINs and switch a tenant's TPM off, every piece of
// platform state is exactly as the platform left it.
func TestPlatformScope_RefusalLeavesPlatformStateUntouched(t *testing.T) {
	svc := newPlatformScopeService(t)
	for name, op := range platformScopedOps {
		requireBindingRefusal(t, op(tenantCtx("tenant-a"), svc), name)
	}

	ctx := systemCtx()
	got, err := svc.SealStoreGet(ctx, &transport.SealStoreGetRequest{Name: platformScopeSecretName})
	require.NoError(t, err)
	assert.Equal(t, []byte("platform-secret"), got.Secret)

	require.NoError(t, svc.VerifySOPIN(ctx, &transport.VerifySOPINRequest{SOPIN: platformScopeSOPIN}))
	require.NoError(t, svc.VerifyUserPIN(ctx, &transport.VerifyUserPINRequest{UserPIN: platformScopeUserPIN}))

	mode, err := svc.GetTenantTPMMode(ctx, platformScopeTPMTenant)
	require.NoError(t, err)
	assert.Equal(t, string(tpmpolicy.DefaultMode), mode.Mode, "a refused mode change must leave the tenant's TPM mode as it was")
}

// TestPlatformScope_SystemIdentityPassesEveryGate proves the refusal is
// scoped: the platform's own identity -- and a context with no identity at
// all, the in-process boot path -- still reach every operation. Past the gate
// some operations fail on their own preconditions (a vTPM cannot start without a supervisor); none may
// fail with the binding's refusal, so the operations share one fixture.
func TestPlatformScope_SystemIdentityPassesEveryGate(t *testing.T) {
	callers := map[string]context.Context{
		"system tenant": systemCtx(),
		"no identity":   context.Background(),
	}
	for caller, ctx := range callers {
		svc := newPlatformScopeService(t)
		for name, op := range platformScopedOps {
			t.Run(caller+"/"+name, func(t *testing.T) {
				err := op(ctx, svc)
				var bindErr *TenantBindingError
				assert.False(t, errors.As(err, &bindErr), "%s refused the platform scope: %v", name, err)
			})
		}
	}
}

// TestPlatformScope_SystemIdentityCompletesTheExploitedOperations runs the
// exact operations the issues' exploits use as the platform identity and
// checks each actually completes.
func TestPlatformScope_SystemIdentityCompletesTheExploitedOperations(t *testing.T) {
	svc := newPlatformScopeService(t)
	ctx := systemCtx()

	list, err := svc.SealStoreList(ctx)
	require.NoError(t, err)
	assert.Contains(t, list.Names, platformScopeSecretName)
	got, err := svc.SealStoreGet(ctx, &transport.SealStoreGetRequest{Name: platformScopeSecretName})
	require.NoError(t, err)
	assert.Equal(t, []byte("platform-secret"), got.Secret)
	require.NoError(t, svc.SealStoreReseal(ctx, &transport.SealStoreResealRequest{Name: platformScopeSecretName}))

	resp, err := svc.SubmitCredential(ctx, &transport.CredentialSubmitRequest{Name: "pkcs11-pin", Value: "c2VjcmV0"})
	require.NoError(t, err)
	assert.Equal(t, "accepted", resp.Status)

	require.NoError(t, svc.ChangeSOPIN(ctx, &transport.ChangeSOPINRequest{CurrentSOPIN: platformScopeSOPIN, NewSOPIN: "so-pin-654321"}))
	lockout, err := svc.GetLockoutStatus(ctx)
	require.NoError(t, err)
	assert.False(t, lockout.IsLocked)

	_, err = svc.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{Backend: "software"})
	require.NoError(t, err)

	changed, err := svc.SetTenantTPMMode(ctx, &transport.SetTenantTPMModeRequest{TenantID: platformScopeTPMTenant, Mode: "none"})
	require.NoError(t, err)
	assert.Equal(t, string(tpmpolicy.ModeNone), changed.Mode)
}

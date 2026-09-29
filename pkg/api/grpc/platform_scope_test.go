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

package grpc

import (
	"context"
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/seal/policy"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// gRPC side of go-xkms#1226 and #1227: every platform-global RPC is refused
// to a tenant-local Admin with NotFound and the unknown-tenant message, and
// still served to the platform identity.

const platformScopeSecret = "credentials/pkcs11-pin"

// platformScopePCRReader returns a fixed value for every PCR.
type platformScopePCRReader struct{}

func (platformScopePCRReader) ReadPCRs(_ string, indices []int) (map[int][]byte, error) {
	values := make(map[int][]byte, len(indices))
	for _, idx := range indices {
		values[idx] = make([]byte, 32)
	}
	return values, nil
}

// newPlatformScopeGRPC returns a Service over an XKMSService composed with an
// unsealed system barrier, a PIN backend with both PINs set, a platform store
// holding one credential and a PCR policy manager holding the "boot" policy.
func newPlatformScopeGRPC(t *testing.T) *Service {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	b, err := seal.NewBarrier(logger, storage.NewMemory(), seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	creds := seal.MustCredentials([]byte("passphrase"))
	defer creds.Secret.Destroy()
	require.NoError(t, b.Initialize(ctx, creds))
	if b.IsSealed() {
		require.NoError(t, b.Unseal(ctx, creds))
	}

	hashCfg := qrdbsdk.DefaultHashConfig()
	hashCfg.Time, hashCfg.Memory, hashCfg.Threads = 1, 8*1024, 1
	pins, err := qrdbsdk.NewSoftwareBackend(nil, hashCfg)
	require.NoError(t, err)
	require.NoError(t, pins.SetSOPIN("", "so-pin-123456"))
	require.NoError(t, pins.SetUserPIN("so-pin-123456", "user-pin-123456"))

	store, err := seal.NewPlatformStore(storage.NewMemory(), logger)
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, platformScopeSecret, []byte("platform-secret")))

	policies, err := policy.NewManager(platformScopePCRReader{}, policy.NewMemoryPolicyStore())
	require.NoError(t, err)
	_, err = policies.CreatePolicy("boot", "sha256", []int{0, 7})
	require.NoError(t, err)

	svc := &xkms.XKMSService{}
	svc.SetBarrier(b)
	svc.SetPINManager(pins)
	svc.SetPlatformStore(store)
	svc.SetPolicyManager(policies)
	return NewService(nil, nil, svc)
}

// platformScopeRPC invokes one platform-global RPC.
type platformScopeRPC func(ctx context.Context, s *Service) error

func rpcErr[T any](_ T, err error) error { return err }

// platformScopeRPCs is every gRPC method #1226 and #1227 name.
var platformScopeRPCs = map[string]platformScopeRPC{
	"SealStorePut": func(ctx context.Context, s *Service) error {
		return rpcErr(s.SealStorePut(ctx, &pb.SealStorePutRequest{Name: platformScopeSecret, Secret: []byte("overwritten")}))
	},
	"SealStoreGet": func(ctx context.Context, s *Service) error {
		return rpcErr(s.SealStoreGet(ctx, &pb.SealStoreGetRequest{Name: platformScopeSecret}))
	},
	"SealStoreDelete": func(ctx context.Context, s *Service) error {
		return rpcErr(s.SealStoreDelete(ctx, &pb.SealStoreDeleteRequest{Name: platformScopeSecret}))
	},
	"SealStoreList": func(ctx context.Context, s *Service) error {
		return rpcErr(s.SealStoreList(ctx, &pb.SealStoreListRequest{}))
	},
	"SealStoreReseal": func(ctx context.Context, s *Service) error {
		return rpcErr(s.SealStoreReseal(ctx, &pb.SealStoreResealRequest{Name: platformScopeSecret}))
	},
	"SealStoreStatus": func(ctx context.Context, s *Service) error {
		return rpcErr(s.SealStoreStatus(ctx, &pb.SealStoreStatusRequest{}))
	},

	"BarrierInitialize": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierInitialize(ctx, &pb.BarrierInitializeRequest{Secret: "passphrase"}))
	},
	"BarrierUnseal": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierUnseal(ctx, &pb.BarrierUnsealRequest{Secret: "passphrase"}))
	},
	"BarrierSeal": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierSeal(ctx, &emptypb.Empty{}))
	},
	"BarrierStatus": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierStatus(ctx, &emptypb.Empty{}))
	},
	"BarrierInitializeShamir": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierInitializeShamir(ctx, &pb.BarrierInitializeShamirRequest{Secret: "passphrase"}))
	},
	"BarrierUnsealShare": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierUnsealShare(ctx, &pb.BarrierUnsealShareRequest{Share: "s"}))
	},
	"BarrierUnsealShares": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierUnsealShares(ctx, &pb.BarrierUnsealSharesRequest{Shares: []string{"a", "b"}}))
	},
	"BarrierRekey": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierRekey(ctx, &pb.BarrierRekeyRequest{Threshold: 2, Total: 3}))
	},
	"BarrierGenerateRecoveryKeys": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierGenerateRecoveryKeys(ctx, &pb.BarrierGenerateRecoveryKeysRequest{Threshold: 2, Total: 3}))
	},
	"BarrierRecoverWithKeys": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierRecoverWithKeys(ctx, &pb.BarrierRecoverWithKeysRequest{Keys: []string{"a", "b"}}))
	},
	"BarrierDeleteRecoveryKeys": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierDeleteRecoveryKeys(ctx, &emptypb.Empty{}))
	},
	"BarrierHasRecoveryKeys": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierHasRecoveryKeys(ctx, &emptypb.Empty{}))
	},
	"BarrierGenerateRootToken": func(ctx context.Context, s *Service) error {
		return rpcErr(s.BarrierGenerateRootToken(ctx, &pb.BarrierGenerateRootTokenRequest{Shares: []string{"a", "b"}}))
	},

	"SetSOPIN": func(ctx context.Context, s *Service) error {
		return rpcErr(s.SetSOPIN(ctx, &pb.SetSOPINRequest{CurrentSoPin: "so-pin-123456", NewSoPin: "so-pin-654321"}))
	},
	"SetUserPIN": func(ctx context.Context, s *Service) error {
		return rpcErr(s.SetUserPIN(ctx, &pb.SetUserPINRequest{SoPin: "so-pin-123456", NewUserPin: "user-pin-654321"}))
	},
	"ChangeSOPIN": func(ctx context.Context, s *Service) error {
		return rpcErr(s.ChangeSOPIN(ctx, &pb.ChangeSOPINRequest{CurrentSoPin: "so-pin-123456", NewSoPin: "so-pin-654321"}))
	},
	"ChangeUserPIN": func(ctx context.Context, s *Service) error {
		return rpcErr(s.ChangeUserPIN(ctx, &pb.ChangeUserPINRequest{CurrentUserPin: "user-pin-123456", NewUserPin: "user-pin-654321"}))
	},
	"VerifySOPIN": func(ctx context.Context, s *Service) error {
		return rpcErr(s.VerifySOPIN(ctx, &pb.VerifySOPINRequest{SoPin: "so-pin-123456"}))
	},
	"VerifyUserPIN": func(ctx context.Context, s *Service) error {
		return rpcErr(s.VerifyUserPIN(ctx, &pb.VerifyUserPINRequest{UserPin: "user-pin-123456"}))
	},
	"GetLockoutStatus": func(ctx context.Context, s *Service) error {
		return rpcErr(s.GetLockoutStatus(ctx, &emptypb.Empty{}))
	},
	"ResetLockout": func(ctx context.Context, s *Service) error {
		return rpcErr(s.ResetLockout(ctx, &pb.ResetLockoutRequest{SoPin: "so-pin-123456"}))
	},

	"ListPIVSlots": func(ctx context.Context, s *Service) error {
		return rpcErr(s.ListPIVSlots(ctx, &pb.ListPIVSlotsRequest{Backend: "software"}))
	},
	"GetPIVCertificate": func(ctx context.Context, s *Service) error {
		return rpcErr(s.GetPIVCertificate(ctx, &pb.GetPIVCertificateRequest{Backend: "software", Slot: "9a", Format: "pem"}))
	},
	"StorePIVCertificate": func(ctx context.Context, s *Service) error {
		return rpcErr(s.StorePIVCertificate(ctx, &pb.StorePIVCertificateRequest{Backend: "software", Slot: "9a", Certificate: []byte("x"), Format: "pem"}))
	},
	"DeletePIVCertificate": func(ctx context.Context, s *Service) error {
		return rpcErr(s.DeletePIVCertificate(ctx, &pb.DeletePIVCertificateRequest{Backend: "software", Slot: "9a"}))
	},
	"GeneratePIVKey": func(ctx context.Context, s *Service) error {
		return rpcErr(s.GeneratePIVKey(ctx, &pb.GeneratePIVKeyRequest{Backend: "software", Slot: "9a", Algorithm: "ecdsap256", Subject: "server"}))
	},
	"ImportPIVCertificate": func(ctx context.Context, s *Service) error {
		return rpcErr(s.ImportPIVCertificate(ctx, &pb.StorePIVCertificateRequest{Backend: "software", Slot: "9a", Certificate: []byte("x"), Format: "pem"}))
	},
	"ExportPIVCertificate": func(ctx context.Context, s *Service) error {
		return rpcErr(s.ExportPIVCertificate(ctx, &pb.GetPIVCertificateRequest{Backend: "software", Slot: "9a", Format: "pem"}))
	},
	"GeneratePIVCSR": func(ctx context.Context, s *Service) error {
		return rpcErr(s.GeneratePIVCSR(ctx, &pb.GeneratePIVCSRRequest{Backend: "software", Slot: "9a", Subject: "server"}))
	},

	"PolicyCreate": func(ctx context.Context, s *Service) error {
		return rpcErr(s.PolicyCreate(ctx, &pb.PolicyCreateRequest{Name: "attacker", Bank: "sha256", Pcrs: []int32{0}}))
	},
	"PolicyGet": func(ctx context.Context, s *Service) error {
		return rpcErr(s.PolicyGet(ctx, &pb.PolicyGetRequest{Name: "boot"}))
	},
	"PolicyList": func(ctx context.Context, s *Service) error {
		return rpcErr(s.PolicyList(ctx, &pb.PolicyListRequest{}))
	},
	"PolicyDelete": func(ctx context.Context, s *Service) error {
		return rpcErr(s.PolicyDelete(ctx, &pb.PolicyDeleteRequest{Name: "boot"}))
	},
	"PolicyRefresh": func(ctx context.Context, s *Service) error {
		return rpcErr(s.PolicyRefresh(ctx, &pb.PolicyRefreshRequest{Name: "boot"}))
	},
	"PolicyVerify": func(ctx context.Context, s *Service) error {
		return rpcErr(s.PolicyVerify(ctx, &pb.PolicyVerifyRequest{Name: "boot"}))
	},
	"PolicyExport": func(ctx context.Context, s *Service) error {
		return rpcErr(s.PolicyExport(ctx, &pb.PolicyExportRequest{Name: "boot"}))
	},
}

func platformScopeCtx(tenantID string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "admin@" + tenantID, TenantID: tenantID, Roles: []string{"admin"}})
}

// TestPlatformScopeGRPC_TenantAdminRefused: each RPC answers a tenant Admin
// with NotFound and the unknown-tenant message.
func TestPlatformScopeGRPC_TenantAdminRefused(t *testing.T) {
	s := newPlatformScopeGRPC(t)
	for name, rpc := range platformScopeRPCs {
		t.Run(name, func(t *testing.T) {
			err := rpc(platformScopeCtx("tenant-a"), s)
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok, "%v", err)
			assert.Equal(t, codes.NotFound, st.Code(), "%v", err)
			assert.Contains(t, st.Message(), qrdbsdk.ErrTenantMissing.Error())
		})
	}
}

// TestPlatformScopeGRPC_SystemAdminServed: the platform identity passes the
// gate on every RPC. Past the gate some RPCs fail on their own preconditions
// (an initialized barrier cannot be initialized again); none may answer with
// the binding's refusal, so the RPCs share one service.
func TestPlatformScopeGRPC_SystemAdminServed(t *testing.T) {
	s := newPlatformScopeGRPC(t)
	for name, rpc := range platformScopeRPCs {
		t.Run(name, func(t *testing.T) {
			err := rpc(platformScopeCtx(qrdbsdk.SystemTenantID), s)
			if err != nil {
				assert.NotContains(t, err.Error(), qrdbsdk.ErrTenantMissing.Error())
			}
		})
	}
}

// TestPlatformScopeGRPC_SystemAdminReadsTheCredential proves the platform
// identity is actually served, not merely unrefused.
func TestPlatformScopeGRPC_SystemAdminReadsTheCredential(t *testing.T) {
	s := newPlatformScopeGRPC(t)
	resp, err := s.SealStoreGet(platformScopeCtx(qrdbsdk.SystemTenantID), &pb.SealStoreGetRequest{Name: platformScopeSecret})
	require.NoError(t, err)
	assert.Equal(t, []byte("platform-secret"), resp.GetSecret())
}

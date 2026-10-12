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
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// gRPC side of go-xkms#1226 and #1227: every platform-global RPC is refused
// to a tenant-local Admin with NotFound and the unknown-tenant message, and
// still served to the platform identity.

const platformScopeSecret = "vault-token"

// newPlatformScopeGRPC returns a Service over an XKMSService composed with an
// unsealed system barrier, a PIN backend with both PINs set, a platform store
// holding one credential and a TPM policy service (whose tenant TPM mode and
// vTPM RPCs are platform-scoped).
func newPlatformScopeGRPC(t *testing.T) *Service {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	hashCfg := qrdbsdk.DefaultHashConfig()
	hashCfg.Time, hashCfg.Memory, hashCfg.Threads = 1, 8*1024, 1
	pins, err := qrdbsdk.NewSoftwareBackend(nil, hashCfg)
	require.NoError(t, err)
	require.NoError(t, pins.SetSOPIN("", "so-pin-123456"))
	require.NoError(t, pins.SetUserPIN("so-pin-123456", "user-pin-123456"))

	store, err := seal.NewPlatformStore(storage.NewMemory(), logger)
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, platformScopeSecret, []byte("platform-secret")))

	policies, _ := tpmpolicytest.NewOffline(t)

	svc := &xkms.XKMSService{}
	svc.SetPINManager(pins)
	svc.SetPlatformStore(store)
	svc.SetTPMPolicyService(policies)
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

	"GetTenantTPMMode": func(ctx context.Context, s *Service) error {
		return rpcErr(s.GetTenantTPMMode(ctx, &pb.TenantTPMModeRequest{TenantId: "tenant-b"}))
	},
	"SetTenantTPMMode": func(ctx context.Context, s *Service) error {
		return rpcErr(s.SetTenantTPMMode(ctx, &pb.SetTenantTPMModeRequest{TenantId: "tenant-b", Mode: "none"}))
	},
	"TenantVTPMStatus": func(ctx context.Context, s *Service) error {
		return rpcErr(s.TenantVTPMStatus(ctx, &pb.TenantVTPMRequest{TenantId: "tenant-b"}))
	},
	"TenantVTPMStart": func(ctx context.Context, s *Service) error {
		return rpcErr(s.TenantVTPMStart(ctx, &pb.TenantVTPMRequest{TenantId: "tenant-b"}))
	},
	"TenantVTPMStop": func(ctx context.Context, s *Service) error {
		return rpcErr(s.TenantVTPMStop(ctx, &pb.TenantVTPMRequest{TenantId: "tenant-b"}))
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

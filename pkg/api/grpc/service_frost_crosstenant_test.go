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

//go:build frost

package grpc

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// ===========================================================================
// Cross-tenant isolation for the FROST RPCs (go-xkms#1231).
//
// Tenant A, authenticated, names a FROST key that belongs to tenant B. Every
// FROST RPC that takes a key ID must answer exactly as it does for a key no
// tenant holds -- the same code and the same message -- and must leave B's key
// untouched. A listing shows only the caller's keys and an import cannot
// replace another tenant's share.
// ===========================================================================

const (
	frostTenantA = "tenant-a"
	frostTenantB = "tenant-b"
	frostKeyA    = "a-frost"
	frostKeyB    = "b-frost"
)

// frostTenantCtx returns a context authenticated as tenantID.
func frostTenantCtx(tenantID string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "svc", TenantID: tenantID})
}

// frostCrossTenantService registers an in-memory FROST backend and creates one
// participant-mode key for each holder tenant (A and B when none are named).
func frostCrossTenantService(t *testing.T, holders ...string) *Service {
	t.Helper()
	svc := NewService(nil, nil, setupFrostXKMS(t))

	keyOf := map[string]string{frostTenantA: frostKeyA, frostTenantB: frostKeyB}
	if len(holders) == 0 {
		holders = []string{frostTenantA, frostTenantB}
	}
	for _, tenant := range holders {
		_, err := svc.FrostGenerateKey(frostTenantCtx(tenant), &pb.FrostGenerateKeyRequest{
			KeyId: keyOf[tenant], Threshold: 2, Total: 3, ParticipantId: 1,
		})
		require.NoError(t, err, "generating %s for %s", keyOf[tenant], tenant)
	}
	return svc
}

// requireFrostKeyBIntact proves tenant B still holds its key.
func requireFrostKeyBIntact(t *testing.T, svc *Service) {
	t.Helper()
	listed, err := svc.FrostListKeys(frostTenantCtx(frostTenantB), &pb.FrostListKeysRequest{})
	require.NoError(t, err)
	require.Len(t, listed.Keys, 1, "tenant B lost its FROST key to tenant A")
	require.Equal(t, frostKeyB, listed.Keys[0].KeyId)
}

// frostElement is 32 bytes standing in for any scalar or element a FROST round
// request carries.
var frostElement = bytes.Repeat([]byte{1}, 32)

// frostKeyRPC is one FROST RPC that addresses a key by ID.
type frostKeyRPC struct {
	name string
	call func(s *Service, ctx context.Context, keyID string) error
}

func frostKeyRPCs() []frostKeyRPC {
	commitments := []*pb.FrostCommitment{
		{ParticipantId: 1, HidingCommitment: frostElement, BindingCommitment: frostElement},
		{ParticipantId: 2, HidingCommitment: frostElement, BindingCommitment: frostElement},
	}
	return []frostKeyRPC{
		{name: "get", call: func(s *Service, ctx context.Context, id string) error {
			_, err := s.FrostGetKey(ctx, &pb.FrostGetKeyRequest{KeyId: id})
			return err
		}},
		{name: "delete", call: func(s *Service, ctx context.Context, id string) error {
			_, err := s.FrostDeleteKey(ctx, &pb.FrostDeleteKeyRequest{KeyId: id})
			return err
		}},
		{name: "nonces", call: func(s *Service, ctx context.Context, id string) error {
			_, err := s.FrostGenerateNonces(ctx, &pb.FrostGenerateNoncesRequest{KeyId: id})
			return err
		}},
		{name: "sign", call: func(s *Service, ctx context.Context, id string) error {
			_, err := s.FrostSignRound(ctx, &pb.FrostSignRoundRequest{
				KeyId: id, Message: []byte("message"), SessionId: "session",
				HidingNonce: frostElement, BindingNonce: frostElement,
				HidingCommitment: frostElement, BindingCommitment: frostElement,
				Commitments: commitments,
			})
			return err
		}},
		{name: "aggregate", call: func(s *Service, ctx context.Context, id string) error {
			_, err := s.FrostAggregate(ctx, &pb.FrostAggregateRequest{
				KeyId: id, Message: []byte("message"), Commitments: commitments,
				Shares: []*pb.FrostSignatureShare{
					{ParticipantId: 1, Share: frostElement},
					{ParticipantId: 2, Share: frostElement},
				},
			})
			return err
		}},
		{name: "verify", call: func(s *Service, ctx context.Context, id string) error {
			_, err := s.FrostVerify(ctx, &pb.FrostVerifyRequest{
				KeyId: id, Message: []byte("message"), Signature: append(append([]byte{}, frostElement...), frostElement...),
			})
			return err
		}},
	}
}

// TestFrostRPCs_CrossTenantRefusalEqualsGenuineMiss is the go-xkms#1231
// regression for gRPC. For each FROST RPC that names a key, tenant A naming
// tenant B's key must get exactly the status tenant A gets for the same key ID
// in a deployment where no tenant holds it, and B's key must survive.
func TestFrostRPCs_CrossTenantRefusalEqualsGenuineMiss(t *testing.T) {
	for _, rpc := range frostKeyRPCs() {
		t.Run(rpc.name, func(t *testing.T) {
			svc := frostCrossTenantService(t, frostTenantA)
			missErr := rpc.call(svc, frostTenantCtx(frostTenantA), frostKeyB)
			miss, ok := status.FromError(missErr)
			require.True(t, ok, "not a gRPC status: %v", missErr)
			require.Equal(t, codes.NotFound, miss.Code(), "a genuinely missing FROST key must be NotFound: %v", missErr)

			svc = frostCrossTenantService(t)
			crossErr := rpc.call(svc, frostTenantCtx(frostTenantA), frostKeyB)
			cross, ok := status.FromError(crossErr)
			require.True(t, ok, "not a gRPC status: %v", crossErr)
			assert.Equal(t, miss.Code(), cross.Code(), "tenant A reached tenant B's FROST key: %v", crossErr)
			assert.Equal(t, miss.Message(), cross.Message(),
				"a cross-tenant refusal must be indistinguishable from a genuine miss")

			requireFrostKeyBIntact(t, svc)
		})
	}
}

// TestFrostRPCs_CrossTenantSigningRoundsRefused drives the exploit end to end:
// tenant A may neither draw Round 1 nonces from tenant B's share nor spend
// tenant B's nonces on a Round 2 signature share.
func TestFrostRPCs_CrossTenantSigningRoundsRefused(t *testing.T) {
	svc := frostCrossTenantService(t)

	_, err := svc.FrostGenerateNonces(frostTenantCtx(frostTenantA), &pb.FrostGenerateNoncesRequest{KeyId: frostKeyB})
	require.Equal(t, codes.NotFound, status.Code(err), "tenant A drew nonces from tenant B's share: %v", err)

	n, err := svc.FrostGenerateNonces(frostTenantCtx(frostTenantB), &pb.FrostGenerateNoncesRequest{KeyId: frostKeyB})
	require.NoError(t, err)

	_, err = svc.FrostSignRound(frostTenantCtx(frostTenantA), &pb.FrostSignRoundRequest{
		KeyId: frostKeyB, Message: []byte("message"), SessionId: n.SessionId,
		HidingNonce: n.HidingNonce, BindingNonce: n.BindingNonce,
		HidingCommitment: n.HidingCommitment, BindingCommitment: n.BindingCommitment,
		Commitments: []*pb.FrostCommitment{
			{ParticipantId: n.ParticipantId, HidingCommitment: n.HidingCommitment, BindingCommitment: n.BindingCommitment},
			{ParticipantId: n.ParticipantId + 1, HidingCommitment: n.HidingCommitment, BindingCommitment: n.BindingCommitment},
		},
	})
	require.Equal(t, codes.NotFound, status.Code(err),
		"tenant A produced a signature share with tenant B's key share: %v", err)
}

// TestFrostListKeys_ShowsOnlyCallersKeys proves a tenant's listing, and its
// total, count only that tenant's FROST keys.
func TestFrostListKeys_ShowsOnlyCallersKeys(t *testing.T) {
	svc := frostCrossTenantService(t)

	listed, err := svc.FrostListKeys(frostTenantCtx(frostTenantA), &pb.FrostListKeysRequest{})
	require.NoError(t, err)
	require.Len(t, listed.Keys, 1, "tenant A saw another tenant's FROST keys: %v", listed.Keys)
	assert.Equal(t, frostKeyA, listed.Keys[0].KeyId)
	assert.Equal(t, int32(1), listed.Total)
}

// TestFrostImportKey_CannotReplaceAnotherTenantsShare proves an import naming
// another tenant's key ID lands in the importer's tenant and leaves the other
// tenant's share in place.
func TestFrostImportKey_CannotReplaceAnotherTenantsShare(t *testing.T) {
	svc := frostCrossTenantService(t)
	before, err := svc.FrostGetKey(frostTenantCtx(frostTenantB), &pb.FrostGetKeyRequest{KeyId: frostKeyB})
	require.NoError(t, err)

	dealt, err := svc.FrostGenerateKey(frostTenantCtx(frostTenantA), &pb.FrostGenerateKeyRequest{
		KeyId: frostKeyB, Threshold: 2, Total: 3, DealerMode: true,
	})
	require.NoError(t, err)
	_, err = svc.FrostImportKey(frostTenantCtx(frostTenantA), &pb.FrostImportKeyRequest{Package: dealt.Packages[0]})
	require.NoError(t, err)

	after, err := svc.FrostGetKey(frostTenantCtx(frostTenantB), &pb.FrostGetKeyRequest{KeyId: frostKeyB})
	require.NoError(t, err)
	assert.Equal(t, before.Key.GroupPublicKey, after.Key.GroupPublicKey,
		"tenant A's import replaced tenant B's key share")

	own, err := svc.FrostGetKey(frostTenantCtx(frostTenantA), &pb.FrostGetKeyRequest{KeyId: frostKeyB})
	require.NoError(t, err)
	assert.Equal(t, dealt.GroupPublicKey, own.Key.GroupPublicKey, "tenant A's import must land in tenant A")
}

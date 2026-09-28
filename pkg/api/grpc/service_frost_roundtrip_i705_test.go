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

//go:build frost

package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// This file covers pkg/api/grpc/service_frost.go's signing round trip
// (go-xkms#705, batch 4). service_frost_authz_test.go's frostCalls fixture
// proves every FROST RPC is gated, and its one end-to-end positive control
// (TestFrostGenerateKey_AuthorizedCallerSucceeds) stops at dealer-mode key
// generation, so FrostImportKey, FrostGetKey, FrostListKeys,
// FrostGenerateNonces, FrostSignRound, FrostAggregate and FrostVerify never
// ran against real FROST crypto.
//
// These tests drive a full dealer-mode generate -> import -> nonces -> sign
// -> aggregate -> verify round trip over a single gRPC Service/backend,
// re-importing each participant's package immediately before the call that
// needs that participant's locally-held secret share (FrostImportKey stores
// exactly one participant's package per key ID, so switching which
// participant is "local" is how a single backend plays every role -- xkms.Reset,
// which pkg/keyprovider/frost's own multi-participant fixture avoids by
// giving each participant a wholly separate backend, mutates the previously
// active XKMSService's backend map in place, so two backends built back to
// back through the package-level singleton cannot coexist within one test;
// hence one backend, reimported between roles, here).
//
// A round has three participant-role boundaries: two GenerateNonces calls
// (one per participant, before either signs) and two SignRound calls, so the
// package is re-imported before each of the four.

// importFrostPackage imports pkg into svc's currently-registered FROST
// backend, making it the "local" participant for every RPC that reads local
// secret material (FrostGenerateNonces, FrostSignRound) until the next
// import switches it again.
func importFrostPackage(t *testing.T, ctx context.Context, svc *Service, pkg *pb.FrostKeyPackage) {
	t.Helper()
	_, err := svc.FrostImportKey(ctx, &pb.FrostImportKeyRequest{Package: pkg})
	require.NoError(t, err)
}

// TestFrostRoundTrip_GenerateSignAggregateVerify drives a full 2-of-3
// threshold signature end to end through the gRPC handlers: dealer-mode
// generation, two participants' Round 1 nonce generation, their Round 2
// signature shares, aggregation and verification.
func TestFrostRoundTrip_GenerateSignAggregateVerify(t *testing.T) {
	ctx := context.Background()
	message := []byte("go-xkms#705 frost round trip")
	const keyID = "grpc-round-trip-key"

	svc := NewService(nil, nil, setupFrostXKMS(t))

	genResp, err := svc.FrostGenerateKey(ctx, &pb.FrostGenerateKeyRequest{
		KeyId: keyID, Threshold: 2, Total: 3, DealerMode: true,
	})
	require.NoError(t, err)
	require.Len(t, genResp.Packages, 3)
	p1Pkg, p2Pkg := genResp.Packages[0], genResp.Packages[1]

	// Round 1: each participant, in turn, generates its nonces and
	// commitments while its own package is the locally-imported one.
	importFrostPackage(t, ctx, svc, p1Pkg)
	nonce1, err := svc.FrostGenerateNonces(ctx, &pb.FrostGenerateNoncesRequest{KeyId: keyID})
	require.NoError(t, err)

	importFrostPackage(t, ctx, svc, p2Pkg)
	nonce2, err := svc.FrostGenerateNonces(ctx, &pb.FrostGenerateNoncesRequest{KeyId: keyID})
	require.NoError(t, err)

	commitments := []*pb.FrostCommitment{
		{ParticipantId: nonce1.ParticipantId, HidingCommitment: nonce1.HidingCommitment, BindingCommitment: nonce1.BindingCommitment},
		{ParticipantId: nonce2.ParticipantId, HidingCommitment: nonce2.HidingCommitment, BindingCommitment: nonce2.BindingCommitment},
	}

	// Round 2: each participant produces a signature share while its own
	// package is once again the locally-imported one.
	importFrostPackage(t, ctx, svc, p1Pkg)
	share1, err := svc.FrostSignRound(ctx, &pb.FrostSignRoundRequest{
		KeyId: keyID, Message: message,
		SessionId:         nonce1.SessionId,
		HidingNonce:       nonce1.HidingNonce,
		BindingNonce:      nonce1.BindingNonce,
		HidingCommitment:  nonce1.HidingCommitment,
		BindingCommitment: nonce1.BindingCommitment,
		Commitments:       commitments,
	})
	require.NoError(t, err)

	importFrostPackage(t, ctx, svc, p2Pkg)
	share2, err := svc.FrostSignRound(ctx, &pb.FrostSignRoundRequest{
		KeyId: keyID, Message: message,
		SessionId:         nonce2.SessionId,
		HidingNonce:       nonce2.HidingNonce,
		BindingNonce:      nonce2.BindingNonce,
		HidingCommitment:  nonce2.HidingCommitment,
		BindingCommitment: nonce2.BindingCommitment,
		Commitments:       commitments,
	})
	require.NoError(t, err)

	shares := []*pb.FrostSignatureShare{
		{ParticipantId: share1.ParticipantId, Share: share1.SignatureShare},
		{ParticipantId: share2.ParticipantId, Share: share2.SignatureShare},
	}

	// Aggregation and verification only read group-invariant public data
	// (group public key, verification shares), which every import carries,
	// so whichever package is currently local does not matter here.
	aggResp, err := svc.FrostAggregate(ctx, &pb.FrostAggregateRequest{
		KeyId: keyID, Message: message,
		Commitments: commitments, Shares: shares, Verify: true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, aggResp.Signature)
	assert.True(t, aggResp.Verified, "aggregate's own verify=true pass must succeed")

	// FrostVerify is the standalone verification RPC over the same signature.
	verifyResp, err := svc.FrostVerify(ctx, &pb.FrostVerifyRequest{
		KeyId: keyID, Message: message, Signature: aggResp.Signature,
	})
	require.NoError(t, err)
	assert.True(t, verifyResp.Valid)

	// A tampered message must not verify against the same signature.
	tamperedResp, err := svc.FrostVerify(ctx, &pb.FrostVerifyRequest{
		KeyId: keyID, Message: []byte("tampered"), Signature: aggResp.Signature,
	})
	require.NoError(t, err)
	assert.False(t, tamperedResp.Valid)
}

// TestFrostGetKey_AfterImport proves FrostGetKey returns the imported
// participant's key metadata, including the group public key, rather than
// only being reachable through the authz-denial fixtures.
func TestFrostGetKey_AfterImport(t *testing.T) {
	ctx := context.Background()
	svc := NewService(nil, nil, setupFrostXKMS(t))
	genResp, err := svc.FrostGenerateKey(ctx, &pb.FrostGenerateKeyRequest{
		KeyId: "grpc-get-key", Threshold: 2, Total: 3, DealerMode: true,
	})
	require.NoError(t, err)
	importFrostPackage(t, ctx, svc, genResp.Packages[0])

	resp, err := svc.FrostGetKey(ctx, &pb.FrostGetKeyRequest{KeyId: "grpc-get-key"})
	require.NoError(t, err)
	assert.Equal(t, "grpc-get-key", resp.Key.KeyId)
	assert.Equal(t, genResp.GroupPublicKey, resp.Key.GroupPublicKey)
}

func TestFrostGetKey_NotFound(t *testing.T) {
	svc := NewService(nil, nil, setupFrostXKMS(t))
	_, err := svc.FrostGetKey(context.Background(), &pb.FrostGetKeyRequest{KeyId: "missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestFrostListKeys_AfterImport proves FrostListKeys reports an imported key
// with its group public key resolved, and that the default page limit (no
// offset/limit supplied) is applied rather than leaving the slice empty.
func TestFrostListKeys_AfterImport(t *testing.T) {
	ctx := context.Background()
	svc := NewService(nil, nil, setupFrostXKMS(t))
	genResp, err := svc.FrostGenerateKey(ctx, &pb.FrostGenerateKeyRequest{
		KeyId: "grpc-list-key", Threshold: 2, Total: 3, DealerMode: true,
	})
	require.NoError(t, err)
	importFrostPackage(t, ctx, svc, genResp.Packages[0])

	resp, err := svc.FrostListKeys(ctx, &pb.FrostListKeysRequest{})
	require.NoError(t, err)
	require.Equal(t, int32(1), resp.Total)
	require.Len(t, resp.Keys, 1)
	assert.Equal(t, "grpc-list-key", resp.Keys[0].KeyId)
	assert.Equal(t, genResp.GroupPublicKey, resp.Keys[0].GroupPublicKey)
}

// TestFrostDeleteKey_Success proves a deleted key is actually gone rather
// than merely reporting success.
func TestFrostDeleteKey_Success(t *testing.T) {
	ctx := context.Background()
	svc := NewService(nil, nil, setupFrostXKMS(t))
	genResp, err := svc.FrostGenerateKey(ctx, &pb.FrostGenerateKeyRequest{
		KeyId: "grpc-delete-key", Threshold: 2, Total: 3, DealerMode: true,
	})
	require.NoError(t, err)
	importFrostPackage(t, ctx, svc, genResp.Packages[0])

	resp, err := svc.FrostDeleteKey(ctx, &pb.FrostDeleteKeyRequest{KeyId: "grpc-delete-key"})
	require.NoError(t, err)
	assert.True(t, resp.Success)

	_, err = svc.FrostGetKey(ctx, &pb.FrostGetKeyRequest{KeyId: "grpc-delete-key"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestGetFrostBackend_NoBackendConfigured proves a deployment with no FROST
// backend registered fails closed with Internal (getFrostBackend's own "no
// FROST backend configured" error) rather than by panicking on a nil
// backend list.
func TestGetFrostBackend_NoBackendConfigured(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.FrostListKeys(context.Background(), &pb.FrostListKeysRequest{})
	assert.Equal(t, codes.Internal, status.Code(err))
}

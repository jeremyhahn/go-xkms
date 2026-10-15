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
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newTrustRootGRPC returns a gRPC service over an in-memory trust-root store.
func newTrustRootGRPC(t *testing.T) *Service {
	t.Helper()
	store, err := truststore.NewDAOStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	svc := &xkms.XKMSService{}
	svc.SetTrustRootStore(store)
	return NewService(nil, nil, svc)
}

// trustRootImportProto returns an import request for a fresh self-signed CA
// classified as purpose.
func trustRootImportProto(t *testing.T, purpose string) *pb.TrustRootImportRequest {
	t.Helper()
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	return &pb.TrustRootImportRequest{Pem: string(ca.CertPEM), Purpose: purpose, Source: "grpc"}
}

// TestTrustRootGRPC_ServesTheStore proves the RPCs import, list, get,
// quarantine and remove a root through the store.
func TestTrustRootGRPC_ServesTheStore(t *testing.T) {
	s := newTrustRootGRPC(t)
	ctx := platformScopeCtx(qrdbsdk.SystemTenantID)

	imported, err := s.TrustRootImport(ctx, trustRootImportProto(t, string(truststore.PurposeImageSigner)))
	require.NoError(t, err)
	assert.Equal(t, int32(1), imported.GetAdded())

	list, err := s.TrustRootList(ctx, &pb.TrustRootListRequest{Purpose: string(truststore.PurposeImageSigner)})
	require.NoError(t, err)
	require.Len(t, list.GetRoots(), 1)
	fp := list.GetRoots()[0].GetFingerprint()
	assert.Equal(t, "grpc", list.GetRoots()[0].GetSource())

	root, err := s.TrustRootGet(ctx, &pb.TrustRootRequest{Fingerprint: fp})
	require.NoError(t, err)
	assert.Contains(t, root.GetPem(), "BEGIN CERTIFICATE")

	root, err = s.TrustRootQuarantine(ctx, &pb.TrustRootRequest{Fingerprint: fp})
	require.NoError(t, err)
	assert.Equal(t, string(truststore.PurposeSynced), root.GetPurpose())

	_, err = s.TrustRootRemove(ctx, &pb.TrustRootRequest{Fingerprint: fp})
	require.NoError(t, err)
	_, err = s.TrustRootGet(ctx, &pb.TrustRootRequest{Fingerprint: fp})
	assert.Equal(t, codes.NotFound, status.Code(err), "%v", err)
}

// TestTrustRootGRPC_MapsErrors proves each refusal reaches the wire with the
// code its class maps to.
func TestTrustRootGRPC_MapsErrors(t *testing.T) {
	s := newTrustRootGRPC(t)
	sys := platformScopeCtx(qrdbsdk.SystemTenantID)
	tenant := platformScopeCtx("tenant-a")
	absent := strings.Repeat("0", 64) // well-formed SHA-256, never imported
	tests := map[string]struct {
		err  error
		want codes.Code
	}{
		"tenant caller":         {rpcErr(s.TrustRootList(tenant, &pb.TrustRootListRequest{})), codes.NotFound},
		"tenant import":         {rpcErr(s.TrustRootImport(tenant, trustRootImportProto(t, "user-ca"))), codes.NotFound},
		"unknown root":          {rpcErr(s.TrustRootGet(sys, &pb.TrustRootRequest{Fingerprint: absent})), codes.NotFound},
		"unknown quarantine":    {rpcErr(s.TrustRootQuarantine(sys, &pb.TrustRootRequest{Fingerprint: absent})), codes.NotFound},
		"malformed fingerprint": {rpcErr(s.TrustRootGet(sys, &pb.TrustRootRequest{Fingerprint: "00"})), codes.InvalidArgument},
		"invalid purpose":       {rpcErr(s.TrustRootList(sys, &pb.TrustRootListRequest{Purpose: "bogus"})), codes.InvalidArgument},
		"invalid import":        {rpcErr(s.TrustRootImport(sys, &pb.TrustRootImportRequest{Pem: "not a certificate"})), codes.InvalidArgument},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, status.Code(tt.err), "%v", tt.err)
		})
	}
}

// TestTrustRootGRPC_Unavailable proves an unwired store, or no service at
// all, answers Unavailable.
func TestTrustRootGRPC_Unavailable(t *testing.T) {
	ctx := platformScopeCtx(qrdbsdk.SystemTenantID)
	for name, s := range map[string]*Service{
		"no store":   NewService(nil, nil, &xkms.XKMSService{}),
		"no service": NewService(nil, nil, nil),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.TrustRootList(ctx, &pb.TrustRootListRequest{})
			assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
			_, err = s.TrustRootRemove(ctx, &pb.TrustRootRequest{Fingerprint: "00"})
			assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
		})
	}
}

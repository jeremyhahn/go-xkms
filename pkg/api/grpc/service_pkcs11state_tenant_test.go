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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestServicePKCS11State_TenantComesFromTheIdentity drives #1114 over gRPC
// (and the Unix transport, which serves the same generated service): naming
// another tenant is InvalidArgument, and the caller's own tenant, stated or
// omitted, reaches only its own namespace.
func TestServicePKCS11State_TenantComesFromTheIdentity(t *testing.T) {
	svc, xkmsSvc := newPKCS11StateGRPCService(t)
	ctxB := auth.WithIdentity(t.Context(), &auth.Identity{Subject: "bob", TenantID: "tenant-b"})
	_, err := xkmsSvc.PKCS11StatePut(ctxB, &transport.PKCS11StatePutRequest{Token: "tok0", Key: "pkcs11/tokens/0", Value: []byte("b-state")})
	require.NoError(t, err)

	ctxA := auth.WithIdentity(t.Context(), &auth.Identity{Subject: "alice", TenantID: "tenant-a"})

	_, err = svc.PKCS11StatePut(ctxA, &pb.PKCS11StatePutRequest{TenantId: "tenant-b", Token: "tok0", Key: "pkcs11/tokens/0", Value: []byte("overwrite")})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = svc.PKCS11StateGet(ctxA, &pb.PKCS11StateGetRequest{Token: "tok0/x", Key: "k"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a '/' in the token is refused")

	for _, own := range []string{"", "tenant-a"} {
		resp, err := svc.PKCS11StateGet(ctxA, &pb.PKCS11StateGetRequest{TenantId: own, Token: "tok0", Key: "pkcs11/tokens/0"})
		require.NoError(t, err)
		assert.False(t, resp.Found, "tenant A's namespace does not hold tenant B's record")
	}

	got, err := xkmsSvc.PKCS11StateGet(ctxB, &transport.PKCS11StateGetRequest{Token: "tok0", Key: "pkcs11/tokens/0"})
	require.NoError(t, err)
	assert.Equal(t, []byte("b-state"), got.Value, "the refused cross-tenant write left tenant B's record intact")
}

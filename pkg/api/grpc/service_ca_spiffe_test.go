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
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestSignCSR_ForwardsTenantAndSPIFFEKind proves the gRPC request's tenant
// and SPIFFE kind reach the servicer (go-xkms#1659).
func TestSignCSR_ForwardsTenantAndSPIFFEKind(t *testing.T) {
	svc := NewService(nil, nil, nil)
	signer := &mockCASignCSR{cert: generateTestCert(t)}
	svc.SetCA(signer)

	_, err := svc.SignCSR(context.Background(), &pb.SignCSRRequest{
		CsrPem:     []byte("csr"),
		TenantId:   "tenant-a",
		SpiffeKind: spiffe.KindService,
	})
	require.NoError(t, err)
	require.NotNil(t, signer.got)
	assert.Equal(t, "tenant-a", signer.got.TenantID)
	assert.Equal(t, spiffe.KindService, signer.got.SPIFFEKind)
}

// TestSignCSR_MapsSPIFFEKindRefusals proves each typed SignCSR refusal keeps
// its meaning on the wire instead of collapsing to Internal.
func TestSignCSR_MapsSPIFFEKindRefusals(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"unknown kind", &xkms.ErrValidation{Sentinel: xkms.ErrSPIFFEKindUnknown}, codes.InvalidArgument},
		{"kind without tenant", &xkms.ErrValidation{Sentinel: xkms.ErrSPIFFEKindWithoutTenant}, codes.InvalidArgument},
		{"kind without trust domain", &xkms.ErrValidation{Sentinel: xkms.ErrSPIFFEKindWithoutTrustDomain}, codes.InvalidArgument},
		{"invalid name", &xkms.ErrValidation{Sentinel: xkms.ErrSPIFFENameInvalid}, codes.InvalidArgument},
		{"svc without permission", &xkms.SPIFFEKindPermissionError{
			Kind: spiffe.KindService, Permission: "certs:issue_service", Err: errors.New("denied"),
		}, codes.PermissionDenied},
		{"foreign tenant", qrdbsdk.ErrTenantMissing, codes.NotFound},
		{"ca failure", errors.New("sign failed"), codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewService(nil, nil, nil)
			svc.SetCA(&mockCASignCSR{err: tt.err})

			_, err := svc.SignCSR(context.Background(), &pb.SignCSRRequest{CsrPem: []byte("csr")})
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.want, st.Code())
		})
	}
}

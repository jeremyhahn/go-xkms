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
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/releasesigningtest"
)

func signRequest(corim []byte) *pb.SignReleaseCoRIMRequest {
	return &pb.SignReleaseCoRIMRequest{Repository: releasesigningtest.Repository, Corim: corim}
}

// TestReleaseSigningRPC_SignsWithTheCallersKey: the caller's tenant key signs
// and the response verifies.
func TestReleaseSigningRPC_SignsWithTheCallersKey(t *testing.T) {
	f := releasesigningtest.New(t, releasesigningtest.Tenant, releasesigningtest.SignPermission)
	svc := NewService(nil, nil, f.Service, WithLocalTrust())
	ctx := releasesigningtest.Context(releasesigningtest.Tenant)

	resp, err := svc.SignReleaseCoRIM(ctx, signRequest(releasesigningtest.UnsignedCoRIM(t)))
	require.NoError(t, err)
	assert.Equal(t, appraisal.ReleaseSigningKeyID, resp.GetKeyId())
	verified, err := refvalue.VerifySigned(resp.GetSignedCorim(), refvalue.VerifyOptions{PublicKey: f.ReleaseKey})
	require.NoError(t, err)
	assert.Equal(t, releasesigningtest.Repository, verified.Signer)

	_, err = svc.SignReleaseCoRIM(ctx, signRequest([]byte{0xff}))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestReleaseSigningRPC_Refusals: no sign permission is PermissionDenied, a
// foreign tenant's key is NotFound, nil is InvalidArgument.
func TestReleaseSigningRPC_Refusals(t *testing.T) {
	corim := releasesigningtest.UnsignedCoRIM(t)
	ctx := releasesigningtest.Context(releasesigningtest.Tenant)

	f := releasesigningtest.New(t, releasesigningtest.Tenant, "attestation_signing_keys:get")
	svc := NewService(nil, nil, f.Service, WithLocalTrust())
	_, err := svc.SignReleaseCoRIM(ctx, signRequest(corim))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	f = releasesigningtest.New(t, releasesigningtest.ForeignTenant, releasesigningtest.SignPermission)
	svc = NewService(nil, nil, f.Service, WithLocalTrust())
	resp, err := svc.SignReleaseCoRIM(ctx, signRequest(corim))
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Nil(t, resp)

	_, err = svc.SignReleaseCoRIM(ctx, nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

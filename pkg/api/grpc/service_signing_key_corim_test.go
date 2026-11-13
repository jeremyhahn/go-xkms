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
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestSignCoRIMRPC_SignsWithTenantReleaseKey proves the RPC returns a signed
// CoRIM that verifies under the caller's tenant release key.
func TestSignCoRIMRPC_SignsWithTenantReleaseKey(t *testing.T) {
	s := setupServiceTest(t)
	svc, err := xkms.Get()
	require.NoError(t, err)
	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	appraiser, err := appraisal.NewAppraiser(store)
	require.NoError(t, err)
	svc.SetAttestationAppraiser(appraiser)

	ctx := auth.WithIdentity(t.Context(), &auth.Identity{Subject: "release-manager", TenantID: "acme"})
	key, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: appraisal.ReleaseSigningKeyID, Backend: "software", KeyType: "signing", Algorithm: "ecdsa", Curve: "P-256", TenantID: "acme",
	})
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(key.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)

	unsigned, err := appraisaltest.UnsignedCoRIM(map[uint32][]byte{0: make([]byte, 32)})
	require.NoError(t, err)
	resp, err := s.SignCoRIM(ctx, &pb.SignCoRIMRequest{Repository: "acme/app", Corim: unsigned, SignerName: "Acme"})
	require.NoError(t, err)
	assert.Equal(t, appraisal.ReleaseSigningKeyID, resp.GetKey().GetKeyId())
	assert.True(t, resp.GetKey().GetDefault())
	m, err := refvalue.VerifySigned(resp.GetCorim(), refvalue.VerifyOptions{PublicKey: pub})
	require.NoError(t, err)
	assert.Equal(t, "Acme", m.Signer)

	_, err = s.SignCoRIM(ctx, &pb.SignCoRIMRequest{Repository: "acme/app", Corim: []byte{0xff}, SignerName: "Acme"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a malformed CoRIM is the caller's error")
}

// TestSignCoRIMRPC_Errors proves an invalid repository and a tenant without
// a release key reach the caller as classified status codes.
func TestSignCoRIMRPC_Errors(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	s, ctx := newSigningKeyGRPC(t, authorizer)

	_, err := s.SignCoRIM(ctx, &pb.SignCoRIMRequest{Repository: "Acme/App"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	empty := NewService(authorizer, nil, nil)
	_, err = empty.SignCoRIM(ctx, &pb.SignCoRIMRequest{Repository: "acme/app"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

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

package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const otaTestBoard = "stm32-h7"

// otaPublicKey parses an ECDSA public key from a response's PEM.
func otaPublicKey(t *testing.T, pemText string) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemText))
	require.NotNil(t, block, "response carries no public key PEM")
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ec, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok, "public key is %T, not ECDSA", pub)
	return ec
}

func TestOTAImageKeyRPCs_CreateRotateSign(t *testing.T) {
	s, _ := crossTenantService(t)
	ctx := tenantCtx(crossTenantA)

	created, err := s.CreateOTAImageKey(ctx, &pb.OTAImageKeyRequest{
		BoardId: otaTestBoard, Backend: crossTenantSource, Algorithm: "ES256",
	})
	require.NoError(t, err)
	assert.Equal(t, "ota-image-"+otaTestBoard, created.KeyId)
	assert.Equal(t, elliptic.P256(), otaPublicKey(t, created.PublicKeyPem).Curve)

	rotated, err := s.RotateOTAImageKey(ctx, &pb.OTAImageKeyRequest{
		BoardId: otaTestBoard, Backend: crossTenantSource,
	})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), rotated.KeyVersion)

	digest := sha256.Sum256([]byte("firmware image"))
	signed, err := s.SignOTAImage(ctx, &pb.SignOTAImageRequest{
		BoardId: otaTestBoard, Backend: crossTenantSource, Data: digest[:], DataIsDigest: true,
	})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), signed.KeyVersion, "signs with the current version")
	assert.True(t, ecdsa.VerifyASN1(otaPublicKey(t, rotated.PublicKeyPem), digest[:], signed.Signature),
		"signature does not verify under the rotated key")
}

func TestOTAImageKeyRPCs_InvalidArgument(t *testing.T) {
	s, svc := crossTenantService(t)
	ctx := tenantCtx(crossTenantA)

	// A key created outside the OTA path under a board's key ID, on P-384.
	scoped, err := svc.LookupTenantBackend(crossTenantSource, crossTenantA)
	require.NoError(t, err)
	_, err = scoped.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN:            "ota-image-p384-board",
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()},
	})
	require.NoError(t, err)

	create := func(req *pb.OTAImageKeyRequest) error {
		_, err := s.CreateOTAImageKey(ctx, req)
		return err
	}
	rotate := func(req *pb.OTAImageKeyRequest) error {
		_, err := s.RotateOTAImageKey(ctx, req)
		return err
	}
	sign := func(req *pb.SignOTAImageRequest) error {
		_, err := s.SignOTAImage(ctx, req)
		return err
	}
	tests := []struct {
		name string
		call func() error
	}{
		{"create malformed board id", func() error {
			return create(&pb.OTAImageKeyRequest{BoardId: "Bad--Board", Backend: crossTenantSource})
		}},
		{"create non-ES256 algorithm", func() error {
			return create(&pb.OTAImageKeyRequest{BoardId: otaTestBoard, Backend: crossTenantSource, Algorithm: "RS256"})
		}},
		{"create missing backend", func() error {
			return create(&pb.OTAImageKeyRequest{BoardId: otaTestBoard})
		}},
		{"rotate malformed board id", func() error {
			return rotate(&pb.OTAImageKeyRequest{BoardId: "bad--board", Backend: crossTenantSource})
		}},
		{"rotate non-ES256 algorithm", func() error {
			return rotate(&pb.OTAImageKeyRequest{BoardId: otaTestBoard, Backend: crossTenantSource, Algorithm: "PS256"})
		}},
		{"rotate non-ES256 key", func() error {
			return rotate(&pb.OTAImageKeyRequest{BoardId: "p384-board", Backend: crossTenantSource})
		}},
		{"sign malformed board id", func() error {
			return sign(&pb.SignOTAImageRequest{BoardId: "-board", Backend: crossTenantSource, Data: []byte("image")})
		}},
		{"sign non-ES256 key", func() error {
			return sign(&pb.SignOTAImageRequest{BoardId: "p384-board", Backend: crossTenantSource, Data: []byte("image")})
		}},
		{"sign missing backend", func() error {
			return sign(&pb.SignOTAImageRequest{BoardId: otaTestBoard, Data: []byte("image")})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, codes.InvalidArgument, status.Code(tc.call()))
		})
	}
}

func TestOTAImageKeyRPCs_UnknownBoardKey(t *testing.T) {
	s, _ := crossTenantService(t)

	_, err := s.RotateOTAImageKey(tenantCtx(crossTenantA), &pb.OTAImageKeyRequest{
		BoardId: otaTestBoard, Backend: crossTenantSource,
	})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestOTAImageKeyRPCs_NotInitialized(t *testing.T) {
	s := NewService(nil, nil, nil)
	ctx := tenantCtx(crossTenantA)

	_, err := s.CreateOTAImageKey(ctx, &pb.OTAImageKeyRequest{BoardId: otaTestBoard, Backend: crossTenantSource})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = s.RotateOTAImageKey(ctx, &pb.OTAImageKeyRequest{BoardId: otaTestBoard, Backend: crossTenantSource})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = s.SignOTAImage(ctx, &pb.SignOTAImageRequest{BoardId: otaTestBoard, Backend: crossTenantSource})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

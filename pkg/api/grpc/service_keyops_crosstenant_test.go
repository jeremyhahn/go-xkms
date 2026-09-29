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
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ===========================================================================
// Cross-tenant isolation for the key lifecycle RPCs (go-xkms#1218).
//
// Tenant A, authenticated, names a key that belongs to tenant B. Every one of
// DeleteKey, GetKey, ListKeys, RotateKey, ExportKey and CopyKey must behave as
// if the key did not exist: the same code and the same message a genuinely
// missing key gets, so the response reveals neither the key nor that another
// tenant holds it. Side effects are asserted too -- an RPC that answered
// NotFound after deleting the key would still be a breach.
// ===========================================================================

const (
	crossTenantSource = "primary"
	crossTenantDest   = "replica"
	crossTenantA      = "tenant-a"
	crossTenantB      = "tenant-b"
	crossTenantAKey   = "a-key"
	crossTenantBKey   = "b-key"
	crossTenantWrap   = string(backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
)

// crossTenantService returns a Service over two software backends. The source
// backend holds one exportable ECDSA key for each holder tenant (tenant A and
// tenant B when none are named); the destination backend is empty.
func crossTenantService(t *testing.T, holders ...string) (*Service, *xkms.XKMSService) {
	t.Helper()

	xkms.Reset()
	t.Cleanup(xkms.Reset)

	backends := make(map[string]xkms.Backend, 2)
	for _, name := range []string{crossTenantSource, crossTenantDest} {
		be, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
		require.NoError(t, err)
		ks, err := xkms.New(&xkms.BackendConfig{Backend: be, CertStorage: storage.New()})
		require.NoError(t, err)
		backends[name] = ks
	}
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       backends,
		DefaultBackend: crossTenantSource,
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	keyOf := map[string]string{crossTenantA: crossTenantAKey, crossTenantB: crossTenantBKey}
	if len(holders) == 0 {
		holders = []string{crossTenantA, crossTenantB}
	}
	for _, tenant := range holders {
		cn := keyOf[tenant]
		scoped, err := svc.LookupTenantBackend(crossTenantSource, tenant)
		require.NoError(t, err)
		_, err = scoped.GenerateECDSA(context.Background(), &types.KeyAttributes{
			CN:            cn,
			KeyType:       types.KeyTypeSigning,
			StoreType:     types.StoreSoftware,
			KeyAlgorithm:  x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
			Exportable:    true,
		})
		require.NoError(t, err, "generating %s for %s", cn, tenant)
	}

	return NewService(nil, nil, svc), svc
}

// tenantKeys lists the keys tenantID can see in the named backend.
func tenantKeys(t *testing.T, svc *xkms.XKMSService, backendName, tenantID string) []*types.KeyAttributes {
	t.Helper()
	scoped, err := svc.LookupTenantBackend(backendName, tenantID)
	require.NoError(t, err)
	keys, err := scoped.ListKeys(context.Background())
	require.NoError(t, err)
	return keys
}

// crossTenantRPC names one key-by-ID RPC and how to call it as a caller
// naming keyID.
type crossTenantRPC struct {
	name string
	call func(s *Service, ctx context.Context, keyID string) error
}

func crossTenantRPCs() []crossTenantRPC {
	return []crossTenantRPC{
		{"delete", func(s *Service, ctx context.Context, keyID string) error {
			_, err := s.DeleteKey(ctx, &pb.DeleteKeyRequest{KeyId: keyID, Backend: crossTenantSource})
			return err
		}},
		{"get", func(s *Service, ctx context.Context, keyID string) error {
			_, err := s.GetKey(ctx, &pb.GetKeyRequest{KeyId: keyID, Backend: crossTenantSource})
			return err
		}},
		{"rotate", func(s *Service, ctx context.Context, keyID string) error {
			_, err := s.RotateKey(ctx, &pb.RotateKeyRequest{KeyId: keyID, Backend: crossTenantSource})
			return err
		}},
		{"export", func(s *Service, ctx context.Context, keyID string) error {
			_, err := s.ExportKey(ctx, &pb.ExportKeyRequest{
				KeyId: keyID, Backend: crossTenantSource, WrappingAlgorithm: crossTenantWrap,
			})
			return err
		}},
		{"copy", func(s *Service, ctx context.Context, keyID string) error {
			_, err := s.CopyKey(ctx, &pb.CopyKeyRequest{
				SourceBackend: crossTenantSource, SourceKeyId: keyID,
				DestBackend: crossTenantDest, DestKeyId: "stolen",
				WrappingAlgorithm: crossTenantWrap,
			})
			return err
		}},
	}
}

// TestKeyLifecycleRPCs_CrossTenantRefusalEqualsGenuineMiss is the
// go-xkms#1218 regression for gRPC. For each RPC, tenant A naming tenant B's
// key must get exactly the status -- code and message -- tenant A gets for the
// same key ID in a deployment where no tenant holds it, and tenant B's key
// must survive the attempt. The genuine miss names the same ID so an echoed
// key ID cannot make two equivalent answers look different.
func TestKeyLifecycleRPCs_CrossTenantRefusalEqualsGenuineMiss(t *testing.T) {
	for _, rpc := range crossTenantRPCs() {
		t.Run(rpc.name, func(t *testing.T) {
			ctx := tenantCtx(crossTenantA)

			s, _ := crossTenantService(t, crossTenantA)
			missErr := rpc.call(s, ctx, crossTenantBKey)
			require.Error(t, missErr)
			miss, ok := status.FromError(missErr)
			require.True(t, ok, "not a gRPC status: %v", missErr)
			require.Equal(t, codes.NotFound, miss.Code(),
				"a genuinely missing key must be NotFound: %v", missErr)

			s, svc := crossTenantService(t)
			crossErr := rpc.call(s, ctx, crossTenantBKey)
			require.Error(t, crossErr, "tenant A reached tenant B's key")
			cross, ok := status.FromError(crossErr)
			require.True(t, ok, "not a gRPC status: %v", crossErr)
			assert.Equal(t, miss.Code(), cross.Code())
			assert.Equal(t, miss.Message(), cross.Message(),
				"a cross-tenant refusal must be indistinguishable from a genuine miss")

			keys := tenantKeys(t, svc, crossTenantSource, crossTenantB)
			require.Len(t, keys, 1, "tenant B lost its key to tenant A")
			assert.Empty(t, tenantKeys(t, svc, crossTenantDest, ""),
				"no key may be created in the destination backend")
		})
	}
}

// TestRotateKey_CrossTenantDoesNotReplaceKey pins the rotation side effect
// precisely: tenant B's public key after tenant A's attempt must be the one
// it had before.
func TestRotateKey_CrossTenantDoesNotReplaceKey(t *testing.T) {
	s, svc := crossTenantService(t)
	scopedB, err := svc.LookupTenantBackend(crossTenantSource, crossTenantB)
	require.NoError(t, err)
	attrs := tenantKeys(t, svc, crossTenantSource, crossTenantB)[0]
	before, err := scopedB.GetKey(context.Background(), attrs)
	require.NoError(t, err)

	_, err = s.RotateKey(tenantCtx(crossTenantA), &pb.RotateKeyRequest{
		KeyId: crossTenantBKey, Backend: crossTenantSource,
	})
	require.Equal(t, codes.NotFound, status.Code(err), "%v", err)

	after, err := scopedB.GetKey(context.Background(), attrs)
	require.NoError(t, err)
	assert.Equal(t, publicKeyDER(t, before), publicKeyDER(t, after),
		"tenant A rotated tenant B's key")
}

// TestListKeys_ShowsOnlyTheCallersKeys proves a tenant listing a shared
// backend sees its own key and never another tenant's, and that the total
// does not count another tenant's keys.
func TestListKeys_ShowsOnlyTheCallersKeys(t *testing.T) {
	s, _ := crossTenantService(t)

	resp, err := s.ListKeys(tenantCtx(crossTenantA), &pb.ListKeysRequest{Backend: crossTenantSource})
	require.NoError(t, err)

	ids := make([]string, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		ids = append(ids, k.KeyId)
	}
	assert.Equal(t, []string{crossTenantAKey}, ids, "tenant A must see exactly its own key")
	assert.Equal(t, int32(1), resp.Total, "the total must not count another tenant's keys")
}

// TestKeyLifecycleRPCs_OwnKeyStillReachable is the positive control: the same
// RPCs, naming tenant A's own key, succeed. Without it, an RPC that refused
// every request would pass the isolation tests above.
func TestKeyLifecycleRPCs_OwnKeyStillReachable(t *testing.T) {
	for _, rpc := range crossTenantRPCs() {
		t.Run(rpc.name, func(t *testing.T) {
			s, _ := crossTenantService(t)
			assert.NoError(t, rpc.call(s, tenantCtx(crossTenantA), crossTenantAKey))
		})
	}
}

// TestCopyKey_CopyStaysInTheCallersTenant proves the copy a tenant makes of
// its own key lands in that tenant's scope in the destination: visible to the
// copying tenant and to no other. gRPC used to import the copy through an
// unscoped destination backend, so it landed with no tenant at all.
func TestCopyKey_CopyStaysInTheCallersTenant(t *testing.T) {
	s, svc := crossTenantService(t)

	_, err := s.CopyKey(tenantCtx(crossTenantA), &pb.CopyKeyRequest{
		SourceBackend: crossTenantSource, SourceKeyId: crossTenantAKey,
		DestBackend: crossTenantDest, DestKeyId: "a-copy",
		WrappingAlgorithm: crossTenantWrap,
	})
	require.NoError(t, err)

	own := tenantKeys(t, svc, crossTenantDest, crossTenantA)
	require.Len(t, own, 1, "the copy must be visible to the tenant that made it")
	assert.Equal(t, "a-copy", own[0].CN)
	assert.Equal(t, crossTenantA, own[0].TenantID)
	assert.Empty(t, tenantKeys(t, svc, crossTenantDest, crossTenantB),
		"the copy must not be visible to another tenant")
}

// publicKeyDER returns the PKIX DER encoding of key's public half.
func publicKeyDER(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()
	signer, ok := key.(crypto.Signer)
	require.True(t, ok, "%T is not a crypto.Signer", key)
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(t, err)
	return der
}

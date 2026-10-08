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

package embeddednode

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// cloudSealStores maps every cloud strategy to the key store its seal key
// lives in.
var cloudSealStores = map[seal.StrategyID]types.StoreType{
	seal.StrategyAWSKMS:  types.StoreAWSKMS,
	seal.StrategyGCPKMS:  types.StoreGCPKMS,
	seal.StrategyAzureKV: types.StoreAzureKV,
	seal.StrategyVault:   types.StoreVault,
}

// kmsSealer stands in for a cloud KMS: it seals under one AES-256-GCM key
// that never leaves it, so only the same instance can unseal what it sealed.
type kmsSealer struct {
	aead cipher.AEAD
}

func newKMSSealer(t *testing.T) *kmsSealer {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return &kmsSealer{aead: aead}
}

func (k *kmsSealer) Seal(_ context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &types.SealedData{
		Ciphertext: k.aead.Seal(nil, nonce, data, nil),
		Nonce:      nonce,
		KeyID:      opts.KeyAttributes.CN,
	}, nil
}

func (k *kmsSealer) Unseal(_ context.Context, sealed *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	return k.aead.Open(nil, sealed.Nonce, sealed.Ciphertext, nil)
}

func (k *kmsSealer) CanSeal() bool { return true }

// cloudNodeSeal returns the node seal a cloud strategy resolves to, sealing
// through sealer.
func cloudNodeSealThrough(id seal.StrategyID, sealer types.Sealer) ResolvedNodeSeal {
	strategy := seal.NewCloudKMSStrategy(id, sealer, seal.SealKeyAttributes(cloudSealStores[id]), nil)
	return ResolvedNodeSeal{Enabled: true, Strategy: strategy}
}

func cloudNodeSealConfig(t *testing.T, id seal.StrategyID) *config.Config {
	t.Helper()
	return &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
		Barrier:   config.BarrierConfig{Enabled: true, Strategy: string(id)},
	}
}

// TestOpenEmbeddedNode_CloudSealAutoUnsealsAcrossBoots proves every cloud
// strategy, injected through NodeSealOptions, seals the node's own barrier
// on first boot and unseals it unattended on the next.
func TestOpenEmbeddedNode_CloudSealAutoUnsealsAcrossBoots(t *testing.T) {
	for id := range cloudSealStores {
		t.Run(string(id), func(t *testing.T) {
			cfg := cloudNodeSealConfig(t, id)
			sealer := newKMSSealer(t)
			for boot := 1; boot <= 2; boot++ {
				node, err := openEmbeddedNodeWithSeal(context.Background(),
					EmbeddedNodeOptions{Config: cfg, Logger: testLogger()}, cloudNodeSealThrough(id, sealer))
				require.NoError(t, err, "boot %d", boot)
				require.False(t, node.IsSealed(), "boot %d: a %s node seal must unseal unattended", boot, id)
				require.NotNil(t, node.BarrierRegistry(), "boot %d", boot)
				require.NoError(t, node.Close())
			}
		})
	}
}

// TestOpenEmbeddedNode_CloudSealUnderAnotherKeyStaysSealed proves a node
// whose root key was sealed under one KMS key does not open under another:
// the barrier stays sealed rather than serving data.
func TestOpenEmbeddedNode_CloudSealUnderAnotherKeyStaysSealed(t *testing.T) {
	cfg := cloudNodeSealConfig(t, seal.StrategyAWSKMS)
	opts := EmbeddedNodeOptions{Config: cfg, Logger: testLogger()}

	node, err := openEmbeddedNodeWithSeal(context.Background(), opts,
		cloudNodeSealThrough(seal.StrategyAWSKMS, newKMSSealer(t)))
	require.NoError(t, err)
	require.False(t, node.IsSealed())
	require.NoError(t, node.Close())

	node, err = openEmbeddedNodeWithSeal(context.Background(), opts,
		cloudNodeSealThrough(seal.StrategyAWSKMS, newKMSSealer(t)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	require.True(t, node.IsSealed(), "a root key sealed under another KMS key must not unseal")

	err = node.Unseal(context.Background(), seal.Credentials{})
	require.ErrorIs(t, err, qrdbsdk.ErrInvalidCredentials)
	var unsealErr *seal.RootKeyUnsealError
	require.ErrorAs(t, err, &unsealErr)
	require.True(t, node.IsSealed())
}

// TestTenantBarrier_CloudSealRoundTrip proves a cloud strategy seals and
// unseals a per-tenant barrier built with go-qrdb's NewTenantBarrier.
func TestTenantBarrier_CloudSealRoundTrip(t *testing.T) {
	ctx := context.Background()
	strategy := cloudNodeSealThrough(seal.StrategyGCPKMS, newKMSSealer(t)).Strategy
	tb := newCloudTenantBarrier(t, qrdbsdk.NewMemoryBackend(), strategy)

	require.NoError(t, tb.Initialize(ctx, seal.Credentials{}))
	require.NoError(t, tb.Put(ctx, "secret", []byte("value")))
	require.NoError(t, tb.Seal())
	require.True(t, tb.IsSealed())
	_, err := tb.Get(ctx, "secret")
	require.ErrorIs(t, err, qrdbsdk.ErrSealed)

	require.NoError(t, tb.Unseal(ctx, seal.Credentials{}))
	got, err := tb.Get(ctx, "secret")
	require.NoError(t, err)
	require.Equal(t, []byte("value"), got)
}

// TestTenantBarrier_CloudSealUnderAnotherKeyIsATypedError proves a tenant
// barrier sealed under one KMS key refuses another with go-qrdb's typed
// unseal error, and stays sealed.
func TestTenantBarrier_CloudSealUnderAnotherKeyIsATypedError(t *testing.T) {
	ctx := context.Background()
	base := qrdbsdk.NewMemoryBackend()
	sealedUnder := cloudNodeSealThrough(seal.StrategyVault, newKMSSealer(t)).Strategy
	tb := newCloudTenantBarrier(t, base, sealedUnder)
	require.NoError(t, tb.Initialize(ctx, seal.Credentials{}))
	require.NoError(t, tb.Seal())

	other := cloudNodeSealThrough(seal.StrategyVault, newKMSSealer(t)).Strategy
	reopened := newCloudTenantBarrier(t, base, other)
	err := reopened.Unseal(ctx, seal.Credentials{})
	require.ErrorIs(t, err, qrdbsdk.ErrInvalidCredentials)
	var unsealErr *seal.RootKeyUnsealError
	require.ErrorAs(t, err, &unsealErr)
	require.Equal(t, seal.StrategyVault, unsealErr.Strategy)
	require.True(t, reopened.IsSealed())
}

func newCloudTenantBarrier(t *testing.T, base qrdbsdk.StorageBackend, strategy seal.SealingStrategy) *qrdbsdk.TenantBarrier {
	t.Helper()
	tb, err := qrdbsdk.NewTenantBarrier("tenant-a", testLogger(), base, qrdbsdk.BarrierConfig{
		PreferenceOrder: []seal.StrategyID{strategy.ID()},
		RootKeyPath:     "core/root-key",
	}, strategy)
	require.NoError(t, err)
	return tb
}

// TestNodeSealOptions_InjectsTheStrategy proves a resolved strategy reaches
// the node and its tenant barriers alongside tenant isolation, that a seal
// go-qrdb builds itself gets tenant isolation alone, and that a disabled seal
// injects nothing.
func TestNodeSealOptions_InjectsTheStrategy(t *testing.T) {
	nodeOpts, serverOpts, err := NodeSealOptions(cloudNodeSealThrough(seal.StrategyAzureKV, newKMSSealer(t)))
	require.NoError(t, err)
	require.Len(t, nodeOpts, 3)
	require.Len(t, serverOpts, 1)

	nodeOpts, serverOpts, err = NodeSealOptions(ResolvedNodeSeal{Enabled: true})
	require.NoError(t, err)
	require.Len(t, nodeOpts, 2)
	require.Empty(t, serverOpts)

	nodeOpts, serverOpts, err = NodeSealOptions(ResolvedNodeSeal{})
	require.NoError(t, err)
	require.Empty(t, nodeOpts)
	require.Empty(t, serverOpts)
}

// TestOpenEmbeddedNode_TenantsGetEveryIsolationMode proves the node opened
// for an enabled seal admits its tenants under the operator default
// entitlements, not go-qrdb's prefix-only default: a barrier-isolated,
// system-managed tenant clears the entitlement gate.
func TestOpenEmbeddedNode_TenantsGetEveryIsolationMode(t *testing.T) {
	cfg := cloudNodeSealConfig(t, seal.StrategyGCPKMS)
	node, err := openEmbeddedNodeWithSeal(context.Background(), EmbeddedNodeOptions{Config: cfg, Logger: testLogger()},
		cloudNodeSealThrough(seal.StrategyGCPKMS, newKMSSealer(t)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })

	_, err = node.Services().Tenant.CreateTenant(context.Background(), "tenant-a", "Tenant A",
		qrdbsdk.TenantIsolationBarrier, qrdbsdk.WithBarrierAutoUnseal(true))
	var entErr *qrdbsdk.EntitlementError
	require.False(t, errors.As(err, &entErr), "the operator default entitlements refused the tenant: %v", err)
}

// TestTenantDefaultEntitlements_PermitsEveryIsolationMode pins the operator
// default: every isolation tier and the system-managed auto-unseal mode.
func TestTenantDefaultEntitlements_PermitsEveryIsolationMode(t *testing.T) {
	ent := tenantDefaultEntitlements()
	require.ElementsMatch(t, []string{
		string(qrdbsdk.TenantIsolationPrefix),
		string(qrdbsdk.TenantIsolationBarrier),
		string(qrdbsdk.TenantIsolationVolume),
		string(qrdbsdk.TenantIsolationRaft),
	}, ent.AllowedIsolationModes)
	require.True(t, ent.AllowSystemManagedBarrier)
	require.True(t, ent.AllowVolumeStorage)
	require.True(t, ent.AllowDedicatedRaft)
	require.True(t, ent.AllowDedicatedWAL)
	require.NotSame(t, ent, tenantDefaultEntitlements(), "each caller gets its own copy")
}

// TestNodeSealOptions_UnregistrableStrategyFailsClosed proves a strategy the
// registry refuses -- here one claiming go-qrdb's built-in "passphrase" ID --
// is an error, never a node opened without its seal.
func TestNodeSealOptions_UnregistrableStrategyFailsClosed(t *testing.T) {
	strategy := seal.NewCloudKMSStrategy("passphrase", newKMSSealer(t), seal.SealKeyAttributes(types.StoreAWSKMS), nil)
	_, _, err := NodeSealOptions(ResolvedNodeSeal{Enabled: true, Strategy: strategy})
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
}

// TestResolveNodeSeal_UnknownStrategyFailsClosed proves a strategy no
// resolver knows is refused instead of leaving the data plane unsealed.
func TestResolveNodeSeal_UnknownStrategyFailsClosed(t *testing.T) {
	cfg := cloudNodeSealConfig(t, "rot13")
	res, err := ResolveNodeSeal(cfg, testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.Contains(t, nodeErr.Reason, "unknown barrier strategy")
	require.False(t, res.Enabled)
}

// TestResolveCloudNodeSeal_NotCompiledInFailsClosed proves a cloud strategy
// whose provider is absent from the binary names the missing build tag.
func TestResolveCloudNodeSeal_NotCompiledInFailsClosed(t *testing.T) {
	registered, ok := cloudNodeSeals[seal.StrategyAWSKMS]
	delete(cloudNodeSeals, seal.StrategyAWSKMS)
	t.Cleanup(func() {
		if ok {
			cloudNodeSeals[seal.StrategyAWSKMS] = registered
		}
	})

	_, err := resolveCloudNodeSeal(context.Background(), cloudNodeSealConfig(t, seal.StrategyAWSKMS), "awskms", testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.Contains(t, nodeErr.Reason, "build tag awskms")
}

// TestResolveCloudNodeSeal_RequiresDatastorePath proves the seal key
// metadata is never written relative to the working directory.
func TestResolveCloudNodeSeal_RequiresDatastorePath(t *testing.T) {
	withCloudNodeSeal(t, seal.StrategyAWSKMS, func(context.Context, *config.Config, storage.Backend, *slog.Logger) (types.KeyProvider, error) {
		t.Fatal("the backend must not be built without a datastore path")
		return nil, nil
	})
	cfg := cloudNodeSealConfig(t, seal.StrategyAWSKMS)
	cfg.Datastore.Path = ""

	_, err := resolveCloudNodeSeal(context.Background(), cfg, "awskms", testLogger())
	var pathErr *ErrDatastorePathRequired
	require.ErrorAs(t, err, &pathErr)
}

// TestResolveCloudNodeSeal_BackendErrorFailsClosed proves a backend that
// cannot be built is a NodeSealError carrying the cause.
func TestResolveCloudNodeSeal_BackendErrorFailsClosed(t *testing.T) {
	cause := errors.New("no ambient credentials")
	withCloudNodeSeal(t, seal.StrategyAWSKMS, func(context.Context, *config.Config, storage.Backend, *slog.Logger) (types.KeyProvider, error) {
		return nil, cause
	})

	res, err := resolveCloudNodeSeal(context.Background(), cloudNodeSealConfig(t, seal.StrategyAWSKMS), "awskms", testLogger())
	var nodeErr *NodeSealError
	require.ErrorAs(t, err, &nodeErr)
	require.ErrorIs(t, err, cause)
	require.False(t, res.Enabled)
}

// withCloudNodeSeal registers backend as id's node seal for one test.
func withCloudNodeSeal(t *testing.T, id seal.StrategyID, backend cloudNodeSealBackend) {
	t.Helper()
	registered, ok := cloudNodeSeals[id]
	registerCloudNodeSeal(id, cloudSealStores[id], backend)
	t.Cleanup(func() {
		if ok {
			cloudNodeSeals[id] = registered
			return
		}
		delete(cloudNodeSeals, id)
	})
}

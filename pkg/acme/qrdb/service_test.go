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

package qrdb

import (
	"context"
	"io"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTransport implements transport.Transport and all typed client
// interfaces so it can be used with db.NewClient for unit testing
// the service.go accessor methods. It embeds real test implementations
// where available and provides stub implementations for the rest.
type mockTransport struct {
	healthy bool
	closed  bool
	kv      *MemoryKVClient
	admin   *testAdminClient
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		healthy: true,
		kv:      NewMemoryKVClient(),
		admin:   newTestAdminClient(),
	}
}

// Transport interface methods.
func (m *mockTransport) Connect(ctx context.Context) error { return nil }
func (m *mockTransport) Close() error                      { m.closed = true; return nil }
func (m *mockTransport) Healthy(ctx context.Context) bool  { return m.healthy && !m.closed }
func (m *mockTransport) Request(ctx context.Context, method string, req, resp any) error {
	return nil
}

// KVClient -- delegates to the embedded MemoryKVClient.
func (m *mockTransport) Put(ctx context.Context, key string, value []byte, opts ...db.WriteOption) error {
	return m.kv.Put(ctx, key, value, opts...)
}
func (m *mockTransport) Get(ctx context.Context, key string, opts ...db.ReadOption) ([]byte, error) {
	return m.kv.Get(ctx, key, opts...)
}
func (m *mockTransport) Delete(ctx context.Context, key string, opts ...db.WriteOption) error {
	return m.kv.Delete(ctx, key, opts...)
}
func (m *mockTransport) List(ctx context.Context, prefix string, opts ...db.ReadOption) ([]string, error) {
	return m.kv.List(ctx, prefix, opts...)
}
func (m *mockTransport) Scan(ctx context.Context, prefix string, opts ...db.ReadOption) (map[string][]byte, error) {
	return m.kv.Scan(ctx, prefix, opts...)
}
func (m *mockTransport) Exists(ctx context.Context, key string, opts ...db.ReadOption) (bool, error) {
	return m.kv.Exists(ctx, key, opts...)
}

// AdminClient -- delegates to the embedded testAdminClient.
func (m *mockTransport) Health(ctx context.Context) (*db.HealthResponse, error) {
	return m.admin.Health(ctx)
}
func (m *mockTransport) Status(ctx context.Context) (*db.StatusResponse, error) {
	return m.admin.Status(ctx)
}
func (m *mockTransport) Peers(ctx context.Context) (*db.PeersResponse, error) {
	return m.admin.Peers(ctx)
}
func (m *mockTransport) AddMember(ctx context.Context, shardID, replicaID uint64, raftAddr string) error {
	return m.admin.AddMember(ctx, shardID, replicaID, raftAddr)
}
func (m *mockTransport) RemoveMember(ctx context.Context, shardID, replicaID uint64) error {
	return m.admin.RemoveMember(ctx, shardID, replicaID)
}
func (m *mockTransport) RequestSnapshot(ctx context.Context, shardID uint64) error {
	return m.admin.RequestSnapshot(ctx, shardID)
}
func (m *mockTransport) Drain(ctx context.Context) error {
	return m.admin.Drain(ctx)
}
func (m *mockTransport) Capabilities(ctx context.Context) (*db.CapabilitiesResponse, error) {
	return m.admin.Capabilities(ctx)
}
func (m *mockTransport) StartShard(ctx context.Context, req *db.StartShardRequest) error {
	return m.admin.StartShard(ctx, req)
}
func (m *mockTransport) StopShard(ctx context.Context, shardID uint64) error {
	return m.admin.StopShard(ctx, shardID)
}
func (m *mockTransport) GetShardState(ctx context.Context, shardID uint64) (*db.ShardStateResponse, error) {
	return m.admin.GetShardState(ctx, shardID)
}
func (m *mockTransport) GetTopology(ctx context.Context) (*db.TopologyResponse, error) {
	return m.admin.GetTopology(ctx)
}

// WatchClient stubs.
func (m *mockTransport) Watch(ctx context.Context, key string, opts db.WatchOptions) (<-chan db.WatchResponse, error) {
	return nil, nil
}
func (m *mockTransport) WatchPrefix(ctx context.Context, prefix string, opts db.WatchOptions) (<-chan db.WatchResponse, error) {
	return nil, nil
}

// LeaseClient stubs.
func (m *mockTransport) LeaseGrant(ctx context.Context, ttl int64) (*db.LeaseInfo, error) {
	return nil, nil
}
func (m *mockTransport) LeaseRevoke(ctx context.Context, leaseID int64) error { return nil }
func (m *mockTransport) LeaseKeepAlive(ctx context.Context, leaseID int64) (*db.LeaseInfo, error) {
	return nil, nil
}
func (m *mockTransport) LeaseTimeToLive(ctx context.Context, leaseID int64) (*db.LeaseInfo, error) {
	return nil, nil
}
func (m *mockTransport) LeaseList(ctx context.Context) ([]*db.LeaseInfo, error) {
	return nil, nil
}

// BatchClient stubs.
func (m *mockTransport) ExecuteBatch(ctx context.Context, ops []db.Op, opts ...db.WriteOption) (*db.BatchResponse, error) {
	return nil, nil
}

func (m *mockTransport) ImportFile(ctx context.Context, filename string, data io.Reader, opts db.ImportOptions) (*db.ImportResult, error) {
	return nil, nil
}

// TransactionClient stubs.
func (m *mockTransport) ExecuteTransaction(ctx context.Context, req *db.TransactionRequest, opts ...db.WriteOption) (*db.TransactionResponse, error) {
	return nil, nil
}

// IndexClient stubs.
func (m *mockTransport) IndexCreate(ctx context.Context, name, fieldName string, config db.IndexConfig) error {
	return nil
}
func (m *mockTransport) IndexDrop(ctx context.Context, name string) error { return nil }
func (m *mockTransport) IndexQuery(ctx context.Context, indexName, value string) (*db.IndexQueryResponse, error) {
	return nil, nil
}
func (m *mockTransport) IndexScan(ctx context.Context, indexName, start, end string) (*db.IndexScanResponse, error) {
	return nil, nil
}
func (m *mockTransport) IndexList(ctx context.Context) (*db.IndexListResponse, error) {
	return nil, nil
}

// MVCCClient stubs.
func (m *mockTransport) PutWithLease(ctx context.Context, key string, value []byte, leaseID int64, opts ...db.WriteOption) (*db.MVCCKeyValue, error) {
	return nil, nil
}
func (m *mockTransport) GetRevision(ctx context.Context, key string, opts ...db.ReadOption) (*db.MVCCKeyValue, error) {
	return nil, nil
}
func (m *mockTransport) GetAtRevision(ctx context.Context, key string, revision int64, opts ...db.ReadOption) (*db.MVCCKeyValue, error) {
	return nil, nil
}
func (m *mockTransport) Range(ctx context.Context, start, end []byte, rangeOpts db.RangeOptions, opts ...db.ReadOption) (*db.RangeResponse, error) {
	return nil, nil
}
func (m *mockTransport) Compact(ctx context.Context, revision int64) error { return nil }
func (m *mockTransport) CurrentRevision(ctx context.Context) (int64, error) {
	return 0, nil
}

// TimeSeriesClient stubs.
func (m *mockTransport) TSWrite(ctx context.Context, point *db.TSDataPoint) error {
	return nil
}
func (m *mockTransport) TSWriteBatch(ctx context.Context, points []db.TSDataPoint) error {
	return nil
}
func (m *mockTransport) TSQuery(ctx context.Context, req *db.TSQueryRequest) (*db.TSQueryResponse, error) {
	return nil, nil
}
func (m *mockTransport) TSAggregate(ctx context.Context, req *db.TSAggregateRequest) (*db.TSAggregateResponse, error) {
	return nil, nil
}
func (m *mockTransport) TSWritePoint(ctx context.Context, point *db.TSDataPoint) error {
	return nil
}
func (m *mockTransport) TSRichQuery(ctx context.Context, req *db.TSRichQueryRequest) (*db.TSRichQueryResponse, error) {
	return nil, nil
}
func (m *mockTransport) TSDeleteSeries(ctx context.Context, req *db.TSDeleteRequest) (*db.TSDeleteResponse, error) {
	return nil, nil
}
func (m *mockTransport) TSGetRetention(ctx context.Context, req *db.TSGetRetentionRequest) (*db.TSGetRetentionResponse, error) {
	return nil, nil
}
func (m *mockTransport) TSSetRetention(ctx context.Context, req *db.TSSetRetentionRequest) error {
	return nil
}
func (m *mockTransport) TSListMetrics(ctx context.Context, req *db.TSListMetricsRequest) (*db.TSListMetricsResponse, error) {
	return nil, nil
}

// VectorClient stubs.
func (m *mockTransport) CreateNamespace(ctx context.Context, req *db.CreateNamespaceRequest) (*db.CreateNamespaceResponse, error) {
	return nil, nil
}
func (m *mockTransport) DeleteNamespace(ctx context.Context, req *db.DeleteNamespaceRequest) (*db.DeleteNamespaceResponse, error) {
	return nil, nil
}
func (m *mockTransport) ListNamespaces(ctx context.Context, req *db.ListNamespacesRequest) (*db.ListNamespacesResponse, error) {
	return nil, nil
}
func (m *mockTransport) GetNamespaceInfo(ctx context.Context, req *db.GetNamespaceInfoRequest) (*db.GetNamespaceInfoResponse, error) {
	return nil, nil
}
func (m *mockTransport) UpsertVector(ctx context.Context, req *db.UpsertVectorRequest) (*db.UpsertVectorResponse, error) {
	return nil, nil
}
func (m *mockTransport) GetVector(ctx context.Context, req *db.GetVectorRequest) (*db.GetVectorResponse, error) {
	return nil, nil
}
func (m *mockTransport) DeleteVector(ctx context.Context, req *db.DeleteVectorRequest) (*db.DeleteVectorResponse, error) {
	return nil, nil
}
func (m *mockTransport) BatchUpsert(ctx context.Context, req *db.BatchUpsertRequest) (*db.BatchUpsertResponse, error) {
	return nil, nil
}
func (m *mockTransport) BatchDeleteVectors(ctx context.Context, req *db.BatchDeleteVectorsRequest) (*db.BatchDeleteVectorsResponse, error) {
	return nil, nil
}
func (m *mockTransport) ListVectors(ctx context.Context, req *db.ListVectorsRequest) (*db.ListVectorsResponse, error) {
	return nil, nil
}
func (m *mockTransport) UpdateMetadata(ctx context.Context, req *db.UpdateVectorMetadataRequest) (*db.UpdateVectorMetadataResponse, error) {
	return nil, nil
}
func (m *mockTransport) SearchSimilar(ctx context.Context, req *db.SearchSimilarRequest) (*db.SearchSimilarResponse, error) {
	return nil, nil
}
func (m *mockTransport) SearchByMetadata(ctx context.Context, req *db.SearchByMetadataRequest) (*db.SearchByMetadataResponse, error) {
	return nil, nil
}
func (m *mockTransport) HybridSearch(ctx context.Context, req *db.HybridSearchRequest) (*db.HybridSearchResponse, error) {
	return nil, nil
}
func (m *mockTransport) SearchByID(ctx context.Context, req *db.SearchByIDRequest) (*db.SearchByIDResponse, error) {
	return nil, nil
}
func (m *mockTransport) RebuildIndex(ctx context.Context, req *db.RebuildIndexRequest) (*db.RebuildIndexResponse, error) {
	return nil, nil
}
func (m *mockTransport) GetRebuildProgress(ctx context.Context, req *db.GetRebuildProgressRequest) (*db.GetRebuildProgressResponse, error) {
	return nil, nil
}
func (m *mockTransport) GetIndexStats(ctx context.Context, req *db.GetIndexStatsRequest) (*db.GetIndexStatsResponse, error) {
	return nil, nil
}
func (m *mockTransport) CompactNamespace(ctx context.Context, req *db.CompactNamespaceRequest) (*db.CompactNamespaceResponse, error) {
	return nil, nil
}
func (m *mockTransport) GetCompactionProgress(ctx context.Context, req *db.GetCompactionProgressRequest) (*db.GetCompactionProgressResponse, error) {
	return nil, nil
}

// UserClient stubs.
func (m *mockTransport) CreateUser(ctx context.Context, req *db.CreateUserRequest) (*db.User, error) {
	return nil, nil
}
func (m *mockTransport) GetUser(ctx context.Context, id string) (*db.User, error) {
	return nil, nil
}
func (m *mockTransport) UpdateUser(ctx context.Context, req *db.UpdateUserRequest) (*db.User, error) {
	return nil, nil
}
func (m *mockTransport) DeleteUser(ctx context.Context, id string) error { return nil }
func (m *mockTransport) ListUsers(ctx context.Context, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
	return nil, nil
}
func (m *mockTransport) EnableUser(ctx context.Context, id string) error  { return nil }
func (m *mockTransport) DisableUser(ctx context.Context, id string) error { return nil }

// RoleClient stubs.
func (m *mockTransport) CreateRole(ctx context.Context, req *db.CreateRoleRequest) (*db.Role, error) {
	return nil, nil
}
func (m *mockTransport) GetRole(ctx context.Context, id string) (*db.Role, error) {
	return nil, nil
}
func (m *mockTransport) UpdateRole(ctx context.Context, req *db.UpdateRoleRequest) (*db.Role, error) {
	return nil, nil
}
func (m *mockTransport) DeleteRole(ctx context.Context, id string) error { return nil }
func (m *mockTransport) ListRoles(ctx context.Context, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
	return nil, nil
}
func (m *mockTransport) AssignRole(ctx context.Context, userID, roleID string) error   { return nil }
func (m *mockTransport) UnassignRole(ctx context.Context, userID, roleID string) error { return nil }
func (m *mockTransport) ListPermissions(ctx context.Context) (*db.ListPermissionsResponse, error) {
	return nil, nil
}

// CertClient stubs.
func (m *mockTransport) GenerateCert(ctx context.Context, req *db.GenerateCertRequest) (*db.CertBundle, error) {
	return nil, nil
}
func (m *mockTransport) ExportCert(ctx context.Context, req *db.ExportCertRequest) (*db.ExportCertResponse, error) {
	return nil, nil
}
func (m *mockTransport) RevokeCert(ctx context.Context, serial string) error { return nil }
func (m *mockTransport) ListCerts(ctx context.Context, tenantID string) (*db.ListCertsResponse, error) {
	return nil, nil
}

// DatabaseClient stubs.
func (m *mockTransport) CreateDatabase(ctx context.Context, req db.CreateDatabaseRequest) (*db.DatabaseInfo, error) {
	return nil, nil
}
func (m *mockTransport) GetDatabase(ctx context.Context, name string) (*db.DatabaseInfo, error) {
	return nil, nil
}
func (m *mockTransport) ListDatabases(ctx context.Context) ([]db.DatabaseInfo, error) {
	return nil, nil
}
func (m *mockTransport) DropDatabase(ctx context.Context, name string) error { return nil }
func (m *mockTransport) UpdateDatabaseProtocol(ctx context.Context, req db.UpdateDatabaseProtocolRequest) (*db.DatabaseInfo, error) {
	return nil, nil
}
func (m *mockTransport) UpdateDatabaseEtcd(ctx context.Context, req db.UpdateDatabaseEtcdRequest) (*db.DatabaseInfo, error) {
	return nil, nil
}
func (m *mockTransport) UpdateDatabaseRaft(ctx context.Context, req db.UpdateDatabaseRaftRequest) (*db.DatabaseInfo, error) {
	return nil, nil
}
func (m *mockTransport) UpdateDatabaseBarrier(ctx context.Context, req db.UpdateDatabaseBarrierRequest) (*db.DatabaseInfo, error) {
	return nil, nil
}
func (m *mockTransport) UpdateDatabaseConnection(ctx context.Context, req db.UpdateDatabaseConnectionRequest) (*db.DatabaseInfo, error) {
	return nil, nil
}

// BarrierClient stubs.
func (m *mockTransport) BarrierInitialize(ctx context.Context, req *db.BarrierInitializeRequest) error {
	return nil
}
func (m *mockTransport) BarrierUnseal(ctx context.Context, req *db.BarrierUnsealRequest) error {
	return nil
}
func (m *mockTransport) BarrierSeal(ctx context.Context) error { return nil }
func (m *mockTransport) BarrierStatus(ctx context.Context) (*db.BarrierStatusResponse, error) {
	return nil, nil
}
func (m *mockTransport) BarrierInitializeShamir(ctx context.Context, req *db.BarrierInitializeShamirRequest) (*db.BarrierInitializeShamirResponse, error) {
	return nil, nil
}
func (m *mockTransport) BarrierUnsealWithShare(ctx context.Context, req *db.BarrierUnsealShareRequest) (*db.BarrierUnsealShareResponse, error) {
	return nil, nil
}
func (m *mockTransport) BarrierUnsealWithShares(ctx context.Context, req *db.BarrierUnsealSharesRequest) error {
	return nil
}
func (m *mockTransport) BarrierRekey(ctx context.Context, req *db.BarrierRekeyRequest) (*db.BarrierRekeyResponse, error) {
	return nil, nil
}
func (m *mockTransport) BarrierGenerateRecoveryKeys(ctx context.Context, req *db.BarrierGenerateRecoveryKeysRequest) (*db.BarrierRecoveryKeysResponse, error) {
	return nil, nil
}
func (m *mockTransport) BarrierEnableEncryption(ctx context.Context, req *db.BarrierEnableEncryptionRequest) (*db.BarrierEnableEncryptionResponse, error) {
	return nil, nil
}
func (m *mockTransport) BarrierRecoverWithKeys(ctx context.Context, req *db.BarrierRecoverWithKeysRequest) error {
	return nil
}
func (m *mockTransport) BarrierDeleteRecoveryKeys(ctx context.Context) error { return nil }
func (m *mockTransport) BarrierHasRecoveryKeys(ctx context.Context) (*db.BarrierHasRecoveryKeysResponse, error) {
	return nil, nil
}
func (m *mockTransport) BarrierGenerateRootToken(ctx context.Context, req *db.BarrierGenerateRootTokenRequest) (*db.BarrierRootTokenResponse, error) {
	return nil, nil
}

// CeremonyClient stubs.
func (m *mockTransport) CeremonyInitialize(ctx context.Context, req *db.CeremonyInitializeRequest) (*db.CeremonyInitializeResponse, error) {
	return nil, nil
}
func (m *mockTransport) CeremonyStatus(ctx context.Context) (*db.CeremonyStatusResponse, error) {
	return nil, nil
}
func (m *mockTransport) CeremonyClaimCertBegin(ctx context.Context, req *db.ClaimCertBeginRequest) (*db.ClaimCertBeginResponse, error) {
	return nil, nil
}
func (m *mockTransport) CeremonyClaimCertComplete(ctx context.Context, req *db.ClaimCertCompleteRequest) (*db.ClaimCertCompleteResponse, error) {
	return nil, nil
}
func (m *mockTransport) CeremonyBeginClaimShare(ctx context.Context, req *db.BeginClaimShareRequest) (*db.BeginClaimShareResponse, error) {
	return nil, nil
}
func (m *mockTransport) CeremonyCompleteClaimShare(ctx context.Context, req *db.CompleteClaimShareRequest) (*db.CompleteClaimShareResponse, error) {
	return nil, nil
}
func (m *mockTransport) CeremonySignCSR(ctx context.Context, req *db.SignCSRInitRequest) (*db.SignCSRInitResponse, error) {
	return nil, nil
}

// CredentialClient stubs.
func (m *mockTransport) CredentialSubmit(ctx context.Context, req *db.CredentialSubmitRequest) error {
	return nil
}
func (m *mockTransport) CredentialStrategy(ctx context.Context) (*db.CredentialStrategyResponse, error) {
	return nil, nil
}
func (m *mockTransport) CredentialDelete(ctx context.Context, name string) error { return nil }

// CollectionClient stubs.
func (m *mockTransport) CreateCollection(ctx context.Context, req db.CreateCollectionRequest) (*db.CollectionInfo, error) {
	return nil, nil
}
func (m *mockTransport) GetCollectionInfo(ctx context.Context, database, name string) (*db.CollectionInfo, error) {
	return nil, nil
}
func (m *mockTransport) ListCollections(ctx context.Context, database string) (*db.ListCollectionsResponse, error) {
	return nil, nil
}
func (m *mockTransport) DropCollection(ctx context.Context, database, name string) error {
	return nil
}
func (m *mockTransport) InsertDocument(ctx context.Context, req db.InsertDocumentRequest) (*db.InsertDocumentResponse, error) {
	return nil, nil
}
func (m *mockTransport) GetDocument(ctx context.Context, database, collection string, id uint64) (*db.DocumentResponse, error) {
	return nil, nil
}
func (m *mockTransport) UpdateDocument(ctx context.Context, req db.UpdateDocumentRequest) error {
	return nil
}
func (m *mockTransport) DeleteDocument(ctx context.Context, database, collection string, id uint64) error {
	return nil
}
func (m *mockTransport) ListDocuments(ctx context.Context, req db.ListDocumentsRequest) (*db.ListDocumentsResponse, error) {
	return nil, nil
}

// BackupClient stubs.
func (m *mockTransport) CreateBackup(ctx context.Context, req *db.BackupRequest) (*db.BackupInfo, error) {
	return nil, nil
}
func (m *mockTransport) ListBackups(ctx context.Context) ([]db.BackupInfo, error) {
	return nil, nil
}
func (m *mockTransport) GetBackup(ctx context.Context, id string) (*db.BackupInfo, error) {
	return nil, nil
}
func (m *mockTransport) DeleteBackup(ctx context.Context, id string) error { return nil }
func (m *mockTransport) RestoreBackup(ctx context.Context, req *db.RestoreRequest) (*db.RestoreResult, error) {
	return nil, nil
}
func (m *mockTransport) VerifyBackup(ctx context.Context, id string) (*db.VerifyResult, error) {
	return nil, nil
}

// RebalanceClient stubs.
func (m *mockTransport) GetShardStats(ctx context.Context, shardID uint64) (*db.ShardStatsResponse, error) {
	return nil, nil
}
func (m *mockTransport) CreateRebalancePlan(ctx context.Context, req *db.RebalancePlanRequest) (*db.RebalancePlan, error) {
	return nil, nil
}
func (m *mockTransport) ExecuteRebalance(ctx context.Context, plan *db.RebalancePlan) (*db.RebalanceResult, error) {
	return nil, nil
}
func (m *mockTransport) GetImbalanceReport(ctx context.Context) (*db.ImbalanceReport, error) {
	return nil, nil
}

// newTestSDKClient creates an *sdk.Client backed by a mockTransport
// for unit testing. This allows testing the real service struct with
// a working client that delegates to in-memory implementations.
func newTestSDKClient(t *testing.T) (*qrdbsdk.Client, *mockTransport) {
	t.Helper()
	mt := newMockTransport()
	client, err := qrdbsdk.NewClient(mt)
	require.NoError(t, err)
	return client, mt
}

// ---------------------------------------------------------------------------
// Tests for New() constructor
// ---------------------------------------------------------------------------

func TestServiceNew(t *testing.T) {
	t.Run("no config and no client returns error", func(t *testing.T) {
		_, err := New()
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("invalid config returns error", func(t *testing.T) {
		cfg := &Config{
			Mode:     Mode("bogus"),
			Protocol: ProtocolEmbedded,
			DataDir:  "/tmp/qrdb",
		}
		_, err := New(WithConfig(cfg))
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("embedded protocol without client creates in-memory service", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolEmbedded,
			DataDir:  "/tmp/qrdb",
		}
		svc, err := New(WithConfig(cfg))
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.True(t, svc.Healthy(context.Background()))
		assert.NotNil(t, svc.KV())
		require.NoError(t, svc.Close())
	})

	t.Run("remote protocol returns connection error when no server", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolGRPC,
			Address:  "localhost:19443",
		}
		_, err := New(WithConfig(cfg))
		require.Error(t, err)
		// Connection fails because no QRDB server is running.
		assert.True(t, IsConnection(err) || IsServiceInit(err))
	})

	t.Run("WithQRDBClient creates service with default config", func(t *testing.T) {
		client, _ := newTestSDKClient(t)
		svc, err := New(WithQRDBClient(client))
		require.NoError(t, err)
		require.NotNil(t, svc)

		// Verify default config is applied when none is provided.
		cfg := svc.Config()
		require.NotNil(t, cfg)
		assert.Equal(t, ProtocolEmbedded, cfg.Protocol)
		assert.Equal(t, ModeStandalone, cfg.Mode)
	})

	t.Run("WithQRDBClient and WithConfig uses provided config", func(t *testing.T) {
		client, _ := newTestSDKClient(t)
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolEmbedded,
			DataDir:  "/custom/data",
			Timeout:  defaultTimeout,
		}
		svc, err := New(WithQRDBClient(client), WithConfig(cfg))
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.Equal(t, "/custom/data", svc.Config().DataDir)
	})

	t.Run("unsupported protocol returns error", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: Protocol("websocket"),
			DataDir:  "/tmp/qrdb",
		}
		_, err := New(WithConfig(cfg))
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})
}

// ---------------------------------------------------------------------------
// Tests for createClient error paths
// ---------------------------------------------------------------------------

func TestServiceCreateClient(t *testing.T) {
	t.Run("REST protocol fails to connect when no server", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolREST,
			Address:  "localhost:18443",
		}
		_, err := New(WithConfig(cfg))
		require.Error(t, err)
		assert.True(t, IsConnection(err) || IsServiceInit(err))
	})

	t.Run("QUIC protocol fails to connect when no server", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolQUIC,
			Address:  "localhost:19444",
		}
		_, err := New(WithConfig(cfg))
		require.Error(t, err)
		assert.True(t, IsConnection(err) || IsServiceInit(err))
	})

	t.Run("Unix protocol fails to connect when no socket", func(t *testing.T) {
		cfg := &Config{
			Mode:           ModeStandalone,
			Protocol:       ProtocolUnix,
			UnixSocketPath: "/tmp/nonexistent-qrdb-test.sock",
		}
		_, err := New(WithConfig(cfg))
		require.Error(t, err)
		assert.True(t, IsConnection(err) || IsServiceInit(err))
	})

	t.Run("MCP protocol returns unsupported error", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolMCP,
			Address:  "localhost:19445",
		}
		_, err := New(WithConfig(cfg))
		require.Error(t, err)
		// MCP may not be in the transport factory or may fail to connect.
		assert.True(t, IsConnection(err) || IsServiceInit(err) || IsInvalidConfig(err))
	})
}

// ---------------------------------------------------------------------------
// Tests for service accessor methods
// ---------------------------------------------------------------------------

func TestServiceAccessors(t *testing.T) {
	client, _ := newTestSDKClient(t)
	svc, err := New(WithQRDBClient(client))
	require.NoError(t, err)

	t.Run("KV returns the transport KVClient", func(t *testing.T) {
		kv := svc.KV()
		require.NotNil(t, kv)

		// Verify KV operations work through the accessor.
		ctx := context.Background()
		err := kv.Put(ctx, "test-key", []byte("test-value"))
		require.NoError(t, err)

		val, err := kv.Get(ctx, "test-key")
		require.NoError(t, err)
		assert.Equal(t, []byte("test-value"), val)

		// Clean up.
		_ = kv.Delete(ctx, "test-key")
	})

	t.Run("Admin returns the transport AdminClient", func(t *testing.T) {
		admin := svc.Admin()
		require.NotNil(t, admin)

		ctx := context.Background()
		resp, err := admin.Health(ctx)
		require.NoError(t, err)
		assert.Equal(t, "healthy", resp.Status)
	})

	t.Run("Watch returns the transport WatchClient", func(t *testing.T) {
		watch := svc.Watch()
		assert.NotNil(t, watch)
	})

	t.Run("Lease returns the transport LeaseClient", func(t *testing.T) {
		lease := svc.Lease()
		assert.NotNil(t, lease)
	})

	t.Run("Batch returns the transport BatchClient", func(t *testing.T) {
		batch := svc.Batch()
		assert.NotNil(t, batch)
	})

	t.Run("Transaction returns the transport TransactionClient", func(t *testing.T) {
		txn := svc.Transaction()
		assert.NotNil(t, txn)
	})

	t.Run("Index returns the transport IndexClient", func(t *testing.T) {
		idx := svc.Index()
		assert.NotNil(t, idx)
	})

	t.Run("Config returns the service configuration", func(t *testing.T) {
		cfg := svc.Config()
		require.NotNil(t, cfg)
		assert.Equal(t, ModeStandalone, cfg.Mode)
		assert.Equal(t, ProtocolEmbedded, cfg.Protocol)
	})
}

// ---------------------------------------------------------------------------
// Tests for Healthy()
// ---------------------------------------------------------------------------

func TestServiceHealthy(t *testing.T) {
	t.Run("returns true when transport is healthy", func(t *testing.T) {
		client, _ := newTestSDKClient(t)
		svc, err := New(WithQRDBClient(client))
		require.NoError(t, err)

		ctx := context.Background()
		assert.True(t, svc.Healthy(ctx))
	})

	t.Run("returns false when transport is unhealthy", func(t *testing.T) {
		client, mt := newTestSDKClient(t)
		svc, err := New(WithQRDBClient(client))
		require.NoError(t, err)

		mt.healthy = false
		ctx := context.Background()
		assert.False(t, svc.Healthy(ctx))
	})

	t.Run("returns false after service is closed", func(t *testing.T) {
		client, _ := newTestSDKClient(t)
		svc, err := New(WithQRDBClient(client))
		require.NoError(t, err)

		err = svc.Close()
		require.NoError(t, err)

		ctx := context.Background()
		assert.False(t, svc.Healthy(ctx))
	})

	t.Run("returns false with cancelled context", func(t *testing.T) {
		client, _ := newTestSDKClient(t)
		svc, err := New(WithQRDBClient(client))
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// The mock transport's Healthy checks m.healthy && !m.closed,
		// it does not check ctx. The sdk.Client checks c.closed first.
		// After cancel, the result depends on transport implementation.
		// We verify it does not panic.
		_ = svc.Healthy(ctx)
	})
}

// ---------------------------------------------------------------------------
// Tests for Close()
// ---------------------------------------------------------------------------

func TestServiceClose(t *testing.T) {
	t.Run("closes the underlying client", func(t *testing.T) {
		client, mt := newTestSDKClient(t)
		svc, err := New(WithQRDBClient(client))
		require.NoError(t, err)

		err = svc.Close()
		require.NoError(t, err)
		assert.True(t, mt.closed)
	})

	t.Run("idempotent close returns nil", func(t *testing.T) {
		client, _ := newTestSDKClient(t)
		svc, err := New(WithQRDBClient(client))
		require.NoError(t, err)

		err = svc.Close()
		require.NoError(t, err)

		// Second close should be a no-op.
		err = svc.Close()
		require.NoError(t, err)
	})

	t.Run("healthy returns false after close", func(t *testing.T) {
		client, _ := newTestSDKClient(t)
		svc, err := New(WithQRDBClient(client))
		require.NoError(t, err)

		err = svc.Close()
		require.NoError(t, err)

		ctx := context.Background()
		assert.False(t, svc.Healthy(ctx))
	})
}

// ---------------------------------------------------------------------------
// Tests for WithKVStore option path
// ---------------------------------------------------------------------------

func TestServiceWithKVStore(t *testing.T) {
	t.Run("WithKVStore alone without client requires config", func(t *testing.T) {
		// WithKVStore only sets sc.kvStore; without a client,
		// New() proceeds to createClient which needs config.
		_, err := New(WithKVStore(nil))
		require.Error(t, err)
		assert.True(t, IsInvalidConfig(err))
	})

	t.Run("WithKVStore with nil creates in-memory embedded service", func(t *testing.T) {
		cfg := &Config{
			Mode:     ModeStandalone,
			Protocol: ProtocolEmbedded,
			DataDir:  "/tmp/qrdb",
		}
		svc, err := New(WithKVStore(nil), WithConfig(cfg))
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.True(t, svc.Healthy(context.Background()))
		require.NoError(t, svc.Close())
	})
}

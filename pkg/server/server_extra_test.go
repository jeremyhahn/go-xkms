// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package server

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ============================================================================
// Tests — QRDBNodeError
// ============================================================================

func TestQRDBNodeError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("disk full")
	e := &QRDBNodeError{Stage: "new qrdb node", Err: inner}

	assert.Contains(t, e.Error(), "new qrdb node")
	assert.Contains(t, e.Error(), "disk full")
	assert.ErrorIs(t, e, inner)
}

// ============================================================================
// Tests — ErrSealStrategyBuild
// ============================================================================

func TestErrSealStrategyBuild_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("backend offline")
	e := &ErrSealStrategyBuild{Strategy: "tpm2", Err: inner}

	assert.Contains(t, e.Error(), "tpm2")
	assert.Contains(t, e.Error(), "backend offline")
	assert.ErrorIs(t, e, inner)
}

// ============================================================================
// Tests — ErrSealBackendNotConfigured
// ============================================================================

func TestErrSealBackendNotConfigured_Error(t *testing.T) {
	e := &ErrSealBackendNotConfigured{Strategy: "pkcs11"}
	assert.Contains(t, e.Error(), "pkcs11")
	assert.Contains(t, e.Error(), "not configured")
}

// ============================================================================
// Tests — sealKeyAttributesFor
// ============================================================================

func TestSealKeyAttributesFor(t *testing.T) {
	attrs := sealKeyAttributesFor("software")
	require.NotNil(t, attrs)
	assert.Equal(t, sealKeyCN, attrs.CN)
	assert.Equal(t, "software", string(attrs.StoreType))
}

// ============================================================================
// Tests — sealStoreType
// ============================================================================

func TestSealStoreType(t *testing.T) {
	tests := []struct {
		id        seal.StrategyID
		wantStore string
		wantOK    bool
	}{
		{seal.StrategyTPM2, "tpm2", true},
		{seal.StrategyPKCS11, "pkcs11", true},
		{seal.StrategyAWSKMS, "awskms", true},
		{seal.StrategyGCPKMS, "gcpkms", true},
		{seal.StrategyAzureKV, "azurekv", true},
		{seal.StrategyVault, "vault", true},
		{seal.StrategyPassphrase, "", false},
		{seal.StrategyNone, "", false},
		{"shamir", "", false},
		{"unknown-strategy", "", false},
	}

	for _, tc := range tests {
		t.Run(string(tc.id), func(t *testing.T) {
			store, ok := sealStoreType(tc.id)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantStore, string(store))
			}
		})
	}
}

// ============================================================================
// Tests — server ACME accessor methods
// ============================================================================

func TestServer_CA_NilByDefault(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.CA())
}

func TestServer_Backend_NilForMissingName(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.Nil(t, server.Backend("nonexistent"))
}

func TestServer_Backend_NotNilForSoftware(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.Backend("software"))
}

func TestServer_Logger_NotNil(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.Logger())
}

func TestServer_CreateStorage_ACME_Accessor(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	store, err := server.CreateStorage("test-acme")
	require.NoError(t, err)
	assert.NotNil(t, store)
}

// ============================================================================
// Tests — FactorRegistry
// ============================================================================

func TestServer_FactorRegistry_NotNil(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	// FactorRegistry is always initialized during New() with the hardware
	// factor backends (PIV, PKCS#11, FIDO2, mTLS).
	assert.NotNil(t, server.FactorRegistry())
}

// ============================================================================
// Tests — loadNoiseStaticKey
// ============================================================================

func TestLoadNoiseStaticKey_GeneratesEphemeral(t *testing.T) {
	// A build that cannot run Noise has no Noise key to load; assert that
	// contract instead of the one below, which presumes the suite exists.
	if !noiseRunnable() {
		requireNoiseRefused(t, newMinimalServer(t, &config.Config{}))
		return
	}

	s := newMinimalServer(t, &config.Config{})

	key, err := s.loadNoiseStaticKey()
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestLoadNoiseStaticKey_FromPersistedFile_ReadError(t *testing.T) {
	// "blocker" is a regular file, not a directory, so reading a path
	// underneath it fails with something other than "not found" -- the
	// no-barrier loader must surface that as a typed file-read error rather
	// than silently generating an ephemeral key.
	tmpDir := t.TempDir()
	blocker := filepath.Join(tmpDir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0600))

	cfg := &config.Config{Datastore: config.DatastoreConfig{Path: filepath.Join(blocker, "data")}}
	s := newMinimalServer(t, cfg)

	_, err := s.loadNoiseStaticKey()
	if !noiseRunnable() {
		requireNoiseRefused(t, s)
		return
	}
	require.Error(t, err)
	var errFileRead *ErrFileRead
	assert.True(t, errors.As(err, &errFileRead))
}

// ============================================================================
// Tests — initializeQRDBStorage default/invalid transport
// ============================================================================

// config.Validate already rejects an unrecognized datastore.remote.transport
// (the "invalid datastore.remote.transport" check), so this cannot reach
// New() with "ftp" any more -- see TestNew_QRDBStorageFailure_WrapsAsErrServiceInit
// for that Validate-level rejection. This exercises initializeQRDBStorage's
// own remote-transport-dispatch error directly, using newMinimalServer to
// construct the server without going through New()/Validate. The dispatch
// itself is datastore.DialRemote's (pkg/datastore), exercised directly (and
// qrdbTransportOptions, now datastore.TransportOptions) in
// pkg/datastore/datastore_test.go.
func TestInitializeQRDBStorage_InvalidTransport(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{
			Mode:   "remote",
			Remote: config.DatastoreRemoteConfig{Transport: "ftp"}, // unsupported transport
		},
	}
	s := newMinimalServer(t, cfg)

	err := s.initializeQRDBStorage()
	require.Error(t, err)
	var backendErr *datastore.ErrUnsupportedStorageBackend
	require.True(t, errors.As(err, &backendErr), "error must unwrap to *datastore.ErrUnsupportedStorageBackend, got %T", err)
}

// ============================================================================
// Tests — getBuildVersion
// ============================================================================

func TestGetBuildVersion_DoesNotPanic(t *testing.T) {
	// The function relies on debug.ReadBuildInfo which may return different
	// results in test vs production builds. We only guarantee it does not panic
	// and returns a non-empty string.
	v := getBuildVersion()
	assert.NotEmpty(t, v)
}

// ============================================================================
// Tests — buildHardwareSealStrategies
// ============================================================================

func TestBuildHardwareSealStrategies_EmptyPreferenceOrder(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Barrier.Enabled = true
	// "pkcs11" is not NodeFlipWired, so this deployment keeps xkms's own
	// (non-node) barrier -- buildHardwareSealStrategies, the function these
	// tests exercise -- instead of adopting the qrdb node's barrier, which
	// would skip it entirely and block boot on an operator unseal for the
	// flip-wired default ("passphrase").
	cfg.Barrier.Strategy = "pkcs11"
	cfg.Barrier.PreferenceOrder = []string{}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	// With no hardware strategies in the preference order, only the software
	// fallback is appended. Barrier should be initialized successfully.
	assert.NotNil(t, server.Barrier())
}

func TestBuildHardwareSealStrategies_SkipsMissingBackend(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Barrier.Enabled = true
	// See TestBuildHardwareSealStrategies_EmptyPreferenceOrder.
	cfg.Barrier.Strategy = "pkcs11"
	// Request TPM2 but TPM2 backend is not configured — should be skipped.
	cfg.Barrier.PreferenceOrder = []string{"tpm2", "software"}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.Barrier())
}

func TestBuildHardwareSealStrategies_DuplicateEntriesDeduped(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Barrier.Enabled = true
	// See TestBuildHardwareSealStrategies_EmptyPreferenceOrder.
	cfg.Barrier.Strategy = "pkcs11"
	// Duplicate "software" entries: only first is honoured, second is skipped.
	cfg.Barrier.PreferenceOrder = []string{"software", "software"}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.Barrier())
}

// ============================================================================
// Tests — buildXKMSQRDBConfig cluster branch
// ============================================================================

// TestBuildXKMSQRDBConfig_StandaloneUsesMemory exercises the path where no
// storage path is configured (DataDir == "") so the inner backend becomes
// "memory".
func TestBuildXKMSQRDBConfig_StandaloneUsesMemory(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: ""}, // triggers the memory-engine fallback
	}
	s := newMinimalServer(t, cfg)
	qcfg := s.buildXKMSQRDBConfig()
	require.NotNil(t, qcfg)
	require.Len(t, qcfg.Databases, 1)
	assert.Equal(t, "memory", qcfg.Databases[0].Backend)
}

// TestBuildXKMSQRDBConfig_ClusterFields exercises the Cluster.Enabled branch
// that maps the cluster config onto the qrdb Raft config.
func TestBuildXKMSQRDBConfig_ClusterFields(t *testing.T) {
	cfg := &config.Config{
		Cluster: config.ClusterConfig{
			Enabled:       true,
			NodeID:        42,
			ShardID:       7,
			DeploymentID:  99,
			RaftAddress:   "10.0.0.1:63001",
			ListenAddress: "0.0.0.0:63001",
			Peers:         "1=10.0.0.1:63001",
			Join:          false,
		},
	}
	s := newMinimalServer(t, cfg)
	qcfg := s.buildXKMSQRDBConfig()
	require.NotNil(t, qcfg)
	assert.Equal(t, uint64(42), qcfg.Raft.ReplicaID)
	assert.Equal(t, uint64(7), qcfg.Raft.ShardID)
	assert.Equal(t, uint64(99), qcfg.Raft.DeploymentID)
	assert.Equal(t, "10.0.0.1:63001", qcfg.Raft.RaftAddress)
	assert.Equal(t, "0.0.0.0:63001", qcfg.Raft.ListenAddress)
	assert.Equal(t, "1=10.0.0.1:63001", qcfg.Raft.Peers)
	assert.False(t, qcfg.Raft.Join)
}

// ============================================================================
// Tests — newQRDBAuditSink
// ============================================================================

// TestNewQRDBAuditSink_RingBuffer exercises the default (no file audit) path
// that returns an in-memory ring buffer.
func TestNewQRDBAuditSink_RingBuffer(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Audit: nil, // no audit config → ring buffer
		},
	}
	s := newMinimalServer(t, cfg)
	sink, err := s.newQRDBAuditSink()
	require.NoError(t, err)
	assert.NotNil(t, sink)
}

// TestNewQRDBAuditSink_FileLogger exercises the HMAC-chained file logger path
// when Auth.Audit is enabled with a valid temp-dir path.
func TestNewQRDBAuditSink_FileLogger(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.log")

	cfg := &config.Config{
		Auth: config.AuthConfig{
			Audit: &config.AuditConfig{
				Enabled: true,
				Path:    auditPath,
			},
		},
	}
	s := newMinimalServer(t, cfg)
	sink, err := s.newQRDBAuditSink()
	require.NoError(t, err)
	assert.NotNil(t, sink)
}

// TestNewQRDBAuditSink_FileLogger_Error exercises the error return when the
// audit file path is in a non-existent directory (NewAuditFileLogger fails).
func TestNewQRDBAuditSink_FileLogger_Error(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Audit: &config.AuditConfig{
				Enabled: true,
				Path:    "/nonexistent-dir/no-such-subdir/audit.log",
			},
		},
	}
	s := newMinimalServer(t, cfg)
	_, err := s.newQRDBAuditSink()
	require.Error(t, err)
}

// ============================================================================
// Tests — loadClientCAsUnion
// ============================================================================

// TestLoadClientCAsUnion_EmptySlices returns nil pool with no error when all
// input path slices are empty.
func TestLoadClientCAsUnion_EmptySlices(t *testing.T) {
	pool, err := loadClientCAsUnion()
	require.NoError(t, err)
	assert.Nil(t, pool)
}

// TestLoadClientCAsUnion_EmptyStringsSkipped verifies that empty string paths
// within a slice are skipped without error.
func TestLoadClientCAsUnion_EmptyStringsSkipped(t *testing.T) {
	pool, err := loadClientCAsUnion([]string{"", ""})
	require.NoError(t, err)
	assert.Nil(t, pool)
}

// TestLoadClientCAsUnion_FileNotFound returns ErrFileRead when a path exists
// in a canonicalized form but the file is missing after canonicalization.
func TestLoadClientCAsUnion_FileNotFound(t *testing.T) {
	_, err := loadClientCAsUnion([]string{"/nonexistent/path/ca.pem"})
	require.Error(t, err)
	var e *ErrFileRead
	assert.True(t, errors.As(err, &e))
}

// TestLoadClientCAsUnion_InvalidPEM returns ErrCertParse when the CA file
// exists but contains no valid CERTIFICATE PEM block.
func TestLoadClientCAsUnion_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "bad-ca.pem")
	// Write data that is NOT a valid PEM-encoded certificate.
	require.NoError(t, os.WriteFile(caFile, []byte("not a valid pem block\n"), 0600))

	_, err := loadClientCAsUnion([]string{caFile})
	require.Error(t, err)
	var e *ErrCertParse
	assert.True(t, errors.As(err, &e))
}

// TestLoadClientCAsUnion_Dedup verifies that duplicate paths (after
// canonicalization) are only loaded once without error.
func TestLoadClientCAsUnion_Dedup(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	// Write a minimal self-signed CA PEM. We use a real cert so
	// AppendCertsFromPEM succeeds and added=true.
	certPEM, _ := generateTestCA(t)
	require.NoError(t, os.WriteFile(caFile, certPEM, 0600))

	pool, err := loadClientCAsUnion([]string{caFile, caFile})
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

// ============================================================================
// Tests — canonicalizeCAPath
// ============================================================================

// TestCanonicalizeCAPath_ExistingFile returns the resolved (abs+symlink) path
// when the file actually exists.
func TestCanonicalizeCAPath_ExistingFile(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "ca.pem")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0600))

	got, err := canonicalizeCAPath(f)
	require.NoError(t, err)
	assert.NotEmpty(t, got)
}

// TestCanonicalizeCAPath_NonExistentFile returns the abs path (without error)
// when the file does not exist — this enables dedup before the read attempt.
func TestCanonicalizeCAPath_NonExistentFile(t *testing.T) {
	got, err := canonicalizeCAPath("/nonexistent/path/ca.pem")
	require.NoError(t, err)
	assert.Equal(t, "/nonexistent/path/ca.pem", got)
}

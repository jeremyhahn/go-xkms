// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
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
	cfg := &config.Config{
		Bootstrap: config.BootstrapConfig{
			Noise: config.NoiseBootstrapConfig{
				// No StaticKeyHex and no StaticKeyFile: generates ephemeral key.
			},
		},
	}
	s := newMinimalServer(t, cfg)

	key, err := s.loadNoiseStaticKey()
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestLoadNoiseStaticKey_FromHex(t *testing.T) {
	// Generate a valid hex key first via the ephemeral path.
	cfgEph := &config.Config{
		Bootstrap: config.BootstrapConfig{
			Noise: config.NoiseBootstrapConfig{},
		},
	}
	sEph := newMinimalServer(t, cfgEph)
	ephKey, err := sEph.loadNoiseStaticKey()
	require.NoError(t, err)

	// Encode the private key bytes as hex string for use as StaticKeyHex.
	hexKey := encodeKeyHex(ephKey.Private)

	cfg := &config.Config{
		Bootstrap: config.BootstrapConfig{
			Noise: config.NoiseBootstrapConfig{
				StaticKeyHex: hexKey,
			},
		},
	}
	s := newMinimalServer(t, cfg)

	key, err := s.loadNoiseStaticKey()
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestLoadNoiseStaticKey_FromFile(t *testing.T) {
	// Generate a valid hex key first via the ephemeral path.
	cfgEph := &config.Config{
		Bootstrap: config.BootstrapConfig{
			Noise: config.NoiseBootstrapConfig{},
		},
	}
	sEph := newMinimalServer(t, cfgEph)
	ephKey, err := sEph.loadNoiseStaticKey()
	require.NoError(t, err)

	// Write the hex key to a temp file.
	hexKey := encodeKeyHex(ephKey.Private)
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "noise.key")
	require.NoError(t, os.WriteFile(keyFile, []byte(hexKey), 0600))

	cfg := &config.Config{
		Bootstrap: config.BootstrapConfig{
			Noise: config.NoiseBootstrapConfig{
				StaticKeyFile: keyFile,
			},
		},
	}
	s := newMinimalServer(t, cfg)

	key, err := s.loadNoiseStaticKey()
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestLoadNoiseStaticKey_FromFile_NotFound(t *testing.T) {
	cfg := &config.Config{
		Bootstrap: config.BootstrapConfig{
			Noise: config.NoiseBootstrapConfig{
				StaticKeyFile: "/nonexistent/path/noise.key",
			},
		},
	}
	s := newMinimalServer(t, cfg)

	_, err := s.loadNoiseStaticKey()
	require.Error(t, err)
	var errFileRead *ErrFileRead
	assert.True(t, errors.As(err, &errFileRead))
}

// encodeKeyHex encodes a raw key byte slice as a lowercase hex string, matching
// the encoding noiseproto.DecodeStaticKey expects.
func encodeKeyHex(raw []byte) string {
	const hx = "0123456789abcdef"
	buf := make([]byte, len(raw)*2)
	for i, b := range raw {
		buf[i*2] = hx[b>>4]
		buf[i*2+1] = hx[b&0xf]
	}
	return string(buf)
}

// ============================================================================
// Tests — qrdbTransportOptions
// ============================================================================

func TestQRDBTransportOptions_Empty(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			QRDB: config.QRDBConfig{
				Address: "",
				TLS:     config.TLSConfig{Enabled: false},
			},
		},
	}
	s := newMinimalServer(t, cfg)
	opts := s.qrdbTransportOptions()
	assert.Empty(t, opts)
}

func TestQRDBTransportOptions_WithAddress(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			QRDB: config.QRDBConfig{
				Address: "localhost:63002",
				TLS:     config.TLSConfig{Enabled: false},
			},
		},
	}
	s := newMinimalServer(t, cfg)
	opts := s.qrdbTransportOptions()
	assert.Len(t, opts, 1)
}

func TestQRDBTransportOptions_WithAddressAndTLS(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			QRDB: config.QRDBConfig{
				Address: "localhost:63002",
				TLS: config.TLSConfig{
					Enabled:  true,
					CAFile:   "/path/to/ca.pem",
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
		},
	}
	s := newMinimalServer(t, cfg)
	opts := s.qrdbTransportOptions()
	// address + TLS = 2 options
	assert.Len(t, opts, 2)
}

// ============================================================================
// Tests — initializeQRDBStorage default/invalid transport
// ============================================================================

func TestInitializeQRDBStorage_InvalidTransport(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	cfg.Storage.Backend = "qrdb"
	cfg.Storage.QRDB = config.QRDBConfig{
		Transport: "ftp", // unsupported transport
	}

	_, err := New(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "qrdb storage")
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
	// Duplicate "software" entries: only first is honoured, second is skipped.
	cfg.Barrier.PreferenceOrder = []string{"software", "software"}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.NotNil(t, server.Barrier())
}

// ============================================================================
// Tests — staticUserChecker
// ============================================================================

func TestStaticUserChecker_HasAnyUsers_True(t *testing.T) {
	checker := staticUserChecker{hasUsers: true}
	has, err := checker.HasAnyUsers(context.Background())
	require.NoError(t, err)
	assert.True(t, has)
}

func TestStaticUserChecker_HasAnyUsers_False(t *testing.T) {
	checker := staticUserChecker{hasUsers: false}
	has, err := checker.HasAnyUsers(context.Background())
	require.NoError(t, err)
	assert.False(t, has)
}

// ============================================================================
// Tests — buildXKMSQRDBConfig cluster branch
// ============================================================================

// TestBuildXKMSQRDBConfig_StandaloneUsesMemory exercises the path where no
// storage path is configured (DataDir == "") so the inner backend becomes
// "memory".
func TestBuildXKMSQRDBConfig_StandaloneUsesMemory(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Path: "", // triggers innerBackend = "memory"
		},
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

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

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// standaloneUnsealedNode opens a standalone embedded qrdb node with no
// barrier (unsealed immediately), matching the state RunFirstBoot's callers
// (xkmsd init's bootstrapDurableAdmin) always present it: an already-open,
// unsealed node.
func standaloneUnsealedNode(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Storage: config.StorageConfig{Backend: "qrdb", Path: t.TempDir()},
	}
}

// TestRunFirstBoot_NoCA_CreatesAdminWithoutBoundCertificate proves the
// documented no-CA behaviour: first-boot still creates the system tenant,
// roles and administrator, but issues no certificate -- the caller enrolls
// one afterwards.
func TestRunFirstBoot_NoCA_CreatesAdminWithoutBoundCertificate(t *testing.T) {
	cfg := standaloneUnsealedNode(t)
	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: embeddedNodeTestLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	result, err := RunFirstBoot(context.Background(), node, FirstBootParams{
		Logger: embeddedNodeTestLogger(),
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.AdminCreated)
	assert.Empty(t, result.AdminCertPEM, "no CA was supplied: no certificate should be issued")
}

// TestRunFirstBoot_Idempotent proves a second RunFirstBoot call against the
// same already-bootstrapped node is a no-op (AdminCreated false), matching
// qrdb's canonical first-boot contract.
func TestRunFirstBoot_Idempotent(t *testing.T) {
	cfg := standaloneUnsealedNode(t)
	node, _, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: embeddedNodeTestLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = node.Close() }()

	_, err = RunFirstBoot(context.Background(), node, FirstBootParams{Logger: embeddedNodeTestLogger()})
	require.NoError(t, err)

	second, err := RunFirstBoot(context.Background(), node, FirstBootParams{Logger: embeddedNodeTestLogger()})
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.False(t, second.AdminCreated, "a node whose administrator already exists must be a no-op")
}

// TestRunFirstBoot_NoServicesAvailable proves that a node exposing no
// identity services (a sealed node, or one still mid-boot) fails RunFirstBoot
// with ErrFirstBootServicesUnavailable rather than silently doing nothing.
func TestRunFirstBoot_NoServicesAvailable(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{Backend: "qrdb", Path: t.TempDir()},
		Barrier: config.BarrierConfig{Enabled: true, Strategy: "passphrase"},
	}
	node, sealRes, err := OpenEmbeddedNode(context.Background(), EmbeddedNodeOptions{
		Config: cfg,
		Logger: embeddedNodeTestLogger(),
	})
	require.NoError(t, err)
	defer func() { _ = node.Close() }()
	require.True(t, sealRes.Enabled)
	require.True(t, node.IsSealed(), "fixture setup: a fresh passphrase-strategy node must come up sealed")

	_, err = RunFirstBoot(context.Background(), node, FirstBootParams{Logger: embeddedNodeTestLogger()})
	require.ErrorIs(t, err, ErrFirstBootServicesUnavailable)
}

// TestPersistAdminCredential_NilResultIsNoOp proves a nil first-boot result
// (an idempotent no-op boot) writes nothing and returns no error.
func TestPersistAdminCredential_NilResultIsNoOp(t *testing.T) {
	require.NoError(t, PersistAdminCredential(t.TempDir(), nil, embeddedNodeTestLogger()))
}

// TestPersistAdminCredential_MkdirFailureIsTypedError proves a data
// directory that cannot be created (its parent is an existing regular file,
// not a directory) surfaces as *AdminCredentialError, exercising both its
// Error and Unwrap methods.
func TestPersistAdminCredential_MkdirFailureIsTypedError(t *testing.T) {
	parent := t.TempDir()
	blocker := filepath.Join(parent, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o600))
	dataDir := filepath.Join(blocker, "data")

	result := &qrdbsdk.FirstBootResult{
		AdminCreated:        true,
		AdminCertPEM:        []byte("cert-pem"),
		AdminKeyPEM:         []byte("key-pem"),
		AdminCertThumbprint: "thumbprint",
	}
	err := PersistAdminCredential(dataDir, result, embeddedNodeTestLogger())
	require.Error(t, err)

	var credErr *AdminCredentialError
	require.ErrorAs(t, err, &credErr)
	assert.Equal(t, dataDir, credErr.Path)
	assert.Contains(t, credErr.Error(), dataDir)
	assert.NotNil(t, credErr.Unwrap())
}

// TestPersistAdminCredential_CertWithoutKeyWarnsAndSkips proves the one
// combination that must not pass silently: an admin certificate issued
// without a distributable key (Path B, or a CertProvider that never
// returned one) logs a warning but persists nothing and returns no error.
func TestPersistAdminCredential_CertWithoutKeyWarnsAndSkips(t *testing.T) {
	dataDir := t.TempDir()
	result := &qrdbsdk.FirstBootResult{
		AdminCreated:        true,
		AdminCertPEM:        []byte("cert-pem-only"),
		AdminCertThumbprint: "thumbprint",
	}

	require.NoError(t, PersistAdminCredential(dataDir, result, embeddedNodeTestLogger()))

	assert.NoFileExists(t, filepath.Join(dataDir, adminCertFilename))
	assert.NoFileExists(t, filepath.Join(dataDir, adminKeyFilename))
}

// TestPersistAdminCredential_EmptyDataDirWarnsAndSkips proves an in-memory
// deployment (no storage path) reports the credential rather than attempting
// to write it, and returns no error.
func TestPersistAdminCredential_EmptyDataDirWarnsAndSkips(t *testing.T) {
	result := &qrdbsdk.FirstBootResult{
		AdminCreated: true,
		AdminCertPEM: []byte("cert-pem"),
		AdminKeyPEM:  []byte("key-pem"),
	}

	require.NoError(t, PersistAdminCredential("", result, embeddedNodeTestLogger()))
}

// TestPersistAdminCredential_AlreadyPresentIsNoOp proves a restart over a
// data directory that already carries both credential files leaves them
// alone rather than overwriting a credential the operator has already taken
// delivery of.
func TestPersistAdminCredential_AlreadyPresentIsNoOp(t *testing.T) {
	dataDir := t.TempDir()
	certPath := filepath.Join(dataDir, adminCertFilename)
	keyPath := filepath.Join(dataDir, adminKeyFilename)
	require.NoError(t, os.WriteFile(certPath, []byte("existing-cert"), 0o644))
	require.NoError(t, os.WriteFile(keyPath, []byte("existing-key"), 0o600))

	result := &qrdbsdk.FirstBootResult{
		AdminCreated: true,
		AdminCertPEM: []byte("new-cert-pem"),
		AdminKeyPEM:  []byte("new-key-pem"),
	}
	require.NoError(t, PersistAdminCredential(dataDir, result, embeddedNodeTestLogger()))

	got, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, "existing-cert", string(got), "an already-present credential must not be overwritten")
}

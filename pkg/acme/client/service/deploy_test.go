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

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCertPEM() []byte {
	return []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")
}

func testKeyPEM() []byte {
	return []byte("-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n")
}

// testLogger is defined in challenge_test.go

func TestDeployer_Deploy_WithPostHook(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	deployer := NewDeployer(testLogger())
	cfg := &DeployConfig{
		CertPath: certPath,
		KeyPath:  keyPath,
		PostHook: "echo deployed",
	}

	err := deployer.Deploy(context.Background(), testCertPEM(), testKeyPEM(), cfg)
	require.NoError(t, err)

	// Verify files were written despite the hook
	_, err = os.Stat(certPath)
	require.NoError(t, err)
	_, err = os.Stat(keyPath)
	require.NoError(t, err)
}

func TestDeployer_Deploy_CreatesParentDirs(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "nested", "deep", "certs", "cert.pem")
	keyPath := filepath.Join(tmpDir, "nested", "deep", "keys", "key.pem")

	deployer := NewDeployer(testLogger())
	cfg := &DeployConfig{
		CertPath: certPath,
		KeyPath:  keyPath,
	}

	err := deployer.Deploy(context.Background(), testCertPEM(), testKeyPEM(), cfg)
	require.NoError(t, err)

	certData, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, testCertPEM(), certData)

	keyData, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, testKeyPEM(), keyData)
}

func TestDeployer_Deploy_NilConfig(t *testing.T) {
	deployer := NewDeployer(testLogger())

	err := deployer.Deploy(context.Background(), testCertPEM(), testKeyPEM(), nil)
	require.Error(t, err)

	var deployErr ErrDeployFailed
	require.True(t, errors.As(err, &deployErr))
	assert.Equal(t, "unknown", deployErr.CertName)
	assert.ErrorIs(t, err, ErrDeployConfigNil)
}

func TestDeployer_Deploy_EmptyCertPEM(t *testing.T) {
	tmpDir := t.TempDir()
	deployer := NewDeployer(testLogger())
	cfg := &DeployConfig{
		CertPath: filepath.Join(tmpDir, "cert.pem"),
		KeyPath:  filepath.Join(tmpDir, "key.pem"),
	}

	err := deployer.Deploy(context.Background(), []byte{}, testKeyPEM(), cfg)
	require.Error(t, err)

	var deployErr ErrDeployFailed
	require.True(t, errors.As(err, &deployErr))
	assert.ErrorIs(t, err, ErrDeployCertPEMEmpty)
}

func TestDeployer_Deploy_EmptyKeyPEM(t *testing.T) {
	tmpDir := t.TempDir()
	deployer := NewDeployer(testLogger())
	cfg := &DeployConfig{
		CertPath: filepath.Join(tmpDir, "cert.pem"),
		KeyPath:  filepath.Join(tmpDir, "key.pem"),
	}

	err := deployer.Deploy(context.Background(), testCertPEM(), []byte{}, cfg)
	require.Error(t, err)

	var deployErr ErrDeployFailed
	require.True(t, errors.As(err, &deployErr))
	assert.ErrorIs(t, err, ErrDeployKeyPEMEmpty)
}

func TestDeployer_Deploy_EmptyCertPath(t *testing.T) {
	tmpDir := t.TempDir()
	deployer := NewDeployer(testLogger())
	cfg := &DeployConfig{
		CertPath: "",
		KeyPath:  filepath.Join(tmpDir, "key.pem"),
	}

	err := deployer.Deploy(context.Background(), testCertPEM(), testKeyPEM(), cfg)
	require.Error(t, err)

	var deployErr ErrDeployFailed
	require.True(t, errors.As(err, &deployErr))
	assert.ErrorIs(t, err, ErrDeployCertPathEmpty)
}

func TestDeployer_Deploy_EmptyKeyPath(t *testing.T) {
	tmpDir := t.TempDir()
	deployer := NewDeployer(testLogger())
	cfg := &DeployConfig{
		CertPath: filepath.Join(tmpDir, "cert.pem"),
		KeyPath:  "",
	}

	err := deployer.Deploy(context.Background(), testCertPEM(), testKeyPEM(), cfg)
	require.Error(t, err)

	var deployErr ErrDeployFailed
	require.True(t, errors.As(err, &deployErr))
	assert.ErrorIs(t, err, ErrDeployKeyPathEmpty)
}

func TestDeployer_Deploy_CertPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	deployer := NewDeployer(testLogger())
	cfg := &DeployConfig{
		CertPath: certPath,
		KeyPath:  keyPath,
	}

	err := deployer.Deploy(context.Background(), testCertPEM(), testKeyPEM(), cfg)
	require.NoError(t, err)

	fi, err := os.Stat(certPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), fi.Mode().Perm())
}

func TestDeployer_Deploy_KeyPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	deployer := NewDeployer(testLogger())
	cfg := &DeployConfig{
		CertPath: certPath,
		KeyPath:  keyPath,
	}

	err := deployer.Deploy(context.Background(), testCertPEM(), testKeyPEM(), cfg)
	require.NoError(t, err)

	fi, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
}

func TestDeployer_Deploy_PostHookFailure(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	deployer := NewDeployer(testLogger())
	cfg := &DeployConfig{
		CertPath: certPath,
		KeyPath:  keyPath,
		PostHook: "exit 1",
	}

	err := deployer.Deploy(context.Background(), testCertPEM(), testKeyPEM(), cfg)
	require.Error(t, err)

	var hookErr ErrPostHookFailed
	require.True(t, errors.As(err, &hookErr))
	assert.Equal(t, "exit 1", hookErr.Hook)
}

func TestDeployer_Deploy_PostHookWithContext(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	deployer := NewDeployer(testLogger())
	cfg := &DeployConfig{
		CertPath: certPath,
		KeyPath:  keyPath,
		PostHook: "sleep 10",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately before calling Deploy

	err := deployer.Deploy(ctx, testCertPEM(), testKeyPEM(), cfg)
	require.Error(t, err)

	var hookErr ErrPostHookFailed
	require.True(t, errors.As(err, &hookErr))
	assert.Equal(t, "sleep 10", hookErr.Hook)
}

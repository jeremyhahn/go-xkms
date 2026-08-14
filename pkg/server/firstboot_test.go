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

package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/daemon"
)

// newFirstBootServer builds the smallest Server the first-boot hook reads:
// a logger and a config. Everything else the hook touches it guards on.
func newFirstBootServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		config: &config.Config{},
	}
}

// TestRunFirstBoot_NoEmbeddedNode covers the deployment that stores identity
// somewhere other than an embedded qrdb node: there is no first-boot to run, so
// the hook is a no-op rather than an error that would refuse to start a daemon
// which is configured correctly.
func TestRunFirstBoot_NoEmbeddedNode(t *testing.T) {
	s := newFirstBootServer(t)
	require.Nil(t, s.qrdbNode)

	assert.NoError(t, s.runFirstBoot(context.Background()))
}

// TestRunFirstBoot_NodeWithoutServices is the fail-closed case. A node that
// exposes no identity services cannot create the system tenant, the roles or
// the administrator, and continuing would start a daemon whose first
// authenticated request fails for reasons that look nothing like "the bootstrap
// never ran". It must refuse instead of skipping.
func TestRunFirstBoot_NodeWithoutServices(t *testing.T) {
	s := newFirstBootServer(t)
	// A node that has not built its service graph: Services() returns nil.
	s.qrdbNode = &qrdbnode.Node{}

	err := s.runFirstBoot(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFirstBootServicesUnavailable)
}

// TestFirstBootTrustDomain_Configured verifies the administrator certificate is
// stamped with the operator's own trust domain, so an admin certificate and a
// node certificate issued by one deployment share one SPIFFE trust domain.
func TestFirstBootTrustDomain_Configured(t *testing.T) {
	s := newFirstBootServer(t)
	s.config.Cluster.RaftEnrollment.TrustDomain = "example.internal"

	assert.Equal(t, "example.internal", s.firstBootTrustDomain())
}

// TestFirstBootTrustDomain_Default verifies an unconfigured deployment falls
// back to the same default the enrollment path uses. An empty trust domain
// would produce an unusable SPIFFE ID rather than an obvious failure.
func TestFirstBootTrustDomain_Default(t *testing.T) {
	s := newFirstBootServer(t)
	require.Empty(t, s.config.Cluster.RaftEnrollment.TrustDomain)

	assert.Equal(t, daemon.DefaultTrustDomain, s.firstBootTrustDomain())
}

// TestPersistAdminCredential_WritesBothFiles is the credential-delivery
// guarantee: first-boot creates the only account on the daemon, so if its
// certificate and key are not written down there is no way in at all.
func TestPersistAdminCredential_WritesBothFiles(t *testing.T) {
	s := newFirstBootServer(t)
	dir := t.TempDir()
	s.config.Storage.Path = dir

	result := &qrdbsdk.FirstBootResult{
		AdminCreated: true,
		AdminCertPEM: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"),
		AdminKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n"),
	}

	require.NoError(t, s.persistAdminCredential(result))

	certPEM, err := os.ReadFile(filepath.Join(dir, adminCertFilename))
	require.NoError(t, err)
	assert.Equal(t, result.AdminCertPEM, certPEM)

	keyPath := filepath.Join(dir, adminKeyFilename)
	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, result.AdminKeyPEM, keyPEM)

	// The key authenticates as the highest privilege account on the daemon, so
	// it must not be readable by other users on the host.
	info, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// TestPersistAdminCredential_DoesNotOverwrite covers restart: the operator has
// already taken delivery of the credential, and replacing it on every boot
// would invalidate whatever they configured against it.
func TestPersistAdminCredential_DoesNotOverwrite(t *testing.T) {
	s := newFirstBootServer(t)
	dir := t.TempDir()
	s.config.Storage.Path = dir

	existingCert := []byte("existing cert")
	existingKey := []byte("existing key")
	require.NoError(t, os.WriteFile(filepath.Join(dir, adminCertFilename), existingCert, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, adminKeyFilename), existingKey, 0o600))

	err := s.persistAdminCredential(&qrdbsdk.FirstBootResult{
		AdminCreated: true,
		AdminCertPEM: []byte("replacement cert"),
		AdminKeyPEM:  []byte("replacement key"),
	})
	require.NoError(t, err)

	certPEM, err := os.ReadFile(filepath.Join(dir, adminCertFilename))
	require.NoError(t, err)
	assert.Equal(t, existingCert, certPEM, "an existing admin certificate must survive a restart")

	keyPEM, err := os.ReadFile(filepath.Join(dir, adminKeyFilename))
	require.NoError(t, err)
	assert.Equal(t, existingKey, keyPEM, "an existing admin key must survive a restart")
}

// TestPersistAdminCredential_NoCredentialIssued covers the boots where there is
// nothing to write — no CA was injected, or the administrator already existed.
// Writing empty files there would look like a credential that cannot be used.
func TestPersistAdminCredential_NoCredentialIssued(t *testing.T) {
	s := newFirstBootServer(t)
	dir := t.TempDir()
	s.config.Storage.Path = dir

	for name, result := range map[string]*qrdbsdk.FirstBootResult{
		"nil result": nil,
		"no cert":    {AdminCreated: true, AdminKeyPEM: []byte("k")},
		"no key":     {AdminCreated: true, AdminCertPEM: []byte("c")},
	} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, s.persistAdminCredential(result))
			assert.NoFileExists(t, filepath.Join(dir, adminCertFilename))
			assert.NoFileExists(t, filepath.Join(dir, adminKeyFilename))
		})
	}
}

// TestPersistAdminCredential_UnwritableDir is the error path: a data directory
// that cannot be written must surface, because the alternative is a daemon that
// reports a successful bootstrap while the only credential for it was lost.
func TestPersistAdminCredential_UnwritableDir(t *testing.T) {
	s := newFirstBootServer(t)
	// A file where the directory should be: MkdirAll and WriteFile both fail.
	parent := t.TempDir()
	blocker := filepath.Join(parent, "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	s.config.Storage.Path = blocker

	err := s.persistAdminCredential(&qrdbsdk.FirstBootResult{
		AdminCreated: true,
		AdminCertPEM: []byte("c"),
		AdminKeyPEM:  []byte("k"),
	})

	require.Error(t, err)
	var credErr *AdminCredentialError
	assert.ErrorAs(t, err, &credErr)
}

// TestFirstBootError_WrapsCause checks the wrapper keeps the cause reachable
// through errors.Is. Startup logs the returned error, and a wrapper that hid
// its cause would report "first-boot initialize failed" with no indication of
// why.
func TestFirstBootError_WrapsCause(t *testing.T) {
	cause := errors.New("storage unavailable")
	err := &FirstBootError{Op: "initialize", Cause: cause}

	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "initialize")
	assert.Contains(t, err.Error(), "storage unavailable")
}

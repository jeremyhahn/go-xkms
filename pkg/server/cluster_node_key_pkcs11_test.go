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

//go:build pkcs11

package server

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/pinselect"
	"github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// preNodeServer is a *Server as Server.New has it before
// initializeQRDBStorage: a multi-node config whose Raft transport key lives
// on the PKCS#11 token, and no shared datastore open yet.
func preNodeServer(t *testing.T, library, token string) *Server {
	t.Helper()
	return &Server{
		config: &config.Config{
			Datastore: config.DatastoreConfig{Path: t.TempDir()},
			Backends: config.BackendsConfig{PKCS11: &config.PKCS11Config{
				Enabled: true,
				Library: library,
				Token:   token,
			}},
			Cluster: config.ClusterConfig{
				Enabled:        true,
				NodeID:         1,
				RaftAddress:    "10.0.0.1:63001",
				RaftEnrollment: config.RaftEnrollmentConfig{KeyBackend: "pkcs11"},
			},
		},
		keyProviders: make(map[string]types.KeyProvider),
		logger:       slog.Default(),
	}
}

// nodeKeyFor resolves the node transport key from the providers open on s,
// as buildClusterCAOptions does (it is raft-tagged; cluster_node_key_test.go
// pins that it passes s.keyProviders through).
func nodeKeyFor(t *testing.T, s *Server) (xkms.Backend, error) {
	t.Helper()
	resolve, err := clusterca.NewNodeKeyBackends(&clusterca.NodeKeyBackendsParams{
		DataDir:  filepath.Join(s.config.Datastore.Path, "cluster-ca"),
		Hardware: maps.Clone(s.keyProviders),
	})
	require.NoError(t, err)
	return resolve(s.config.Cluster.RaftEnrollment.KeyBackend)
}

// TestPreNodePKCS11_NodeKeyResolvesBeforeTheNode pins the Codex P1 on train
// #1595: Raft mTLS is provisioned inside initializeQRDBStorage, before
// initializeBackends, so a configured PKCS#11 node key must already be open
// then. The token opened before the node backs the transport key, and the
// later backend registry reuses that one open rather than a second login.
func TestPreNodePKCS11_NodeKeyResolvesBeforeTheNode(t *testing.T) {
	token := softhsmtest.Provision(t, "server-pre-node-key")
	s := preNodeServer(t, token.Library, token.Label)
	pin, err := types.NewLiteralSecretValue(context.Background(), []byte(token.UserPIN))
	require.NoError(t, err)

	require.NoError(t, s.registerPreNodePKCS11Backend(pin))
	opened := s.keyProviders["pkcs11"]
	require.NotNil(t, opened)
	t.Cleanup(func() { assert.NoError(t, opened.Close()) })
	require.Nil(t, s.sharedStorage(), "the token must open before the shared datastore exists")

	backend, err := nodeKeyFor(t, s)
	require.NoError(t, err)
	assert.Same(t, opened, backend.KeyProvider(),
		"the transport key must resolve to the token opened before the node")

	require.NoError(t, s.initPKCS11Backend())
	assert.Same(t, opened, s.keyProviders["pkcs11"],
		"the backend registry must reuse the pre-node open, not open the token twice")
}

// TestPreNodePKCS11_UnavailableTokenStillRefuses proves a PKCS#11 token that
// cannot be opened is a typed startup error and leaves no provider behind, so
// the node key is refused rather than replaced with a software key.
func TestPreNodePKCS11_UnavailableTokenStillRefuses(t *testing.T) {
	notAModule := filepath.Join(t.TempDir(), "libnotpkcs11.so")
	require.NoError(t, os.WriteFile(notAModule, []byte("not a module"), 0o600))
	s := preNodeServer(t, notAModule, "missing-token")
	pin, err := types.NewLiteralSecretValue(context.Background(), []byte("123456"))
	require.NoError(t, err)

	err = s.registerPreNodePKCS11Backend(pin)
	var initErr *ErrBackendInit
	require.True(t, errors.As(err, &initErr), "error = %v, want *ErrBackendInit", err)
	_, ok := s.keyProviders["pkcs11"]
	assert.False(t, ok, "a failed open must not register a provider")

	backend, err := nodeKeyFor(t, s)
	var notConfigured *clusterca.ErrNodeKeyBackendNotConfigured
	assert.True(t, errors.As(err, &notConfigured),
		"NodeKeyBackends(pkcs11) error = %v, want ErrNodeKeyBackendNotConfigured", err)
	assert.Nil(t, backend)
}

// TestOpenPreNodePKCS11Backend_SealedPINStoreRequired proves the pre-node
// open takes its PIN only from the TPM-sealed pre-barrier store: without a
// place for that store the open is a typed error, never a fallback to the
// configured (barrier-held) PIN.
func TestOpenPreNodePKCS11Backend_SealedPINStoreRequired(t *testing.T) {
	// Only tpm2 passes the pre-node backend PIN policy; the empty datastore
	// path makes the backend PIN record relative, so run in a scratch dir.
	t.Chdir(t.TempDir())
	s := preNodeServer(t, "/nonexistent/libsofthsm2.so", "token")
	s.config.Datastore.Path = ""
	s.config.Credentials.SealStrategy = "tpm2"
	s.backendPINProbe = func() (bool, bool) { return true, false }

	err := s.openPreNodePKCS11Backend()
	var initErr *ErrBackendInit
	require.True(t, errors.As(err, &initErr), "error = %v, want *ErrBackendInit", err)
	var pathErr *embeddednode.ErrDatastorePathRequired
	assert.True(t, errors.As(err, &pathErr), "error = %v, want ErrDatastorePathRequired", err)
	assert.Empty(t, s.keyProviders)
}

// requirePreNodePolicyRefusal checks a pre-node open refused by the backend
// PIN policy: the typed error, no token open and no strategy record.
func requirePreNodePolicyRefusal(t *testing.T, s *Server, err error, strategy pinselect.BackendPINStrategy) {
	t.Helper()
	require.ErrorIs(t, err, ErrBackendPINNodeKeyBeforeUnseal)
	assert.Contains(t, err.Error(), string(strategy))
	assert.Empty(t, s.keyProviders, "the token must not open below the tpm2 strategy")
	assert.Nil(t, s.backendPIN)
}

func requireNoBackendPINRecord(t *testing.T, s *Server) {
	t.Helper()
	_, err := pinselect.LoadBackendPINStrategy(s.backendPINDir())
	require.ErrorIs(t, err, pinselect.ErrBackendPINStrategyNotPersisted, "a refused pre-node resolution persisted a record")
}

// Before unseal only tpm2 can supply the PIN: a Raft key on the token with
// strategy sealed stops start-up before the token opens.
func TestOpenPreNodePKCS11Backend_SealedStrategyRefusedBeforeOpen(t *testing.T) {
	s := preNodeServer(t, "/nonexistent/libsofthsm2.so", "token")
	s.config.BackendPIN.Strategy = string(pinselect.BackendPINSealed)
	s.backendPINProbe = func() (bool, bool) { return false, true }

	err := s.openPreNodePKCS11Backend()
	requirePreNodePolicyRefusal(t, s, err, pinselect.BackendPINSealed)
	requireNoBackendPINRecord(t, s)
}

// auto with no TPM-sealed credentials resolves to sealed: refused the same.
func TestOpenPreNodePKCS11Backend_AutoToSealedRefusedBeforeOpen(t *testing.T) {
	s := preNodeServer(t, "/nonexistent/libsofthsm2.so", "token")
	// A TPM is present, but the credentials are not sealed to it.
	s.backendPINProbe = func() (bool, bool) { return true, false }

	err := s.openPreNodePKCS11Backend()
	requirePreNodePolicyRefusal(t, s, err, pinselect.BackendPINSealed)
	requireNoBackendPINRecord(t, s)
}

// A persisted sealed record governs auto: refused the same, record kept.
func TestOpenPreNodePKCS11Backend_PersistedSealedRefusedBeforeOpen(t *testing.T) {
	s := preNodeServer(t, "/nonexistent/libsofthsm2.so", "token")
	require.NoError(t, pinselect.SaveBackendPINStrategy(s.backendPINDir(), pinselect.BackendPINSealed))
	s.config.Credentials.SealStrategy = "tpm2"
	s.backendPINProbe = func() (bool, bool) { return true, false }

	err := s.openPreNodePKCS11Backend()
	requirePreNodePolicyRefusal(t, s, err, pinselect.BackendPINSealed)
	persisted, loadErr := pinselect.LoadBackendPINStrategy(s.backendPINDir())
	require.NoError(t, loadErr)
	assert.Equal(t, pinselect.BackendPINSealed, persisted)
}

// A minimum above the resolved strategy is refused before the open.
func TestOpenPreNodePKCS11Backend_MinimumRefusedBeforeOpen(t *testing.T) {
	s := preNodeServer(t, "/nonexistent/libsofthsm2.so", "token")
	s.config.BackendPIN.Minimum = string(pinselect.BackendPINTPM2)
	s.backendPINProbe = func() (bool, bool) { return false, true }

	err := s.openPreNodePKCS11Backend()
	var below *pinselect.BackendPINBelowMinimumError
	require.True(t, errors.As(err, &below), "error = %v, want BackendPINBelowMinimumError", err)
	assert.Empty(t, s.keyProviders)
	assert.Nil(t, s.backendPIN)
	requireNoBackendPINRecord(t, s)
}

// tpm2 with TPM-sealed credentials passes the policy and reaches the
// pre-barrier PIN release (here: no datastore path for its store).
func TestOpenPreNodePKCS11Backend_TPM2PassesPolicy(t *testing.T) {
	t.Chdir(t.TempDir())
	s := preNodeServer(t, "/nonexistent/libsofthsm2.so", "token")
	s.config.Datastore.Path = ""
	s.config.BackendPIN.Strategy = string(pinselect.BackendPINTPM2)
	s.config.Credentials.SealStrategy = "tpm2"
	s.backendPINProbe = func() (bool, bool) { return true, false }

	err := s.openPreNodePKCS11Backend()
	require.NotErrorIs(t, err, ErrBackendPINNodeKeyBeforeUnseal)
	var pathErr *embeddednode.ErrDatastorePathRequired
	require.True(t, errors.As(err, &pathErr), "error = %v, want ErrDatastorePathRequired", err)
	assert.Empty(t, s.keyProviders)

	// The later start-up step reuses the pre-node resolution.
	require.NoError(t, s.resolveBackendPIN())
	require.NotNil(t, s.backendPIN)
	assert.Equal(t, pinselect.BackendPINTPM2, s.backendPIN.Strategy())
}

// Without a Raft key on the token nothing opens before the node and the
// sealed strategy stays allowed.
func TestOpenPreNodePKCS11Backend_NoNodeKeyKeepsSealed(t *testing.T) {
	s := preNodeServer(t, "/nonexistent/libsofthsm2.so", "token")
	s.config.Cluster.RaftEnrollment.KeyBackend = ""
	s.config.BackendPIN.Strategy = string(pinselect.BackendPINSealed)
	s.backendPINProbe = func() (bool, bool) { return false, true }

	require.NoError(t, s.openPreNodePKCS11Backend())
	assert.Empty(t, s.keyProviders)
	require.NoError(t, s.resolveBackendPIN())
	require.NotNil(t, s.backendPIN)
	assert.Equal(t, pinselect.BackendPINSealed, s.backendPIN.Strategy())
}

// TestOpenPreNodePKCS11Backend_OnlyForAPKCS11NodeKey proves nothing opens
// before the node unless the Raft transport key is enrolled on the token.
func TestOpenPreNodePKCS11Backend_OnlyForAPKCS11NodeKey(t *testing.T) {
	cases := map[string]func(*config.Config){
		"standalone":         func(c *config.Config) { c.Cluster.Enabled = false },
		"tpm2 node key":      func(c *config.Config) { c.Cluster.RaftEnrollment.KeyBackend = "tpm2" },
		"pkcs11 not enabled": func(c *config.Config) { c.Backends.PKCS11.Enabled = false },
		"no pkcs11 backend":  func(c *config.Config) { c.Backends.PKCS11 = nil },
		"static raft tls": func(c *config.Config) {
			c.Cluster.RaftTLS = config.RaftTLSConfig{CACertFile: "ca.pem", CertFile: "node.pem", KeyFile: "node.key"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := preNodeServer(t, "/nonexistent/libsofthsm2.so", "token")
			s.config.Datastore.Path = ""
			mutate(s.config)

			require.NoError(t, s.openPreNodePKCS11Backend())
			assert.Empty(t, s.keyProviders)
		})
	}
}

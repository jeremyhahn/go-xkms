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

//go:build raft

package server

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// nodeKeyServer is a local-CA cluster node whose transport key is the
// PKCS#11 backend, with the given daemon backends.
func nodeKeyServer(t *testing.T, providers map[string]types.KeyProvider) *Server {
	t.Helper()
	return &Server{
		keyProviders: providers,
		config: &config.Config{
			Datastore: config.DatastoreConfig{Path: t.TempDir()},
			Cluster: config.ClusterConfig{
				NodeID:         1,
				RaftAddress:    "10.0.0.1:63001",
				RaftEnrollment: config.RaftEnrollmentConfig{KeyBackend: "pkcs11"},
			},
		},
	}
}

// TestBuildClusterCAOptions_NodeKeyRefusesMissingHardware verifies a node
// configured for a PKCS#11 transport key without a PKCS#11 backend is
// refused, even though CA custody resolves every name.
func TestBuildClusterCAOptions_NodeKeyRefusesMissingHardware(t *testing.T) {
	s := nodeKeyServer(t, nil)
	custody := func(string) (xkms.Backend, error) { return nil, nil }

	opts, err := s.buildClusterCAOptions(map[uint64]string{1: "10.0.0.1:63001"}, custody)
	if err != nil {
		t.Fatalf("buildClusterCAOptions: %v", err)
	}
	backend, err := opts.NodeKeyBackends(opts.KeyBackend)
	var notConfigured *clusterca.ErrNodeKeyBackendNotConfigured
	if !errors.As(err, &notConfigured) {
		t.Fatalf("NodeKeyBackends(pkcs11) error = %v, want ErrNodeKeyBackendNotConfigured", err)
	}
	if backend != nil {
		t.Errorf("NodeKeyBackends(pkcs11) = %v, want no backend", backend)
	}
}

// TestBuildClusterCAOptions_NodeKeyUsesDaemonHardware verifies the transport
// key resolves to the daemon's own PKCS#11 backend.
func TestBuildClusterCAOptions_NodeKeyUsesDaemonHardware(t *testing.T) {
	hsm := &nonSealerProvider{}
	s := nodeKeyServer(t, map[string]types.KeyProvider{"pkcs11": hsm})
	custody := func(string) (xkms.Backend, error) { return nil, nil }

	opts, err := s.buildClusterCAOptions(map[uint64]string{1: "10.0.0.1:63001"}, custody)
	if err != nil {
		t.Fatalf("buildClusterCAOptions: %v", err)
	}
	backend, err := opts.NodeKeyBackends(opts.KeyBackend)
	if err != nil {
		t.Fatalf("NodeKeyBackends(pkcs11): %v", err)
	}
	if backend.KeyProvider() != types.KeyProvider(hsm) {
		t.Error("the transport key must resolve to the daemon's PKCS#11 key provider")
	}
}

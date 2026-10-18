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
	"path/filepath"
	"testing"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestBuildClusterACMEOptions_Defaults verifies that an ACME enrollment config
// with no overrides maps onto clusterca.Options with the documented defaults
// (xkms.cluster trust domain, the default Noise port, the "8080" challenge
// port), routes the cache under the cluster-ca subdirectory, and carries the CA
// config through for the first-node pre-stage.
func TestBuildClusterACMEOptions_Defaults(t *testing.T) {
	dir := t.TempDir()
	caCfg := ca.DefaultMultiIdentityCAConfigWithIntermediate()
	s := &Server{config: &config.Config{
		Datastore: config.DatastoreConfig{Path: dir},
		CA:        caCfg,
		Cluster: config.ClusterConfig{
			NodeID:      1,
			RaftAddress: "10.0.0.1:63001",
			RaftEnrollment: config.RaftEnrollmentConfig{
				ACME:        config.RaftACMEEnrollmentConfig{Enabled: true},
				ClusterCACN: "Cluster CA",
			},
		},
	}}
	members := map[uint64]string{1: "10.0.0.1:63001", 2: "10.0.0.2:63001"}
	backends := func(string) (xkms.Backend, error) { return nil, nil }

	opts, err := s.buildClusterCAOptions(members, backends)
	if err != nil {
		t.Fatalf("buildClusterCAOptions: %v", err)
	}

	if opts.TrustDomain != defaultRaftTrustDomain {
		t.Errorf("TrustDomain = %q, want %q", opts.TrustDomain, defaultRaftTrustDomain)
	}
	if opts.ACME == nil {
		t.Fatal("ACME options are nil")
	}
	if opts.ACME.ChallengePort != defaultClusterACMEChallengePort {
		t.Errorf("ACME.ChallengePort = %q, want %q", opts.ACME.ChallengePort, defaultClusterACMEChallengePort)
	}
	if opts.ACME.ChallengeHost != s.config.Server.Host {
		t.Errorf("ACME.ChallengeHost = %q, want the daemon's server.host %q", opts.ACME.ChallengeHost, s.config.Server.Host)
	}
	if opts.Advertise.NoisePort != clusterenroll.DefaultNoisePort {
		t.Errorf("Advertise.NoisePort = %d, want %d", opts.Advertise.NoisePort, clusterenroll.DefaultNoisePort)
	}
	if opts.NodeID != 1 {
		t.Errorf("NodeID = %d, want 1", opts.NodeID)
	}
	if opts.ClusterCACN != "Cluster CA" {
		t.Errorf("ClusterCACN = %q, want \"Cluster CA\"", opts.ClusterCACN)
	}
	if want := filepath.Join(dir, clusterCACacheSubdir); opts.DataDir != want {
		t.Errorf("DataDir = %q, want %q", opts.DataDir, want)
	}
	if opts.CAConfig != caCfg {
		t.Error("CAConfig was not carried through for the first-node pre-stage")
	}
	if opts.Backends == nil {
		t.Error("Backends seam was not carried through")
	}
}

// TestBuildClusterCAOptions_HardwareKey checks that a key backend without ACME
// enrollment maps to local-CA mode: no ACME options, the key backend and
// the CA configuration carried through for TrustedCA issuance (go-xkms#1381).
func TestBuildClusterCAOptions_HardwareKey(t *testing.T) {
	caCfg := ca.DefaultMultiIdentityCAConfigWithIntermediate()
	s := &Server{config: &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
		CA:        caCfg,
		Cluster: config.ClusterConfig{
			NodeID:      1,
			RaftAddress: "10.0.0.1:63001",
			RaftEnrollment: config.RaftEnrollmentConfig{
				KeyBackend: "tpm2",
			},
		},
	}}
	backends := func(string) (xkms.Backend, error) { return nil, nil }

	opts, err := s.buildClusterCAOptions(map[uint64]string{1: "10.0.0.1:63001"}, backends)
	if err != nil {
		t.Fatalf("buildClusterCAOptions: %v", err)
	}
	if opts.ACME != nil {
		t.Errorf("ACME = %+v, want nil for local-CA mode", opts.ACME)
	}
	if opts.KeyBackend != "tpm2" {
		t.Errorf("KeyBackend = %q, want tpm2", opts.KeyBackend)
	}
	if opts.CAConfig != caCfg {
		t.Error("CAConfig was not carried through for TrustedCA issuance")
	}
}

// TestBuildClusterACMEOptions_ExplicitOverrides verifies that explicit trust
// domain, challenge port, and joiner directory URL survive the mapping.
func TestBuildClusterACMEOptions_ExplicitOverrides(t *testing.T) {
	dir := t.TempDir()
	s := &Server{config: &config.Config{
		Server:    config.ServerConfig{Host: "10.0.0.5"},
		Datastore: config.DatastoreConfig{Path: dir},
		Cluster: config.ClusterConfig{
			NodeID:      2,
			RaftAddress: "10.0.0.2:63001",
			RaftEnrollment: config.RaftEnrollmentConfig{
				TrustDomain: "prod.cluster",
				KeyBackend:  "tpm2",
				ACME: config.RaftACMEEnrollmentConfig{
					Enabled:       true,
					DirectoryURL:  "https://node1:8443/api/v1/acme/directory",
					ChallengePort: "9090",
				},
			},
		},
	}}
	members := map[uint64]string{1: "10.0.0.1:63001", 2: "10.0.0.2:63001"}
	backends := func(string) (xkms.Backend, error) { return nil, nil }

	opts, err := s.buildClusterCAOptions(members, backends)
	if err != nil {
		t.Fatalf("buildClusterCAOptions: %v", err)
	}

	if opts.TrustDomain != "prod.cluster" {
		t.Errorf("TrustDomain = %q, want prod.cluster", opts.TrustDomain)
	}
	if opts.KeyBackend != "tpm2" {
		t.Errorf("KeyBackend = %q, want tpm2", opts.KeyBackend)
	}
	if opts.ACME.DirectoryURL != "https://node1:8443/api/v1/acme/directory" {
		t.Errorf("ACME.DirectoryURL = %q", opts.ACME.DirectoryURL)
	}
	if opts.ACME.ChallengePort != "9090" {
		t.Errorf("ACME.ChallengePort = %q, want 9090", opts.ACME.ChallengePort)
	}
	if opts.ACME.ChallengeHost != "10.0.0.5" {
		t.Errorf("ACME.ChallengeHost = %q, want server.host 10.0.0.5: the enroll-01 listener binds what every daemon listener binds (#140)", opts.ACME.ChallengeHost)
	}
}

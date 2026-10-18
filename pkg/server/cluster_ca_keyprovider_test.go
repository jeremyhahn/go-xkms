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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestTrustedCAIsClusterCA pins which deployments make the TrustedCA go-qrdb's
// cluster CA (Key A): every one with a CA, except those whose cluster identity
// another CA owns (go-xkms#1381).
func TestTrustedCAIsClusterCA(t *testing.T) {
	operatorFiles := config.RaftTLSConfig{CACertFile: "ca.pem", CertFile: "node.pem", KeyFile: "node-key.pem"}
	cases := []struct {
		name    string
		ca      bool
		cluster config.ClusterConfig
		want    bool
	}{
		{name: "no CA configured", ca: false, want: false},
		{name: "standalone node", ca: true, want: true},
		{
			name:    "clustered, ACME enrollment",
			ca:      true,
			cluster: config.ClusterConfig{Enabled: true, RaftEnrollment: config.RaftEnrollmentConfig{ACME: config.RaftACMEEnrollmentConfig{Enabled: true}}},
			want:    true,
		},
		{
			name:    "clustered, local-CA with a hardware key backend",
			ca:      true,
			cluster: config.ClusterConfig{Enabled: true, RaftEnrollment: config.RaftEnrollmentConfig{KeyBackend: "tpm2"}},
			want:    true,
		},
		{
			name:    "clustered, local-CA with the software key backend",
			ca:      true,
			cluster: config.ClusterConfig{Enabled: true},
			want:    true,
		},
		{
			name: "clustered, operator files win over the TrustedCA",
			ca:   true,
			cluster: config.ClusterConfig{
				Enabled:        true,
				RaftTLS:        operatorFiles,
				RaftEnrollment: config.RaftEnrollmentConfig{KeyBackend: "tpm2"},
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Cluster: tc.cluster}
			if tc.ca {
				cfg.CA = ca.DefaultMultiIdentityCAConfigWithIntermediate()
			}
			s := &Server{config: cfg}
			if got := s.trustedCAIsClusterCA(); got != tc.want {
				t.Errorf("trustedCAIsClusterCA() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestClusterCAKeyProviderOptions verifies the node gets the TrustedCA key
// provider, retained for initializeCA to bind, exactly when the TrustedCA is
// the cluster CA.
func TestClusterCAKeyProviderOptions(t *testing.T) {
	s := &Server{config: &config.Config{CA: ca.DefaultMultiIdentityCAConfigWithIntermediate()}}
	if opts := s.clusterCAKeyProviderOptions(); len(opts) != 1 {
		t.Fatalf("clusterCAKeyProviderOptions() returned %d options, want 1", len(opts))
	}
	if s.clusterCAKeyProvider == nil {
		t.Fatal("the key provider was not retained for initializeCA to bind")
	}
}

// TestClusterCAKeyProviderOptions_NoCA verifies a node without a TrustedCA
// keeps go-qrdb's own cluster CA: no option and no provider.
func TestClusterCAKeyProviderOptions_NoCA(t *testing.T) {
	s := &Server{config: &config.Config{}}
	if opts := s.clusterCAKeyProviderOptions(); len(opts) != 0 {
		t.Fatalf("clusterCAKeyProviderOptions() returned %d options, want 0", len(opts))
	}
	if s.clusterCAKeyProvider != nil {
		t.Fatal("a key provider was created without a TrustedCA")
	}
}

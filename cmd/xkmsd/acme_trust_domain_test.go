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

package main

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
)

// TestClusterACMETrustDomain_IsEmbeddedNodeTrustDomain pins the
// trust-domain-grammar row: the ACME node URI-SAN hook names nodes under the
// one cluster trust domain, embeddednode.TrustDomain, with no default of its
// own.
func TestClusterACMETrustDomain_IsEmbeddedNodeTrustDomain(t *testing.T) {
	for _, cfg := range []*config.Config{
		{},
		{Cluster: config.ClusterConfig{RaftEnrollment: config.RaftEnrollmentConfig{TrustDomain: "prod.example"}}},
	} {
		if got, want := clusterACMETrustDomain(cfg), embeddednode.TrustDomain(cfg); got != want {
			t.Errorf("clusterACMETrustDomain = %q, want embeddednode.TrustDomain %q", got, want)
		}
	}
}

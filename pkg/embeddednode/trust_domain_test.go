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

package embeddednode

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestEmbeddedNodeStorageConfig_OneClusterTrustDomain pins the
// trust-domain-grammar row: the embedded go-qrdb node uses the trust domain
// go-xkms names its cluster with, for both its peer identities
// (Auth.ClusterTrustDomain, which go-qrdb stamps into node SANs and pins in
// clusterkeys) and its tenant principals (Auth.SPIFFETrustDomain). Without
// ClusterTrustDomain go-qrdb falls back to its own "qrdb.cluster".
func TestEmbeddedNodeStorageConfig_OneClusterTrustDomain(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{name: "default", cfg: &config.Config{}, want: DefaultTrustDomain},
		{name: "configured", cfg: &config.Config{Cluster: config.ClusterConfig{
			RaftEnrollment: config.RaftEnrollmentConfig{TrustDomain: "prod.example"},
		}}, want: "prod.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, TrustDomain(tc.cfg))
			qcfg := EmbeddedNodeStorageConfig(tc.cfg, ResolvedNodeSeal{})
			assert.Equal(t, TrustDomain(tc.cfg), qcfg.Auth.ClusterTrustDomain)
			assert.Equal(t, TrustDomain(tc.cfg), qcfg.Auth.EffectiveClusterTrustDomain())
			assert.Equal(t, TrustDomain(tc.cfg), qcfg.Auth.SPIFFETrustDomain)
			assert.Equal(t, TrustDomain(tc.cfg), qcfg.Auth.EffectiveSPIFFETrustDomain())
		})
	}
}

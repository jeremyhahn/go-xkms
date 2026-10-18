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
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	clustercapkg "github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
)

// trustedCAIsClusterCA reports whether the TrustedCA is go-qrdb's cluster CA
// (Key A): a CA is configured and no other CA owns the cluster identity. A
// standalone node, and a clustered node whose Raft leaf the TrustedCA issues
// (ACME or local-CA mode, any key backend), qualify. Operator-supplied Raft
// TLS is BYO-TLS with no Key A.
func (s *Server) trustedCAIsClusterCA() bool {
	if s.config.CA == nil {
		return false
	}
	cluster := s.config.Cluster
	return !cluster.Enabled || !cluster.RaftTLS.Enabled()
}

// clusterCAKeyProviderOptions returns the node option that makes the TrustedCA
// go-qrdb's cluster CA through WithClusterCAKeyProvider (go-xkms#1381): every
// Key A signature goes through the TrustedCA's crypto.Signer and no CA key
// bytes reach the node. The provider is bound in initializeCA; nil when the
// TrustedCA is not the cluster CA.
func (s *Server) clusterCAKeyProviderOptions() []qrdbnode.NodeOption {
	if !s.trustedCAIsClusterCA() {
		return nil
	}
	s.clusterCAKeyProvider = clustercapkg.NewKeyProvider(s.config.Cluster.RaftEnrollment.ClusterCACN)
	return []qrdbnode.NodeOption{qrdbnode.WithClusterCAKeyProvider(s.clusterCAKeyProvider)}
}

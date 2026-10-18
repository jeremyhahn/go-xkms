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

//go:build !raft

package embeddednode

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewNode_ClusterWithoutRaftBuildFailsLoudly is the non-vacuousness guard
// for the build-tag contract: a binary compiled without `-tags raft` must
// REFUSE a clustered configuration rather than quietly starting a standalone
// node. A silent downgrade would present a single node as a replicated
// cluster, so this must be an error, not a warning.
func TestNewNode_ClusterWithoutRaftBuildFailsLoudly(t *testing.T) {
	opts := &NodeOptions{
		QRDB:   newTestQRDBConfig(),
		Logger: testLogger(),
		Cluster: ClusterOptions{
			Enabled: true,
			NodeID:  1,
			Peers:   "1=10.0.0.1:9001,2=10.0.0.2:9001",
		},
	}

	res, err := NewNode(t.Context(), opts)

	require.Error(t, err)
	assert.Nil(t, res, "no node may be returned when clustering is unavailable")
	assert.ErrorIs(t, err, ErrClusterRequiresRaftBuild)
}

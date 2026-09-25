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

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestWaitForClusterLeader_StandaloneNodeReportsItselfLeaderImmediately
// proves the success path: over the embedded standalone node (the default,
// non "-tags raft" build this package's fast test suite always uses),
// s.qrdbClient.Cluster().Leader immediately reports the single replica as
// its own shard's leader, so waitForClusterLeader returns nil on the first
// poll without ever reaching its ctx.Done()/deadline branches.
//
// Those branches (no leader within the 30s timeout, or the context
// cancelled while still waiting) are only reachable against a genuine
// multi-node `-tags raft` cluster whose election has not yet settled or
// never completes -- a scenario this package's fast, hermetic test build
// cannot construct without either a real multi-process cluster or a 30s
// sleep, both excluded here (see go-xkms#705 batch 3's final report for
// this gap). This test pins the one branch that is reachable in-process.
func TestWaitForClusterLeader_StandaloneNodeReportsItselfLeaderImmediately(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}

	s, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = s.Shutdown() }()

	require.NotNil(t, s.qrdbClient, "New must have constructed the embedded qrdb client")

	err = s.waitForClusterLeader()
	assert.NoError(t, err, "a standalone node must report itself as the shard leader on the first poll")
}

// TestWaitForClusterLeader_DefaultsShardIDToOne proves the ShardID==0
// default-to-1 branch: a config that never set Cluster.ShardID still
// resolves a leader, exercising the "shardID == 0" fallback rather than
// polling shard 0 forever.
func TestWaitForClusterLeader_DefaultsShardIDToOne(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}
	cfg.Cluster.ShardID = 0

	s, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = s.Shutdown() }()

	require.Equal(t, uint64(0), s.config.Cluster.ShardID)
	assert.NoError(t, s.waitForClusterLeader())
}

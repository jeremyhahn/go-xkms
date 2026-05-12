// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package qrdb

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

// Registry is the Prometheus registry for QRDB metrics.
var Registry = prometheus.NewRegistry()

// RaftMetricsCollector collects Raft cluster metrics from the QRDB
// admin service and exposes them as Prometheus gauges.
type RaftMetricsCollector struct {
	service   Service
	nodeID    string
	clusterID string

	raftLeader       prometheus.Gauge
	raftTerm         prometheus.Gauge
	raftAppliedIndex prometheus.Gauge
	raftPeers        prometheus.Gauge
	raftCommitIndex  prometheus.Gauge
	raftShardCount   prometheus.Gauge
	raftIsDraining   prometheus.Gauge
}

// NewRaftMetricsCollector creates a RaftMetricsCollector and registers
// its metrics with the package-level Registry.
func NewRaftMetricsCollector(service Service, nodeID, clusterID string) *RaftMetricsCollector {
	labels := prometheus.Labels{
		"node_id":    nodeID,
		"cluster_id": clusterID,
	}

	c := &RaftMetricsCollector{
		service:   service,
		nodeID:    nodeID,
		clusterID: clusterID,

		raftLeader: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "qrdb",
			Subsystem:   "raft",
			Name:        "leader",
			Help:        "Whether this node is the Raft leader (1=leader, 0=follower).",
			ConstLabels: labels,
		}),
		raftTerm: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "qrdb",
			Subsystem:   "raft",
			Name:        "term",
			Help:        "Current Raft term.",
			ConstLabels: labels,
		}),
		raftAppliedIndex: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "qrdb",
			Subsystem:   "raft",
			Name:        "applied_index",
			Help:        "Last applied Raft log index.",
			ConstLabels: labels,
		}),
		raftPeers: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "qrdb",
			Subsystem:   "raft",
			Name:        "peers",
			Help:        "Number of known Raft peers.",
			ConstLabels: labels,
		}),
		raftCommitIndex: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "qrdb",
			Subsystem:   "raft",
			Name:        "commit_index",
			Help:        "Current Raft commit index.",
			ConstLabels: labels,
		}),
		raftShardCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "qrdb",
			Subsystem:   "raft",
			Name:        "shard_count",
			Help:        "Number of Raft shards loaded on this node.",
			ConstLabels: labels,
		}),
		raftIsDraining: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   "qrdb",
			Subsystem:   "raft",
			Name:        "is_draining",
			Help:        "Whether this node is in drain mode (1=draining, 0=normal).",
			ConstLabels: labels,
		}),
	}

	Registry.MustRegister(
		c.raftLeader,
		c.raftTerm,
		c.raftAppliedIndex,
		c.raftPeers,
		c.raftCommitIndex,
		c.raftShardCount,
		c.raftIsDraining,
	)

	return c
}

// Collect queries the QRDB admin service and updates all Prometheus
// gauge metrics with the current Raft cluster state.
func (c *RaftMetricsCollector) Collect(ctx context.Context) error {
	admin := c.service.Admin()

	// Collect status metrics.
	status, err := admin.Status(ctx)
	if err != nil {
		return NewError(ErrorCodeInternal, "failed to collect status metrics").
			WithCause(err)
	}

	if status.IsLeader {
		c.raftLeader.Set(1)
	} else {
		c.raftLeader.Set(0)
	}
	c.raftShardCount.Set(float64(status.ShardCount))
	if status.IsDraining {
		c.raftIsDraining.Set(1)
	} else {
		c.raftIsDraining.Set(0)
	}

	// Collect peer metrics.
	peers, err := admin.Peers(ctx)
	if err != nil {
		return NewError(ErrorCodeInternal, "failed to collect peer metrics").
			WithCause(err)
	}

	totalPeers := 0
	for _, shard := range peers.Shards {
		totalPeers += len(shard.Peers)
	}
	c.raftPeers.Set(float64(totalPeers))

	return nil
}

// Unregister removes all collector metrics from the package-level Registry.
func (c *RaftMetricsCollector) Unregister() {
	Registry.Unregister(c.raftLeader)
	Registry.Unregister(c.raftTerm)
	Registry.Unregister(c.raftAppliedIndex)
	Registry.Unregister(c.raftPeers)
	Registry.Unregister(c.raftCommitIndex)
	Registry.Unregister(c.raftShardCount)
	Registry.Unregister(c.raftIsDraining)
}

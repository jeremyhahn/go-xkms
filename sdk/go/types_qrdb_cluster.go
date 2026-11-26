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

// This file re-exports the go-qrdb/sdk/go runtime peer-discovery and
// cluster-formation primitives so that downstream consumers (e.g.
// go-quicbaas, go-trusted-platform) can depend solely on the go-xkms SDK
// without importing go-qrdb directly.
//
// Every alias is prefixed with QRDB to avoid name collisions with go-xkms's
// own types. Note these are the RUNTIME discovery primitives (interfaces,
// constructors, manager) that xkms's own node-embedding and trust-bootstrap
// paths consume; the YAML/config-layer discovery aliases formerly re-exported
// from types_qrdb.go were removed as a database/cluster-plane surface that
// belongs to github.com/jeremyhahn/go-qrdb/sdk/go, not to go-xkms's SDK.

package xkms

import (
	qrdb "github.com/jeremyhahn/go-qrdb/sdk/go/cluster"
)

// ==========================================================================
// Runtime discovery primitives (from types_discovery.go in go-qrdb/sdk/go)
// ==========================================================================

// QRDBPeer is a discovered cluster peer.
type QRDBPeer = qrdb.Peer

// QRDBDiscoveryBackend is the behavior implemented by every runtime discovery
// method.
type QRDBDiscoveryBackend = qrdb.DiscoveryBackend

// QRDBDiscoveryConfig is the shared runtime discovery configuration.
type QRDBDiscoveryConfig = qrdb.DiscoveryConfig

// QRDBDiscoveryStaticConfig configures static (fixed peer-list) discovery.
type QRDBDiscoveryStaticConfig = qrdb.DiscoveryStaticConfig

// QRDBDiscoveryMulticastConfig configures multicast (LAN announcement)
// discovery.
type QRDBDiscoveryMulticastConfig = qrdb.DiscoveryMulticastConfig

// QRDBDiscoveryDNSConfig configures DNS SRV-record discovery.
type QRDBDiscoveryDNSConfig = qrdb.DiscoveryDNSConfig

// QRDBDiscoveryTokenConfig configures token-server (HTTP) discovery.
type QRDBDiscoveryTokenConfig = qrdb.DiscoveryTokenConfig

// QRDBDiscoveryManager fans out across multiple discovery methods.
type QRDBDiscoveryManager = qrdb.DiscoveryManager

// QRDBDiscoveryManagerConfig configures a QRDBDiscoveryManager.
type QRDBDiscoveryManagerConfig = qrdb.DiscoveryManagerConfig

// Runtime discovery constructors.
var (
	// QRDBNewDiscoveryManager builds a discovery Manager from its config.
	QRDBNewDiscoveryManager = qrdb.NewDiscoveryManager

	// QRDBNewStaticDiscovery builds a static discovery method.
	QRDBNewStaticDiscovery = qrdb.NewStaticDiscovery

	// QRDBNewMulticastDiscovery builds a multicast discovery method.
	QRDBNewMulticastDiscovery = qrdb.NewMulticastDiscovery

	// QRDBNewDNSDiscovery builds a DNS SRV discovery method.
	QRDBNewDNSDiscovery = qrdb.NewDNSDiscovery

	// QRDBNewTokenDiscovery builds a token-server discovery method.
	QRDBNewTokenDiscovery = qrdb.NewTokenDiscovery
)

// ==========================================================================
// Cluster-formation entry points (from go-qrdb/sdk/go types_discovery.go)
// ==========================================================================

// QRDBDiscoveryOptions configures cluster-formation discovery
// (QRDBBuildDiscovery).
type QRDBDiscoveryOptions = qrdb.DiscoveryOptions

// Cluster-formation constructors.
var (
	// QRDBBuildDiscovery constructs a QRDBDiscoveryBackend from
	// QRDBDiscoveryOptions.
	QRDBBuildDiscovery = qrdb.BuildDiscovery

	// QRDBBootstrapShard forms or joins a Raft shard using peer discovery.
	QRDBBootstrapShard = qrdb.BootstrapShard
)

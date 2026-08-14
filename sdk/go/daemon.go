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

package xkms

import (
	xkmsdaemon "github.com/jeremyhahn/go-xkms/pkg/daemon"
)

// ---------------------------------------------------------------------------
// Embedded go-qrdb node construction
//
// This is the single node-construction path for the stack. go-xkms itself and
// every downstream project that embeds go-qrdb through go-xkms builds its node
// with NewDaemonNode rather than reaching for go-qrdb's node constructors
// directly, so the standalone/clustered decision, membership parsing, and
// inter-node mTLS provisioning live in exactly one place.
//
// Clustering is compiled in only with the `raft` build tag; without it a
// clustered configuration fails with ErrClusterRequiresRaftBuild instead of
// silently degrading to a single node.
//
// Hardware-backed provisioning (TPM-attested ACME enrollment, PKCS#11 / TPM2
// resident node keys) is injected through DaemonOptions.RaftMTLSResolver,
// because those strategies depend on a certificate authority owned by the
// daemon rather than by node construction. A nil resolver selects the built-in
// software auto-provisioning path.
// ---------------------------------------------------------------------------

// DaemonOptions configures embedded node construction.
type DaemonOptions = xkmsdaemon.Options

// DaemonClusterOptions describes the clustered topology. Its zero value is a
// valid standalone configuration.
type DaemonClusterOptions = xkmsdaemon.ClusterOptions

// DaemonNodeResult carries the constructed node and any cluster-enrollment
// advertiser whose lifecycle the caller owns.
type DaemonNodeResult = xkmsdaemon.Result

// RaftMTLSResolver resolves inter-node mTLS material for a multi-node cluster.
type RaftMTLSResolver = xkmsdaemon.RaftMTLSResolver

// NewDaemonNode builds the embedded go-qrdb node for the given options, in
// either standalone or clustered topology.
var NewDaemonNode = xkmsdaemon.NewNode

// Defaults applied when the corresponding option is unset.
const (
	// DefaultClusterTrustDomain is the SPIFFE trust domain stamped into
	// auto-provisioned Raft node certificates.
	DefaultClusterTrustDomain = xkmsdaemon.DefaultTrustDomain

	// RaftTLSCacheSubdir is the subdirectory of the storage path where
	// auto-provisioned cluster TLS material is cached across restarts.
	RaftTLSCacheSubdir = xkmsdaemon.RaftTLSCacheSubdir
)

// Node-construction errors.
var (
	// ErrNilDaemonOptions is returned when NewDaemonNode is called with nil
	// options.
	ErrNilDaemonOptions = xkmsdaemon.ErrNilOptions

	// ErrNilDaemonQRDBConfig is returned when DaemonOptions.QRDB is unset.
	ErrNilDaemonQRDBConfig = xkmsdaemon.ErrNilQRDBConfig

	// ErrNilDaemonLogger is returned when DaemonOptions.Logger is unset.
	ErrNilDaemonLogger = xkmsdaemon.ErrNilLogger

	// ErrClusterRequiresRaftBuild is returned when a clustered configuration
	// is supplied to a binary built without the `raft` build tag.
	ErrClusterRequiresRaftBuild = xkmsdaemon.ErrClusterRequiresRaftBuild
)

// Typed membership-parsing errors, returned by DaemonClusterOptions.Members
// for malformed "nodeID=address" peer entries.
type (
	// MemberFormatError reports an entry that is not in nodeID=address form.
	MemberFormatError = xkmsdaemon.MemberFormatError

	// MemberNodeIDError reports an entry whose node ID is unparseable or zero.
	MemberNodeIDError = xkmsdaemon.MemberNodeIDError

	// MemberAddressError reports an entry with an empty address.
	MemberAddressError = xkmsdaemon.MemberAddressError
)

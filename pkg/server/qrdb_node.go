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
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"

	"github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/unix"
	"github.com/jeremyhahn/go-xkms/pkg/apimodule"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/webui"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// buildXKMSQRDBConfig translates the xkms configuration into the qrdb node
// configuration used to construct the in-process engine. xkms hosts qrdb as
// its single core: the node is the one database and the source of identity,
// bootstrap, and clustering.
//
// There is exactly ONE barrier in the system: the node's own. Whenever the
// barrier is enabled the node's seal subsystem is enabled and IS that
// barrier, sealed by the strategy resolveNodeSeal resolved; xkms adopts it
// (initEmbeddedQRDBNode) and never builds a second one.
//
// Standalone hosting maps:
//   - Datastore.Path   -> Raft.DataDir (local engine root)
//   - Datastore.Engine -> Databases[0] = {default, mvcc, memory|file|pebble}
func (s *Server) buildXKMSQRDBConfig() *qrdbsdk.DaemonConfig {
	// The storage+seal shape (Auth, Raft.DataDir, Databases, Seal.*,
	// Storage.VolumePools) comes from the shared, Server-independent builder
	// so this deployment's config resolves the SAME shape xkmsd init resolves
	// from the same *config.Config -- see embedded_node.go.
	qcfg := embeddednode.EmbeddedNodeStorageConfig(s.config, s.nodeSeal())

	// Unified API server: network serving runs exclusively on the node's
	// own multi-protocol server, which takes xkmsd's REST/gRPC/Unix/MCP
	// ports and serves the xkms capability plane through the registered
	// ServiceModule. QUIC is HTTP/3 on the REST port (the node's REST
	// server runs an HTTP/3 listener alongside TCP and advertises it via
	// Alt-Svc). Enabling protocols here means node construction runs the
	// full qrdb server start pipeline — module surfaces answer
	// Unavailable/503 until xkmsd finishes composing the XKMSService.
	//
	// The loopback desktop engine (pkg/server/loopback) is exempt even
	// though it forces Protocols.REST on (see Config.LoopbackDesktop): it
	// serves REST itself on an injected, pre-bound 127.0.0.1 listener
	// (Server.startREST, gated on s.restListener != nil), never through
	// this node. The datastore is still always hosted -- LoopbackDesktop
	// only means "this process is not the unified network API server",
	// never "this process has no datastore" -- so createStorage still
	// resolves through the node's KV below; only the node's OWN network
	// listeners are skipped, avoiding a double bind on the same host.
	if s.config.NodeServing() && !s.config.LoopbackDesktop {
		qcfg.Server.Host = s.config.Server.Host
		qcfg.Server.AdminPort = s.config.Server.RESTPort
		qcfg.Server.GRPCPort = s.config.Server.GRPCPort
		qcfg.Protocols.REST = s.config.Protocols.REST
		qcfg.Protocols.GRPC = s.config.Protocols.GRPC
		qcfg.Protocols.MCP = s.config.Protocols.MCP
		// The Unix socket is the node's TLS unix listener: the same auth
		// chain as every other transport (client certificate or session
		// JWT), so the CLI and the pkcs11 module present credentials over
		// it like any network client.
		qcfg.Protocols.Unix = s.config.Protocols.Unix
		qcfg.Unix.SocketPath = s.config.Unix.SocketPath
		if qcfg.Unix.SocketPath == "" {
			qcfg.Unix.SocketPath = unix.DefaultSocketPath
		}
		if s.config.Protocols.MCP {
			qcfg.MCP.Port = s.config.Server.MCPPort
		}
	}

	// Map cluster configuration onto the qrdb Raft config. These fields are
	// consumed only by the clustered node path (built with -tags raft); for a
	// standalone node they are ignored. Validation (config.Validate) guarantees
	// the required fields are present when Cluster.Enabled.
	if s.config.Cluster.Enabled {
		qcfg.Raft.ReplicaID = s.config.Cluster.NodeID
		qcfg.Raft.ShardID = s.config.Cluster.ShardID
		qcfg.Raft.DeploymentID = s.config.Cluster.DeploymentID
		qcfg.Raft.RaftAddress = s.config.Cluster.RaftAddress
		qcfg.Raft.ListenAddress = s.config.Cluster.ListenAddress
		qcfg.Raft.Peers = s.config.Cluster.Peers
		qcfg.Raft.MemberIdentities = s.config.Cluster.MemberIdentities
		qcfg.Raft.Join = s.config.Cluster.Join
	}

	return qcfg
}

// newQRDBAuditSink builds the compliance-grade audit sink injected into the
// embedded qrdb node, via the shared, Server-independent NewEmbeddedAuditSink
// (embedded_node.go). The returned sink is retained on s.qrdbAuditSink and
// closed during Shutdown.
func (s *Server) newQRDBAuditSink() (qrdbsdk.NodeAuditLogger, error) {
	return embeddednode.NewEmbeddedAuditSink(s.config, s.logger)
}

// initEmbeddedQRDBNode constructs the in-process qrdb standalone node that is
// xkms's single core engine: the one database plus the source of identity,
// bootstrap, and clustering. On success the node is retained on s.qrdbNode and
// its SDK client on s.qrdbClient; the server owns both lifecycles and tears
// them down in Shutdown via stopQRDBNode.
//
// The node's barrier is the single barrier (see buildXKMSQRDBConfig), sealed
// by the injected hardware or cloud strategy when there is one. The
// hardware auth-factor registry is initialized here and injected into the node
// via WithFactorRegistry so the node's unified AuthFactorService can verify
// hardware factor challenges during custodian enrollment and Shamir unseal
// ceremonies.
func (s *Server) initEmbeddedQRDBNode() error {
	qcfg := s.buildXKMSQRDBConfig()

	sink, err := s.newQRDBAuditSink()
	if err != nil {
		return &QRDBNodeError{Stage: "new qrdb audit sink", Err: err}
	}
	s.qrdbAuditSink = sink

	// Initialize the hardware auth-factor registry before assembling server
	// options so it can be injected into the qrdb node constructor below.
	if err := s.initializeFactorRegistry(); err != nil {
		return &QRDBNodeError{Stage: "initialize factor registry", Err: err}
	}

	// xkmsd's session tokens authenticate on the node's own chain (the
	// unified gRPC and MCP surfaces) as well as on xkms's REST routes. The
	// live authenticator holder exists before the node serves, so the
	// authenticator initializeAuthentication installs later (and every
	// reload) is the one that verifies.
	if s.liveAuthenticator == nil {
		s.liveAuthenticator = auth.NewLiveAuthenticator(nil)
	}
	nodeOpts := []qrdbnode.NodeOption{
		qrdbnode.WithLogger(s.logger),
		qrdbnode.WithAuthenticators(qrdbsdk.ChainAfterMTLS, auth.NewQRDBBearerAuthenticator(s.liveAuthenticator)),
	}

	// The audit sink and the hardware auth-factor registry are wired into the
	// node: the audit sink so Client().Audit() emits to the HMAC-chained
	// subsystem, and the factor registry so the node's AuthFactorService can
	// handle custodian enrollment, challenge, and verify operations for
	// PIV, PKCS#11, and FIDO2 factors.
	serverOpts := []qrdbserver.ServerOption{
		qrdbserver.WithAuditLogger(sink),
		qrdbserver.WithFactorRegistry(s.factorRegistry),
		// qrdb serves GET /v1/ca/bootstrap, first-contact trust, from xkmsd's
		// CA bundle; the xkms module leaves the route to it.
		qrdbserver.WithBootstrapCABundle(s.bootstrapCABundle),
	}

	// Unified API server: qrdb's transports are TLS-only and take their
	// material from the WithServerTLS option, not from the daemon config.
	// The rotating provider serves operator files or a persisted bootstrap
	// certificate immediately, then upgrades to the CA-issued certificate
	// once the CA composes (upgradeUnifiedTLSCert). Skipped for the
	// loopback desktop engine for the same reason as the protocol wiring
	// above: it never serves through this node's transports, so building
	// the unified TLS material (and persisting a bootstrap cert under
	// Datastore.Path) would be pure waste.
	if s.config.NodeServing() && !s.config.LoopbackDesktop {
		tlsCfg, err := s.buildUnifiedTLSConfig()
		if err != nil {
			return &QRDBNodeError{Stage: "build unified server TLS config", Err: err}
		}
		serverOpts = append(serverOpts, qrdbserver.WithServerTLS(tlsCfg))
		s.sealedWindowTLS = tlsCfg
	}

	// Phase 3 of the unified API server
	// (plans/unified-api-server-2026-08-14.md): register xkms's WHOLESALE
	// crypto gRPC surface as a qrdb ServiceModule. ADDITIVE — the legacy
	// transport stacks keep serving as today; this surface activates when the
	// node's server transports are enabled (the Phase 4 cutover), gated
	// per-RPC by qrdb's reflection interceptor over option
	// (qrdb.v1.permission).
	//
	// ORDERING: this runs near the top of server.New, long before the
	// XKMSService is composed (s.xkmsService is assigned after backends, CA,
	// and first-boot) — and when node transports are enabled, node
	// construction below invokes RegisterGRPC immediately. The module
	// therefore takes lazy resolvers and binds on the first RPC: until
	// s.xkmsService is set, every module RPC answers Unavailable. New publishes
	// it last, under s.mu, after the SSH client is composed, so the first
	// RPC binds a fully wired service and never creates the "ssh" database
	// on its own deadline (DS-4012).
	moduleOpts := []apimodule.Option{
		apimodule.WithSSHClient(func() sdkssh.Client { return s.ensureSSHClient() }),
		apimodule.WithRESTServer(func() *rest.Server { return s.ModuleRESTServer() }),
		apimodule.WithMCPServer(func() *mcp.Server { return s.ModuleMCPServer() }),
	}
	// Embedded web UI: registration is config-driven (assets are installed
	// after construction via SetUIAssets and late-bind through the REST
	// resolver).
	if s.config.UIEnabled() {
		if prefix, err := webui.NormalizePrefix(s.config.UI.PathPrefix); err == nil {
			moduleOpts = append(moduleOpts,
				apimodule.WithWebUI(prefix, s.config.UI.RedirectRoot))
		} else {
			s.logger.Error("web UI not registered on the unified server: invalid path prefix",
				"prefix", s.config.UI.PathPrefix, "error", err)
		}
	}
	xkmsModule, err := apimodule.NewModule(
		func() *xkms.XKMSService { return s.XKMSService() },
		moduleOpts...,
	)
	if err != nil {
		return &QRDBNodeError{Stage: "new xkms module", Err: err}
	}
	serverOpts = append(serverOpts, qrdbserver.WithModule(xkmsModule))

	// Additional ServiceModules supplied by the composing binary via
	// WithExtraModules (e.g. cmd/xkmsd's admin-surface module). Registered on
	// the same unified server as the xkms module, never on a second embedded
	// node.
	for _, mod := range s.extraModules {
		serverOpts = append(serverOpts, qrdbserver.WithModule(mod))
	}

	// The node's barrier is the one barrier: inject the resolved seal so the
	// node builds and auto-unseals it (encrypting the data-plane KV) and owns
	// the barrier registry and tenant service -- the same options
	// embeddednode.OpenEmbeddedNode injects for every other embedder.
	sealNodeOpts, sealServerOpts, err := embeddednode.NodeSealOptions(s.nodeSeal())
	if err != nil {
		return &QRDBNodeError{Stage: "node seal options", Err: err}
	}
	nodeOpts = append(nodeOpts, sealNodeOpts...)
	serverOpts = append(serverOpts, sealServerOpts...)

	// The attested-caller gate (attestation.peer_gate): qrdb enforces it on
	// every node transport after authorization.
	gateOpts, err := s.attestedCallerNodeOptions()
	if err != nil {
		return &QRDBNodeError{Stage: "attested-caller gate", Err: err}
	}
	nodeOpts = append(nodeOpts, gateOpts...)

	// The TrustedCA as the cluster CA (Key A), bound once initializeCA runs.
	nodeOpts = append(nodeOpts, s.clusterCAKeyProviderOptions()...)

	// newQRDBNode is build-tag specific: the default (!raft) build hosts a
	// standalone node; the -tags raft build hosts a clustered node when
	// Cluster.Enabled, falling back to standalone otherwise.
	node, err := s.newQRDBNode(qcfg, serverOpts, nodeOpts)
	if err != nil {
		return &QRDBNodeError{Stage: "new qrdb node", Err: err}
	}

	s.qrdbNode = node

	// Node-barrier flip: we gated construction on auto-unseal credentials
	// being available, so auto-unseal is normally unattended. It can still
	// fail (wrong boot passphrase, a rotated TPM PCR state) and leave the
	// node sealed. Rather than treat that as fatal, serve the node's own
	// pre-boot sealed-window listener — a qrdb-native, browser-drivable API
	// exposing only barrier status/initialize/unseal, ceremony, and
	// credential endpoints — and block here until an operator completes the
	// unseal (or the configured timeout / server shutdown ends the wait).
	// serveSealedWindow is a documented no-op when the node is not sealed,
	// so this runs unconditionally without a redundant IsSealed guard.
	//
	// What follows adopts the node's barrier + registry + tenant service as
	// xkms's own: there is no other barrier. serveSealedWindow only returns nil
	// once the barrier itself reports unsealed and the pending boot has
	// completed, so a still-sealed node here means that post-unseal
	// completion left the barrier state ambiguous — fail closed rather than
	// proceed with a nil client.
	if s.nodeSealEnabled {
		if err := s.serveSealedWindow(node); err != nil {
			return &QRDBNodeError{Stage: "sealed window", Err: err}
		}
		if node.IsSealed() {
			return &QRDBNodeError{Stage: "node barrier auto-unseal", Err: &embeddednode.NodeSealError{
				Reason: "barrier did not auto-unseal with the supplied credentials (check the TPM PCR state)"}}
		}
		if registry := node.BarrierRegistry(); registry != nil {
			s.barrierRegistry = registry
			s.barrier = registry.SystemBarrier()
		}
		if svcNode := node.Services(); svcNode != nil {
			s.tenantService = svcNode.Tenant
			s.tenantStores = svcNode.StoreResolver
		}
		s.logger.Info("adopted the qrdb node barrier (single barrier; data plane encrypted at rest)")
	}

	s.qrdbClient = node.Client()
	s.logger.Info("qrdb engine started in-process",
		"data_dir", qcfg.Raft.DataDir, "clustered", s.config.Cluster.Enabled)

	// A clustered node cannot serve writes until a leader is elected; gate
	// startup readiness on it. Standalone nodes skip this.
	if s.config.Cluster.Enabled {
		if err := s.waitForClusterLeader(); err != nil {
			return err
		}
	}

	// First-boot deliberately does NOT run here. The node and its unsealed
	// barrier are only half of what it needs: the administrator's certificate
	// is issued by the CA, and the CA is initialized later in New. Bootstrapping
	// from here produced an administrator with no bound certificate — an
	// identity nobody can authenticate as. New calls runFirstBoot once both are
	// ready.
	return nil
}

// waitForClusterLeader blocks until the cluster elects a leader for the
// configured shard, or a timeout elapses. It polls the qrdb cluster client and
// respects server shutdown via s.ctx.
func (s *Server) waitForClusterLeader() error {
	const (
		timeout  = 30 * time.Second
		interval = 250 * time.Millisecond
	)
	shardID := s.config.Cluster.ShardID
	if shardID == 0 {
		shardID = 1
	}
	// The leader query is xkms's own boot gating, so it runs as the node's
	// service principal; the authentication chain refuses a bare context.
	ctx, err := s.qrdbNode.ServiceContext(s.ctx)
	if err != nil {
		return &QRDBNodeError{Stage: "await cluster leader", Err: err}
	}
	deadline := time.Now().Add(timeout)
	for {
		if _, hasLeader, err := s.qrdbClient.Cluster().Leader(ctx, shardID); err == nil && hasLeader {
			s.logger.Info("cluster leader elected", "shard_id", shardID)
			return nil
		}
		if time.Now().After(deadline) {
			return &QRDBNodeError{
				Stage: "await cluster leader",
				Err:   &errs.Message{Msg: fmt.Sprintf("no leader elected for shard %d within %s", shardID, timeout)},
			}
		}
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(interval):
		}
	}
}

// stopQRDBNode closes the hosted qrdb node and clears the references. It is
// idempotent; a nil node is silently skipped.
func (s *Server) stopQRDBNode() error {
	node := s.qrdbNode
	if node == nil {
		return nil
	}
	sink := s.qrdbAuditSink
	s.qrdbNode = nil
	s.qrdbClient = nil
	s.qrdbAuditSink = nil
	if err := node.Close(); err != nil {
		return &QRDBNodeError{Stage: "close", Err: err}
	}
	// Close the audit sink after the node so no in-flight emit races the
	// underlying file handle / buffer. The interface always exposes Close.
	if sink != nil {
		if err := sink.Close(); err != nil {
			return &QRDBNodeError{Stage: "close audit sink", Err: err}
		}
	}
	// Release the single autodetect TPM open LAST, after the node (whose barrier
	// seal strategy used it) and the tpm2 backend (which shared the connection)
	// are both closed. externalTPM kept those from closing it early.
	if s.nodeSealClose != nil {
		closeFn := s.nodeSealClose
		s.nodeSealClose = nil
		if err := closeFn(); err != nil {
			s.logger.Warn("node barrier: failed to close the shared TPM open", "error", err)
		}
	}
	return nil
}

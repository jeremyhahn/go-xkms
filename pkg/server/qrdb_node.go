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
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/apimodule"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/webui"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// buildXKMSQRDBConfig translates the xkms configuration into the qrdb node
// configuration used to construct the in-process engine. xkms hosts qrdb as
// its single core: the node is the one database and the source of identity,
// bootstrap, and clustering.
//
// The node runs with its own seal subsystem DISABLED. xkms's barrier is the
// single barrier in the system — it is qrdb's StorageBarrier implementation
// (pkg/seal aliases it directly), layered over the node's KV by
// initializeBarrier with xkms's hardware seal strategies on top. Enabling the
// node's own seal as well would create a redundant second barrier, which is
// exactly the duplication this unification removes.
//
// Standalone hosting maps:
//   - Storage.Path  -> Raft.DataDir (Pebble root)
//   - embedded      -> Databases[0] = {default, mvcc, pebble|memory}
func (s *Server) buildXKMSQRDBConfig() *qrdbsdk.DaemonConfig {
	qcfg := &qrdbsdk.DaemonConfig{}

	// Authentication and authorization on the embedded node follow xkmsd's
	// own auth posture: the node's middleware guards every qrdb-native
	// plane (admin, users, credentials, barrier) and provides the upstream
	// identity for module routes. Stated EXPLICITLY even though the qrdb
	// zero value is now fail-safe (nil ⇒ enabled): the embedder's posture
	// should be legible here, not inherited silently. A SPIFFE trust
	// domain is pinned only when the operator configured one — the
	// first-boot default domain stays on the CN/OU identity path.
	qcfg.Auth.Enabled = qrdbsdk.BoolPtr(s.config.Auth.Enabled)
	if td := s.config.Cluster.RaftEnrollment.TrustDomain; td != "" {
		qcfg.Auth.SPIFFETrustDomain = td
	}

	// Data directory: the qrdb node reads Raft.DataDir for the Pebble root,
	// both for standalone and single-node clusters.
	qcfg.Raft.DataDir = s.config.Storage.Path

	// Inner storage engine for the embedded node. xkms's Storage.Backend value
	// ("qrdb") selects qrdb hosting; the node's own data-plane engine is Pebble
	// when a data directory is configured, otherwise in-memory.
	innerBackend := "pebble"
	if qcfg.Raft.DataDir == "" {
		innerBackend = "memory"
	}
	qcfg.Databases = []qrdbsdk.DaemonDatabaseConfig{
		{Name: "default", Engine: "mvcc", Backend: innerBackend},
	}

	// Barrier: when the flip is engaged (resolveNodeSeal set nodeSealEnabled —
	// Storage.Backend=="qrdb" + Barrier.Enabled + auto-unseal creds), the node's
	// OWN barrier encrypts the data-plane KV (encfs) and auto-unseals at
	// construction, so node.Client() is immediately available and every backend
	// key store is encrypted at rest. Otherwise Seal stays disabled and xkms's
	// own StorageBarrier (initializeBarrier) is the barrier — identical to the
	// prior behavior.
	if s.nodeSealEnabled {
		qcfg.Seal.Enabled = true
		if s.config.Barrier.SealStrategy() == "none" {
			qcfg.Seal.Strategy = "none"
		} else {
			// passphrase native, or hardware injected via WithSealStrategy (the
			// node consults the injected strategy only for a non-shamir/non-none
			// Strategy, so leave it at the passphrase default).
			qcfg.Seal.Strategy = "passphrase"
		}
		if s.config.Barrier.RootKeyPath != "" {
			qcfg.Seal.RootKeyPath = s.config.Barrier.RootKeyPath
		}
		// Provision a default volume pool so dedicated-isolation tenants draw
		// per-tenant Pebble storage from the node's own registry (replacing
		// xkms's buildVolumePool).
		if s.config.Storage.Path != "" && len(qcfg.Storage.VolumePools) == 0 {
			qcfg.Storage.VolumePools = []qrdbsdk.DaemonVolumePoolConfig{{
				Name:  "default",
				Paths: []string{filepath.Join(s.config.Storage.Path, "tenant-volumes")},
			}}
		}
	} else {
		qcfg.Seal.Enabled = false
	}

	// Unified API server: network serving runs exclusively on the node's
	// own multi-protocol server, which takes xkmsd's REST/gRPC/Unix/MCP
	// ports and serves the xkms capability plane through the registered
	// ServiceModule. QUIC is HTTP/3 on the REST port (the node's REST
	// server runs an HTTP/3 listener alongside TCP and advertises it via
	// Alt-Svc). Enabling protocols here means node construction runs the
	// full qrdb server start pipeline — module surfaces answer
	// Unavailable/503 until xkmsd finishes composing the XKMSService.
	if s.config.NetworkServing() {
		qcfg.Server.Host = s.config.Server.Host
		qcfg.Server.AdminPort = s.config.Server.RESTPort
		qcfg.Server.GRPCPort = s.config.Server.GRPCPort
		qcfg.Protocols.REST = s.config.Protocols.REST
		qcfg.Protocols.GRPC = s.config.Protocols.GRPC
		qcfg.Protocols.MCP = s.config.Protocols.MCP
		// The Unix socket is deliberately NOT mapped onto the node: qrdb's
		// transports are TLS-only, and the local IPC contract for xkmsd's
		// socket is plaintext gRPC guarded by filesystem permissions (the
		// pkcs11 module, the CLI, and the SDK unix transport all speak it).
		// xkmsd keeps serving its own socket (startUnix) in every mode.
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
		qcfg.Raft.Join = s.config.Cluster.Join
	}

	return qcfg
}

// defaultQRDBAuditRingCapacity is the in-memory audit ring size used when
// file audit is disabled. The node always receives a queryable logger so audit
// emission and querying function even without persistent file audit.
const defaultQRDBAuditRingCapacity = 1024

// newQRDBAuditSink builds the compliance-grade audit sink injected into the
// embedded qrdb node. When file audit is configured (Auth.Audit.Enabled with a
// Path) it returns the HMAC-chained file logger; otherwise it returns an
// in-memory ring buffer so Client().Audit() always emits and queries
// successfully. The returned sink is retained on s.qrdbAuditSink and closed
// during Shutdown.
func (s *Server) newQRDBAuditSink() (qrdbsdk.NodeAuditLogger, error) {
	if a := s.config.Auth.Audit; a != nil && a.Enabled && a.Path != "" {
		sink, err := qrdbsdk.NewAuditFileLogger(a.Path)
		if err != nil {
			return nil, err
		}
		s.logger.Info("qrdb node audit sink: HMAC-chained file logger", "path", a.Path)
		return sink, nil
	}
	s.logger.Info("qrdb node audit sink: in-memory ring buffer",
		"capacity", defaultQRDBAuditRingCapacity)
	return qrdbsdk.NewAuditRingBuffer(defaultQRDBAuditRingCapacity), nil
}

// initEmbeddedQRDBNode constructs the in-process qrdb standalone node that is
// xkms's single core engine: the one database plus the source of identity,
// bootstrap, and clustering. On success the node is retained on s.qrdbNode and
// its SDK client on s.qrdbClient; the server owns both lifecycles and tears
// them down in Shutdown via stopQRDBNode.
//
// The node's own seal is disabled (see buildXKMSQRDBConfig): xkms's barrier —
// qrdb's StorageBarrier implementation with xkms hardware seal strategies — is
// the single barrier, layered over this node's KV by initializeBarrier. The
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

	nodeOpts := []qrdbnode.NodeOption{
		qrdbnode.WithLogger(s.logger),
	}

	// The audit sink and the hardware auth-factor registry are wired into the
	// node: the audit sink so Client().Audit() emits to the HMAC-chained
	// subsystem, and the factor registry so the node's AuthFactorService can
	// handle custodian enrollment, challenge, and verify operations for
	// PIV, PKCS#11, and FIDO2 factors.
	serverOpts := []qrdbsdk.ServerOption{
		qrdbsdk.WithAuditLogger(sink),
		qrdbsdk.WithFactorRegistry(s.factorRegistry),
	}

	// Unified API server: qrdb's transports are TLS-only and take their
	// material from the WithServerTLS option, not from the daemon config.
	// The rotating provider serves operator files or a persisted bootstrap
	// certificate immediately, then upgrades to the CA-issued certificate
	// once the CA composes (upgradeUnifiedTLSCert).
	if s.config.NetworkServing() {
		tlsCfg, err := s.buildUnifiedTLSConfig()
		if err != nil {
			return &QRDBNodeError{Stage: "build unified server TLS config", Err: err}
		}
		serverOpts = append(serverOpts, qrdbsdk.WithServerTLS(tlsCfg))
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
	// s.xkmsService is set, every module RPC answers Unavailable. The SSH
	// resolver runs only after that binding, so ensureSSHClient's sync.Once
	// cannot latch nil. NOTE for the Phase 4 cutover: an RPC arriving during
	// server composition reads s.xkmsService without synchronization; the
	// cutover must publish it safely (or enable transports post-composition).
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
		func() *xkms.XKMSService { return s.xkmsServiceRef() },
		moduleOpts...,
	)
	if err != nil {
		return &QRDBNodeError{Stage: "new xkms module", Err: err}
	}
	serverOpts = append(serverOpts, qrdbsdk.WithModule(xkmsModule))

	// Node-barrier flip: feed the resolved seal material so the node builds and
	// auto-unseals its own barrier (encrypting the data-plane KV), and owns the
	// barrier registry + tenant service. Mirrors go-quicbaas's embedded-node
	// seal wiring so both products drive the identical shared mechanism.
	if s.nodeSealEnabled {
		if s.nodeSealStrategy != nil {
			nodeOpts = append(nodeOpts, qrdbnode.WithSealStrategy(s.nodeSealStrategy))
			// The per-tenant StrategyRegistry lets a tenant barrier be sealed
			// with the same hardware strategy the system barrier uses.
			if hwReg, regErr := seal.NewHardwareStrategyRegistry(s.nodeSealStrategy); regErr == nil {
				serverOpts = append(serverOpts, qrdbsdk.WithStrategyRegistry(hwReg))
			} else {
				s.logger.Warn("node barrier: could not build hardware strategy registry", "error", regErr)
			}
		}
		if len(s.nodeSealPassphrase) > 0 {
			nodeOpts = append(nodeOpts, qrdbnode.WithSealPassphrase(s.nodeSealPassphrase))
		}
		// Enable per-tenant isolation on the node so it builds the volume pool +
		// tenant service and restores dedicated-isolation tenants itself.
		nodeOpts = append(nodeOpts, qrdbnode.WithTenantIsolation())
	}

	// newQRDBNode is build-tag specific: the default (!raft) build hosts a
	// standalone node; the -tags raft build hosts a clustered node when
	// Cluster.Enabled, falling back to standalone otherwise.
	node, err := s.newQRDBNode(qcfg, serverOpts, nodeOpts)
	if err != nil {
		return &QRDBNodeError{Stage: "new qrdb node", Err: err}
	}

	s.qrdbNode = node

	// Node-barrier flip: adopt the node's barrier + registry + tenant service as
	// xkms's own, replacing the hand-rolled barrier subsystem (initializeBarrier
	// / initializeBarrierRegistry / buildVolumePool skip themselves when
	// nodeSealEnabled). We gated on auto-unseal credentials, so the node must be
	// unsealed here; if it is not, the supplied credentials did not unlock it
	// (wrong passphrase or a TPM PCR mismatch) — fail closed rather than proceed
	// with a nil client.
	if s.nodeSealEnabled {
		if node.IsSealed() {
			return &QRDBNodeError{Stage: "node barrier auto-unseal", Err: &NodeSealError{
				Reason: "barrier did not auto-unseal with the supplied credentials (check the passphrase or TPM PCR state)"}}
		}
		if inner := node.BarrierRegistry(); inner != nil {
			s.barrier = inner.SystemBarrier()
			s.barrierRegistry = seal.WrapBarrierRegistry(inner, s.barrier)
		}
		if svcNode := node.Services(); svcNode != nil {
			s.tenantService = svcNode.Tenant
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

	// Publish this node's client-facing API endpoints so peers can redirect a
	// client to it when it leads. Advertisement is not required to serve, so a
	// failure degrades the cluster to leader hints without an API address
	// rather than preventing startup.
	if err := s.startClusterAdvertiser(); err != nil {
		s.logger.Warn("cluster: failed to advertise this node's API endpoints; "+
			"clients will not be redirected to it when it leads", "error", err)
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
	deadline := time.Now().Add(timeout)
	for {
		if _, hasLeader, err := s.qrdbClient.Cluster().Leader(s.ctx, shardID); err == nil && hasLeader {
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
	// Deregister before the node closes so the registry entry goes away while
	// the KV that holds it is still writable; peers then stop redirecting
	// clients here immediately instead of waiting for the lease to expire.
	if err := s.stopClusterAdvertiser(); err != nil {
		s.logger.Warn("cluster: failed to withdraw this node's advertisement", "error", err)
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

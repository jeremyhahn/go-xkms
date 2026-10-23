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

// Package embeddednode is the single go-qrdb node builder of the stack.
//
// [NewNode] builds the node every go-xkms-derived daemon runs on, in both
// standalone and clustered topologies. go-xkms itself, and every downstream
// project that embeds go-qrdb through go-xkms, calls it rather than reaching
// for go-qrdb's node constructors directly, so the standalone/clustered
// decision, the membership parsing and the inter-node mTLS provisioning
// (Raft mTLS plus the cluster-enrollment advertiser) live in one place.
//
// Clustering is compiled in only with the `raft` build tag. Without it,
// [NewNode] serves standalone topologies and fails loudly on a clustered
// configuration rather than silently degrading to a single node.
//
// Inter-node mTLS for a multi-node cluster (TrustedCA-issued node
// certificates, TPM-attested ACME enrollment) is supplied by the caller
// through [NodeOptions.RaftMTLSResolver]. Those strategies need a certificate
// authority and key-strategy dependencies that belong to the daemon, not to
// node construction, so they are injected instead of imported. The resolver
// is required for a multi-node cluster ([ErrNilRaftMTLSResolver]); there is no
// built-in path that writes a cluster CA key to disk.
//
// [OpenEmbeddedNode] layers a deployment's configuration over [NewNode]:
// it resolves the node-barrier seal posture (config.BarrierConfig) and derives
// the storage+seal shape of the qrdb daemon config (config.DatastoreConfig).
// It is Server-independent by design (it depends only on pkg/config, pkg/seal
// and pkg/types -- never pkg/server or pkg/xkms) so both pkg/server (the
// xkmsd-hosted daemon) and pkg/datastore (the SDK/library composition path's
// single shared datastore) open byte-for-byte the same on-disk identity for
// one Datastore.Path. See docs/datastore/architecture.md.
package embeddednode

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// KeyDirSubdir is the fixed subdirectory, under the configured datastore
// path, where the TPM2 node-barrier seal strategy persists sealed key blobs.
// pkg/server's own TPM2 crypto-operation backend (backend_tpm2.go) shares
// this exact constant so both derive the identical directory.
const KeyDirSubdir = "tpm2-keys"

// DefaultEmbeddedAuditRingCapacity is the in-memory audit ring size used when
// file audit is disabled. A node always receives a queryable logger so audit
// emission and querying function even without persistent file audit.
const DefaultEmbeddedAuditRingCapacity = 1024

// ResolvedNodeSeal is the outcome of resolving a deployment's node-barrier
// seal posture: whether the qrdb node's own barrier -- the deployment's only
// barrier -- encrypts the data plane, and, for the hardware and cloud
// strategies, the pre-built SealingStrategy and the resources it holds.
type ResolvedNodeSeal struct {
	// Enabled reports whether the qrdb node's barrier seals the data plane.
	// False when the deployment is not datastore.mode=="standalone" (a remote
	// datastore's barrier lives on the remote node) or the barrier is
	// disabled.
	Enabled bool

	// Strategy is the pre-built SealingStrategy fed to the node via
	// qrdbnode.WithSealStrategy (see NodeSealOptions). Non-nil for tpm2,
	// pkcs11, awskms, gcpkms, azurekv and vault; "none", "passphrase" and
	// "shamir" are built natively by go-qrdb's own node seal subsystem from
	// DaemonConfig.Seal alone.
	Strategy seal.SealingStrategy

	// TPM is the single open TPM backend produced by the seal autodetect when
	// Strategy is tpm2. Nil otherwise: pkcs11 and vault need the TPM only to
	// release a pre-barrier secret and close it before ResolveNodeSeal
	// returns.
	TPM types.Sealer

	// Close releases what Strategy holds open: the TPM for tpm2, the PKCS#11
	// session for pkcs11, the KMS backend and its key metadata for the cloud
	// strategies. Nil for every other strategy.
	Close func() error
}

// resolveTPM2KeyDir returns the directory the TPM2 seal strategy persists its
// sealed key material under, derived from cfg.Datastore.Path so it never
// resolves relative to the process working directory.
func resolveTPM2KeyDir(cfg *config.Config) (string, error) {
	if cfg.Datastore.Path == "" {
		return "", &ErrDatastorePathRequired{Reason: "the TPM2 seal key directory"}
	}
	return filepath.Join(cfg.Datastore.Path, KeyDirSubdir), nil
}

// ResolveTPM2KeyDir is the exported form of resolveTPM2KeyDir: pkg/server's
// own TPM2 crypto-operation backend (backend_tpm2.go) derives its key
// directory through this SAME function so the node-barrier flip's TPM2
// strategy and that backend always agree on one directory.
func ResolveTPM2KeyDir(cfg *config.Config) (string, error) {
	return resolveTPM2KeyDir(cfg)
}

// nodeSealResolver resolves the node seal for one barrier strategy.
type nodeSealResolver func(cfg *config.Config, logger *slog.Logger) (ResolvedNodeSeal, error)

// nodeSealResolvers maps every non-cloud barrier strategy to its resolver.
// The cloud strategies (awskms, gcpkms, azurekv, vault) resolve through
// resolveCloudNodeSeal, whose providers are compiled in by build tag.
var nodeSealResolvers = map[string]nodeSealResolver{
	"tpm2":       resolveTPM2NodeSeal,
	"pkcs11":     resolvePKCS11NodeSealLogged,
	"none":       resolveInsecureNodeSeal,
	"passphrase": resolveOperatorNodeSeal,
	"shamir":     resolveOperatorNodeSeal,
}

// ResolveNodeSeal decides whether a deployment's qrdb node seals its data
// plane with its own barrier -- the deployment's only barrier -- and, for
// the hardware and cloud strategies, pre-builds the SealingStrategy the node
// is given through qrdbnode.WithSealStrategy (see NodeSealOptions). Secrets
// a strategy needs before the node exists (the PKCS#11 PIN, the Vault
// token) are released from the pre-barrier secret store (see OpenPreseal).
//
// xkmsd run and xkmsd init both call it against the SAME *config.Config so
// they resolve an IDENTICAL seal posture before either one opens the node.
// An unknown strategy, or a cloud strategy not compiled into the binary,
// fails closed.
func ResolveNodeSeal(cfg *config.Config, logger *slog.Logger) (ResolvedNodeSeal, error) {
	if !datastoreModeIsStandalone(cfg) || !cfg.Barrier.Enabled {
		return ResolvedNodeSeal{}, nil
	}
	strategy := cfg.Barrier.SealStrategy()
	if resolve, ok := nodeSealResolvers[strategy]; ok {
		return resolve(cfg, logger)
	}
	res, err := resolveCloudNodeSeal(context.Background(), cfg, strategy, logger)
	if err != nil {
		return ResolvedNodeSeal{}, err
	}
	logger.Info("node barrier: cloud-KMS-sealed data plane", "strategy", strategy)
	return res, nil
}

// resolveTPM2NodeSeal opens the node's TPM and its seal strategy.
func resolveTPM2NodeSeal(cfg *config.Config, logger *slog.Logger) (ResolvedNodeSeal, error) {
	res, err := openNodeTPM(cfg, logger)
	if err != nil {
		return ResolvedNodeSeal{}, err
	}
	logger.Info("node barrier: TPM-sealed data plane")
	return ResolvedNodeSeal{Enabled: true, Strategy: res.Strategy, TPM: res.Sealer, Close: res.Close}, nil
}

// resolvePKCS11NodeSealLogged resolves the PKCS#11 node seal and records it.
func resolvePKCS11NodeSealLogged(cfg *config.Config, logger *slog.Logger) (ResolvedNodeSeal, error) {
	res, err := resolvePKCS11NodeSeal(cfg, logger)
	if err != nil {
		return ResolvedNodeSeal{}, err
	}
	logger.Info("node barrier: PKCS#11-sealed data plane")
	return res, nil
}

// resolveInsecureNodeSeal enables the node barrier under strategy "none",
// which go-qrdb's node seal subsystem builds from DaemonConfig.Seal alone.
func resolveInsecureNodeSeal(_ *config.Config, logger *slog.Logger) (ResolvedNodeSeal, error) {
	logger.Warn("node barrier: strategy 'none' — data plane is NOT encrypted (development/insecure)")
	return ResolvedNodeSeal{Enabled: true}, nil
}

// resolveOperatorNodeSeal enables the node barrier under "passphrase" or
// "shamir", which go-qrdb's node seal subsystem builds from
// DaemonConfig.Seal (for shamir, Seal.ShamirThreshold/ShamirTotal -- see
// EmbeddedNodeStorageConfig) and an operator unseals.
func resolveOperatorNodeSeal(cfg *config.Config, logger *slog.Logger) (ResolvedNodeSeal, error) {
	logger.Info("node barrier: strategy requires operator-driven unseal", "strategy", cfg.Barrier.SealStrategy())
	return ResolvedNodeSeal{Enabled: true}, nil
}

// NodeSealOptions returns the node and server options that make the qrdb
// node's barrier the one barrier for a resolved node seal. Every enabled seal
// turns on per-tenant isolation with the operator default entitlements
// (tenantDefaultEntitlements), so the node builds the barrier registry and
// tenant service itself. A seal with a pre-built strategy also injects it via
// qrdbnode.WithSealStrategy, and a strategy registry holding it via
// qrdbsdk.WithStrategyRegistry so every tenant barrier can seal with the same
// hardware. The strategies go-qrdb builds from DaemonConfig.Seal (none,
// passphrase, shamir) inject no strategy; a disabled seal injects nothing.
func NodeSealOptions(res ResolvedNodeSeal) ([]qrdbnode.NodeOption, []qrdbsdk.ServerOption, error) {
	if !res.Enabled {
		return nil, nil, nil
	}
	nodeOpts := []qrdbnode.NodeOption{
		qrdbnode.WithTenantIsolation(),
		qrdbnode.WithDefaultTenantEntitlements(tenantDefaultEntitlements()),
	}
	if res.Strategy == nil {
		return nodeOpts, nil, nil
	}
	registry, err := seal.NewHardwareStrategyRegistry(res.Strategy)
	if err != nil {
		return nil, nil, &NodeSealError{Reason: "registering the " + string(res.Strategy.ID()) + " strategy", Err: err}
	}
	return append(nodeOpts, qrdbnode.WithSealStrategy(res.Strategy)),
		[]qrdbsdk.ServerOption{qrdbsdk.WithStrategyRegistry(registry)},
		nil
}

// tenantDefaultEntitlements returns the operator default entitlements for
// xkms's own tenants. xkms is the trust anchor that operates its tenants
// directly (there is no untrusted billing plane inside xkms itself), so every
// isolation mode and the system-managed auto-unseal key-management mode are
// permitted by default. Consumers that expose tenants to untrusted callers
// tighten these per plan via UpdateEntitlements.
func tenantDefaultEntitlements() *qrdbsdk.Entitlements {
	return &qrdbsdk.Entitlements{
		AllowedIsolationModes: []string{
			string(qrdbsdk.TenantIsolationPrefix),
			string(qrdbsdk.TenantIsolationBarrier),
			string(qrdbsdk.TenantIsolationVolume),
			string(qrdbsdk.TenantIsolationRaft),
		},
		AllowDedicatedRaft:        true,
		AllowVolumeStorage:        true,
		AllowSystemManagedBarrier: true,
		AllowDedicatedWAL:         true,
	}
}

// openNodeTPM opens the TPM backends.tpm2 configures, with its key store in
// the TPM2 key directory, through seal.OpenTPM2Strategy. It fails closed when
// backends.tpm2 is missing or the TPM cannot be used, keeping the
// *seal.TPM2ProbeError that says why in the chain. The caller closes the
// result.
func openNodeTPM(cfg *config.Config, logger *slog.Logger) (*seal.AutodetectResult, error) {
	keyDir, err := resolveTPM2KeyDir(cfg)
	if err != nil {
		return nil, &NodeSealError{Reason: "resolving TPM2 key directory", Err: err}
	}
	tpmCfg := cfg.Backends.TPM2
	if tpmCfg == nil {
		// barrier.strategy selects the node seal independently of
		// backends.tpm2 (the crypto-operation TPM2 backend, gated by its own
		// Enabled flag). An operator can reasonably set one without the
		// other, so a missing section fails closed with the same typed
		// error as "hardware not found".
		return nil, &NodeSealError{
			Reason: "strategy " + cfg.Barrier.SealStrategy() + " configured for the node seal but backends.tpm2 is not set",
		}
	}
	res, err := seal.OpenTPM2Strategy(seal.AutodetectOptions{
		TPM2: &seal.TPM2ProbeConfig{
			Device:               tpmCfg.DevicePath,
			KeyDir:               keyDir,
			UseSimulator:         tpmCfg.UseSimulator,
			SimulatorHost:        tpmCfg.SimulatorHost,
			SimulatorPort:        tpmCfg.SimulatorPort,
			SRKHandle:            tpmCfg.SRKHandle,
			PlatformPCRSelection: tpmCfg.PlatformPCRSelection,
		},
		ProbeTimeout: seal.RequiredTPMOpenTimeout,
		Logger:       logger,
	})
	if err != nil {
		return nil, &NodeSealError{
			Reason: "strategy " + cfg.Barrier.SealStrategy() + " configured but the TPM could not be used",
			Err:    err,
		}
	}
	return res, nil
}

// datastoreModeIsStandalone reports whether cfg hosts the qrdb datastore in
// this process (Datastore.Mode "standalone", the default).
func datastoreModeIsStandalone(cfg *config.Config) bool {
	mode := strings.ToLower(strings.TrimSpace(cfg.Datastore.Mode))
	return mode == "" || mode == "standalone"
}

// TrustDomain returns the SPIFFE trust domain the deployment issues and pins
// identities under: the configured Raft enrollment trust domain, or
// DefaultTrustDomain when none is configured.
func TrustDomain(cfg *config.Config) string {
	if td := cfg.Cluster.RaftEnrollment.TrustDomain; td != "" {
		return td
	}
	return DefaultTrustDomain
}

// EmbeddedNodeStorageConfig builds the storage+seal portion of the qrdb
// daemon config that determines a node's on-disk identity: Auth, Raft.DataDir,
// Databases, Seal.*, Storage.VolumePools.
//
// This is the shared, Server-independent form of the storage+seal half of
// (*Server).buildXKMSQRDBConfig. xkmsd run layers network-serving and cluster
// fields on top of this same base; xkmsd init uses it directly via
// OpenEmbeddedNode, as does pkg/datastore.Open for the SDK/library
// composition path. All three MUST start from this shared builder or the
// different opens of one Pebble directory could disagree about the database
// engine or the seal strategy.
func EmbeddedNodeStorageConfig(cfg *config.Config, sealRes ResolvedNodeSeal) *qrdbsdk.DaemonConfig {
	qcfg := &qrdbsdk.DaemonConfig{}

	qcfg.Auth.Enabled = qrdbsdk.BoolPtr(cfg.Auth.Enabled)
	// The CA stamps every client certificate's tenant into a SPIFFE SAN under
	// this trust domain, so qrdb's mTLS authenticator pins the same one and
	// rejects a SAN under a foreign trust domain.
	qcfg.Auth.SPIFFETrustDomain = TrustDomain(cfg)

	qcfg.Raft.DataDir = cfg.Datastore.Path

	// Engine selects the local qrdb database backend directly from the
	// global datastore configuration -- never hardcoded. An empty Engine (a
	// caller that skipped Validate) falls back to the same
	// pebble/memory-by-path heuristic Validate would otherwise enforce.
	engine := strings.ToLower(strings.TrimSpace(cfg.Datastore.Engine))
	if engine == "" {
		if qcfg.Raft.DataDir == "" {
			engine = "memory"
		} else {
			engine = "pebble"
		}
	}
	qcfg.Databases = []qrdbsdk.DaemonDatabaseConfig{
		{Name: "default", Backend: engine},
	}

	if sealRes.Enabled {
		qcfg.Seal.Enabled = true
		qcfg.Seal.Strategy = cfg.Barrier.SealStrategy()
		if qcfg.Seal.Strategy == "shamir" {
			qcfg.Seal.ShamirThreshold = cfg.Barrier.ShamirThreshold
			qcfg.Seal.ShamirTotal = cfg.Barrier.ShamirTotal
		}
		if cfg.Barrier.RootKeyPath != "" {
			qcfg.Seal.RootKeyPath = cfg.Barrier.RootKeyPath
		}
		if cfg.Datastore.Path != "" && len(qcfg.Storage.VolumePools) == 0 {
			qcfg.Storage.VolumePools = []qrdbsdk.DaemonVolumePoolConfig{{
				Name: "default",
				Path: filepath.Join(cfg.Datastore.Path, "tenant-volumes"),
			}}
		}
	} else {
		qcfg.Seal.Enabled = false
	}

	return qcfg
}

// NewEmbeddedAuditSink builds the compliance-grade audit sink an embedded
// qrdb node is constructed with. When file audit is configured
// (Auth.Audit.Enabled with a Path) it returns the HMAC-chained file logger;
// otherwise it returns an in-memory ring buffer so Client().Audit() always
// emits and queries successfully.
func NewEmbeddedAuditSink(cfg *config.Config, logger *slog.Logger) (qrdbsdk.NodeAuditLogger, error) {
	if a := cfg.Auth.Audit; a != nil && a.Enabled && a.Path != "" {
		sink, err := qrdbsdk.NewAuditFileLogger(a.Path)
		if err != nil {
			return nil, err
		}
		logger.Info("qrdb node audit sink: HMAC-chained file logger", "path", a.Path)
		return sink, nil
	}
	logger.Info("qrdb node audit sink: in-memory ring buffer",
		"capacity", DefaultEmbeddedAuditRingCapacity)
	return qrdbsdk.NewAuditRingBuffer(DefaultEmbeddedAuditRingCapacity), nil
}

// EmbeddedNodeOptions configures OpenEmbeddedNode.
type EmbeddedNodeOptions struct {
	// Config is the deployment configuration. Required.
	Config *config.Config

	// Logger receives node construction events. Required.
	Logger *slog.Logger

	// FactorRegistry, when set, is injected into the node via
	// WithFactorRegistry so its unified AuthFactorService can verify
	// hardware factor challenges during custodian enrollment and Shamir
	// unseal ceremonies. Left nil, the node is built with no factor
	// registry (no hardware auth-factor operations available) -- the right
	// default for a caller that only wants a KV store (the SDK/library
	// composition path); a caller running a real ceremony (xkmsd init)
	// builds one explicitly (e.g. via pkg/factor.NewDefaultRegistry) and
	// passes it here.
	FactorRegistry *qrdbsdk.AuthFactorRegistry

	// AuditSink overrides the node's audit sink. Optional; NewEmbeddedAuditSink
	// is used when nil.
	AuditSink qrdbsdk.NodeAuditLogger

	// ExtraServerOptions and ExtraNodeOptions are appended after the options
	// this function derives from the resolved seal posture (TLS, additional
	// ServiceModules, cluster tuning -- concerns specific to the caller, not
	// to the node's on-disk identity).
	ExtraServerOptions []qrdbsdk.ServerOption
	ExtraNodeOptions   []qrdbnode.NodeOption

	// Cluster describes the topology. The zero value builds a standalone
	// node, which is what xkmsd init and the SDK/library composition path
	// always use (a one-shot bootstrap ceremony, or an embedded library
	// caller, is never a cluster member).
	Cluster ClusterOptions

	// RaftMTLSResolver supplies inter-node mTLS material for a multi-node
	// cluster. Unused (and safe to leave nil) for a standalone node.
	RaftMTLSResolver RaftMTLSResolver
}

// OpenEmbeddedNode resolves this deployment's node-barrier seal posture,
// derives the qrdb daemon config and node/server options from it, and
// constructs the node via NewNode -- the single node-construction path
// for the stack. xkmsd run ((*Server).initEmbeddedQRDBNode),
// xkmsd init, and pkg/datastore.Open (the SDK/library composition path) all
// reach the node through this same sequence of ResolveNodeSeal +
// EmbeddedNodeStorageConfig + NewNode, so the different opens of one
// Pebble directory can never disagree about the database engine or the seal
// strategy.
//
// It returns the constructed node unsealed-or-not exactly as go-qrdb left it:
// "none" and a provisioned tpm2 auto-unseal at construction; "passphrase" and
// "shamir" leave the node sealed. Completing that unseal is the caller's
// responsibility.
func OpenEmbeddedNode(ctx context.Context, opts EmbeddedNodeOptions) (*qrdbnode.Node, ResolvedNodeSeal, error) {
	// Callers such as pkg/datastore.Open may skip config.Validate, so the
	// engine is checked here before it reaches go-qrdb.
	if _, err := config.NormalizeDatastoreEngine(opts.Config.Datastore.Engine); err != nil {
		return nil, ResolvedNodeSeal{}, err
	}
	sealRes, err := ResolveNodeSeal(opts.Config, opts.Logger)
	if err != nil {
		return nil, ResolvedNodeSeal{}, err
	}
	node, err := openEmbeddedNodeWithSeal(ctx, opts, sealRes)
	return node, sealRes, err
}

// openEmbeddedNodeWithSeal opens the node behind an already-resolved seal.
// The caller owns sealRes and releases it whether or not this succeeds.
func openEmbeddedNodeWithSeal(ctx context.Context, opts EmbeddedNodeOptions, sealRes ResolvedNodeSeal) (*qrdbnode.Node, error) {
	qcfg := EmbeddedNodeStorageConfig(opts.Config, sealRes)

	auditSink := opts.AuditSink
	if auditSink == nil {
		var err error
		auditSink, err = NewEmbeddedAuditSink(opts.Config, opts.Logger)
		if err != nil {
			return nil, err
		}
	}

	nodeOpts := append([]qrdbnode.NodeOption{qrdbnode.WithLogger(opts.Logger)}, opts.ExtraNodeOptions...)
	serverOpts := append([]qrdbsdk.ServerOption{
		qrdbsdk.WithAuditLogger(auditSink),
	}, opts.ExtraServerOptions...)
	if opts.FactorRegistry != nil {
		serverOpts = append(serverOpts, qrdbsdk.WithFactorRegistry(opts.FactorRegistry))
	}

	sealNodeOpts, sealServerOpts, err := NodeSealOptions(sealRes)
	if err != nil {
		return nil, err
	}
	nodeOpts = append(nodeOpts, sealNodeOpts...)
	serverOpts = append(serverOpts, sealServerOpts...)

	res, err := NewNode(ctx, &NodeOptions{
		QRDB:             qcfg,
		Cluster:          opts.Cluster,
		Logger:           opts.Logger,
		ServerOptions:    serverOpts,
		NodeOptions:      nodeOpts,
		RaftMTLSResolver: opts.RaftMTLSResolver,
	})
	if err != nil {
		return nil, err
	}
	return res.Node, nil
}

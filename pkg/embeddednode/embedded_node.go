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

// Package embeddednode builds a standalone embedded go-qrdb node the same
// way every go-xkms composition root does: resolving a deployment's
// node-barrier seal posture (config.BarrierConfig) and deriving the
// storage+seal shape of the qrdb daemon config from it (config.DatastoreConfig).
//
// It is Server-independent by design (it depends only on pkg/config,
// pkg/daemon, pkg/seal and pkg/types -- never pkg/server or pkg/xkms) so
// both pkg/server (the xkmsd-hosted daemon) and pkg/datastore (the SDK/
// library composition path's single shared datastore, used by pkg/xkms's
// AutoInitialize/register_* factories through a caller-supplied handle) can
// open byte-for-byte the same on-disk identity for one Datastore.Path: the
// same database engine, and the same barrier/seal/encryption-at-rest
// configuration. See docs/datastore/architecture.md.
package embeddednode

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/daemon"
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
// seal posture (see config.BarrierConfig.NodeFlipWired): whether the qrdb
// node's own barrier encrypts the data plane, and -- for tpm2, the one
// strategy that needs a prebuilt Go object -- the SealingStrategy and its
// hardware handle.
type ResolvedNodeSeal struct {
	// Enabled reports whether the qrdb node's own barrier is the single
	// barrier for this deployment (the flip). False means either the
	// deployment is not datastore.mode=="standalone", the barrier is
	// disabled, or the configured strategy is not one NodeFlipWired covers
	// -- in every case the caller's own (non-node) barrier is used instead.
	Enabled bool

	// Strategy is the pre-built hardware SealingStrategy fed to the node via
	// qrdbnode.WithSealStrategy. Non-nil only for tpm2; "none", "passphrase"
	// and "shamir" are built natively by go-qrdb's own node seal subsystem
	// from DaemonConfig.Seal alone.
	Strategy seal.SealingStrategy

	// TPM is the single open TPM backend produced by the seal autodetect when
	// Strategy is tpm2. Nil otherwise.
	TPM types.Sealer

	// Close releases the autodetect TPM open. Nil unless Strategy is tpm2.
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

// ResolveNodeSeal decides whether a deployment's qrdb node uses its OWN
// barrier to encrypt the data-plane KV (the flip), and -- for tpm2, the one
// strategy that needs it -- resolves and pre-builds the hardware
// SealingStrategy.
//
// This is the Server-independent form of (*Server).resolveNodeSeal (see
// pkg/server/node_seal.go for the full design rationale): xkmsd run and
// xkmsd init both call it against the SAME *config.Config so they resolve an
// IDENTICAL seal posture before either one opens the node.
func ResolveNodeSeal(cfg *config.Config, logger *slog.Logger) (ResolvedNodeSeal, error) {
	if !datastoreModeIsStandalone(cfg) || !cfg.Barrier.Enabled {
		return ResolvedNodeSeal{}, nil
	}

	strategy := cfg.Barrier.SealStrategy()

	if !cfg.Barrier.NodeFlipWired() {
		logger.Warn("node barrier: strategy not yet wired for the node barrier; using the caller's own barrier "+
			"(the qrdb node's own data plane will NOT be encrypted)",
			"strategy", strategy)
		return ResolvedNodeSeal{}, nil
	}

	if strategy == "tpm2" {
		tpmCfg := cfg.Backends.TPM2
		keyDir, err := resolveTPM2KeyDir(cfg)
		if err != nil {
			return ResolvedNodeSeal{}, &NodeSealError{Reason: "resolving TPM2 key directory", Err: err}
		}
		if tpmCfg == nil {
			// barrier.strategy selects tpm2 for the node-seal flip
			// independently of backends.tpm2 (the crypto-operation TPM2
			// backend, gated by its own Enabled flag). An operator can
			// reasonably set one without the other, so a missing section
			// here must fail closed with the same typed error as "hardware
			// not found" rather than dereferencing a nil *config.TPM2Config
			// below.
			return ResolvedNodeSeal{}, &NodeSealError{
				Reason: "strategy tpm2 configured for the node-seal flip but backends.tpm2 is not set",
			}
		}
		res := seal.BuildBestStrategy(seal.AutodetectOptions{
			TPM2: &seal.TPM2ProbeConfig{
				Device:          tpmCfg.DevicePath,
				KeyDir:          keyDir,
				UseSimulator:    tpmCfg.UseSimulator,
				SimulatorHost:   tpmCfg.SimulatorHost,
				SimulatorPort:   tpmCfg.SimulatorPort,
				SRKHandle:       tpmCfg.SRKHandle,
				PlatformPolicy:  tpmCfg.PlatformPolicy,
				PlatformPCR:     tpmCfg.PlatformPCR,
				PlatformPCRBank: tpmCfg.PlatformPCRBank,
			},
			Logger: logger,
		})
		if !res.HardwareAvailable() {
			return ResolvedNodeSeal{}, &NodeSealError{Reason: "strategy tpm2 configured but no usable, provisioned TPM was found"}
		}
		logger.Info("node barrier: TPM-sealed data plane")
		return ResolvedNodeSeal{Enabled: true, Strategy: res.Strategy, TPM: res.Sealer, Close: res.Close}, nil
	}

	// "none", "passphrase", "shamir": go-qrdb's own node seal subsystem builds
	// the strategy from DaemonConfig.Seal.Strategy (and, for shamir,
	// Seal.ShamirThreshold/ShamirTotal -- see EmbeddedNodeStorageConfig); this
	// package injects nothing here.
	switch strategy {
	case "none":
		logger.Warn("node barrier: strategy 'none' — data plane is NOT encrypted (development/insecure)")
	default:
		logger.Info("node barrier: strategy requires operator-driven unseal", "strategy", strategy)
	}
	return ResolvedNodeSeal{Enabled: true}, nil
}

// datastoreModeIsStandalone reports whether cfg hosts the qrdb datastore in
// this process (Datastore.Mode "standalone", the default).
func datastoreModeIsStandalone(cfg *config.Config) bool {
	mode := strings.ToLower(strings.TrimSpace(cfg.Datastore.Mode))
	return mode == "" || mode == "standalone"
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
	if td := cfg.Cluster.RaftEnrollment.TrustDomain; td != "" {
		qcfg.Auth.SPIFFETrustDomain = td
	}

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
		{Name: "default", Engine: "mvcc", Backend: engine},
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
				Name:  "default",
				Paths: []string{filepath.Join(cfg.Datastore.Path, "tenant-volumes")},
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
	Cluster daemon.ClusterOptions

	// RaftMTLSResolver supplies inter-node mTLS material for a multi-node
	// cluster. Unused (and safe to leave nil) for a standalone node.
	RaftMTLSResolver daemon.RaftMTLSResolver
}

// OpenEmbeddedNode resolves this deployment's node-barrier seal posture,
// derives the qrdb daemon config and node/server options from it, and
// constructs the node via daemon.NewNode -- the single node-construction path
// for the stack (pkg/daemon). xkmsd run ((*Server).initEmbeddedQRDBNode),
// xkmsd init, and pkg/datastore.Open (the SDK/library composition path) all
// reach the node through this same sequence of ResolveNodeSeal +
// EmbeddedNodeStorageConfig + daemon.NewNode, so the different opens of one
// Pebble directory can never disagree about the database engine or the seal
// strategy.
//
// It returns the constructed node unsealed-or-not exactly as go-qrdb left it:
// "none" and a provisioned tpm2 auto-unseal at construction; "passphrase" and
// "shamir" leave the node sealed. Completing that unseal is the caller's
// responsibility.
func OpenEmbeddedNode(ctx context.Context, opts EmbeddedNodeOptions) (*qrdbnode.Node, ResolvedNodeSeal, error) {
	sealRes, err := ResolveNodeSeal(opts.Config, opts.Logger)
	if err != nil {
		return nil, ResolvedNodeSeal{}, err
	}

	qcfg := EmbeddedNodeStorageConfig(opts.Config, sealRes)

	auditSink := opts.AuditSink
	if auditSink == nil {
		auditSink, err = NewEmbeddedAuditSink(opts.Config, opts.Logger)
		if err != nil {
			return nil, sealRes, err
		}
	}

	nodeOpts := append([]qrdbnode.NodeOption{qrdbnode.WithLogger(opts.Logger)}, opts.ExtraNodeOptions...)
	serverOpts := append([]qrdbsdk.ServerOption{
		qrdbsdk.WithAuditLogger(auditSink),
	}, opts.ExtraServerOptions...)
	if opts.FactorRegistry != nil {
		serverOpts = append(serverOpts, qrdbsdk.WithFactorRegistry(opts.FactorRegistry))
	}

	if sealRes.Enabled {
		if sealRes.Strategy != nil {
			nodeOpts = append(nodeOpts, qrdbnode.WithSealStrategy(sealRes.Strategy))
			if hwReg, regErr := seal.NewHardwareStrategyRegistry(sealRes.Strategy); regErr == nil {
				serverOpts = append(serverOpts, qrdbsdk.WithStrategyRegistry(hwReg))
			} else {
				opts.Logger.Warn("node barrier: could not build hardware strategy registry", "error", regErr)
			}
		}
		nodeOpts = append(nodeOpts, qrdbnode.WithTenantIsolation())
	}

	res, err := daemon.NewNode(ctx, &daemon.Options{
		QRDB:             qcfg,
		Cluster:          opts.Cluster,
		StoragePath:      opts.Config.Datastore.Path,
		Logger:           opts.Logger,
		ServerOptions:    serverOpts,
		NodeOptions:      nodeOpts,
		RaftMTLSResolver: opts.RaftMTLSResolver,
	})
	if err != nil {
		return nil, sealRes, err
	}
	return res.Node, sealRes, nil
}

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

package main

import (
	"context"
	"errors"
	"log/slog"

	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	xkmsserver "github.com/jeremyhahn/go-xkms/pkg/server"
)

// This file opens the SAME durable qrdb node `xkmsd run` will later reopen
// from the same data directory, so that admin login factors enrolled during
// `xkmsd init` are written to the store the running server authenticates
// against, not to a throwaway one. Node construction itself goes through
// pkg/embeddednode.OpenEmbeddedNode -- the single shared, Server-independent
// entry point xkmsd run's (*server.Server).initEmbeddedQRDBNode also builds
// on -- so the two opens of one Pebble directory can never disagree about
// the database engine or the barrier/seal/encryption-at-rest configuration.

// Node-open error types.
var (
	// ErrNodeConfigRequired is returned when neither a loaded config file nor
	// --data-dir supplies a datastore path for the durable node.
	ErrNodeConfigRequired = errors.New("init: a datastore path is required to open the durable node (set datastore.path in --config or pass --data-dir)")

	// ErrNodeOpenFailed is returned when the durable qrdb node cannot be
	// constructed.
	ErrNodeOpenFailed = errors.New("init: failed to open the durable qrdb node")

	// ErrNodeUnsealFailed is returned when the node's own barrier cannot be
	// initialized/unsealed with the supplied credentials.
	ErrNodeUnsealFailed = errors.New("init: failed to unseal the durable node barrier")

	// ErrNodeShamirUnsupported is returned when the resolved node-barrier seal
	// strategy is "shamir". Splitting and distributing the node barrier's own
	// Shamir quorum is a separate, multi-officer ceremony
	// (accumulated via go-qrdb's ceremony API, not a single credential) that
	// `xkmsd init` does not yet drive; running it here would either block
	// forever waiting on shares nothing supplies, or silently leave the node
	// sealed. Deployments that need a Shamir-protected node barrier must use
	// a strategy NodeFlipWired covers that init CAN complete unattended today
	// (none, passphrase, tpm2) until that ceremony is wired.
	ErrNodeShamirUnsupported = errors.New("init: --barrier-strategy shamir is not yet supported for the durable node barrier")

	// ErrNodeStillSealed is returned when the node remains sealed after the
	// unseal step that should have completed it -- a defensive check, since
	// proceeding with a nil client would panic deep inside the ceremony.
	ErrNodeStillSealed = errors.New("init: durable node barrier did not unseal")
)

// resolveInitNodeConfig derives the *config.Config the durable node is opened
// with. It starts from the operator's loaded config (nil when `--config`
// resolved to no file) and overlays the init-time flags that name what the
// loaded config cannot: datastore.mode defaults to "standalone" (init always
// opens the datastore this process would host), datastore.path falls back to
// the resolved data directory, and barrier.enabled / barrier.strategy fall back to
// --barrier-strategy so a bare `xkmsd init --barrier-strategy passphrase` run
// with no config file still resolves a seal posture. Values already present
// in a loaded config always win: the config file is the same one `xkmsd run`
// will load, so agreeing with it is what keeps the two opens of one Pebble
// directory in sync.
func resolveInitNodeConfig(cfg *config.Config, flags *initFlags, dataDir string) *config.Config {
	var nodeCfg config.Config
	if cfg != nil {
		nodeCfg = *cfg
	} else {
		nodeCfg = *config.Defaults()
	}

	if nodeCfg.Datastore.Mode == "" {
		nodeCfg.Datastore.Mode = "standalone"
	}
	if nodeCfg.Datastore.Path == "" {
		nodeCfg.Datastore.Path = dataDir
	}
	if !nodeCfg.Barrier.Enabled && flags.barrierStrategy != "" {
		nodeCfg.Barrier.Enabled = true
	}
	if nodeCfg.Barrier.Strategy == "" {
		nodeCfg.Barrier.Strategy = flags.barrierStrategy
	}
	if flags.barrierStrategy == "shamir" {
		if flags.shares > 0 {
			nodeCfg.Barrier.ShamirTotal = flags.shares
		}
		if flags.threshold > 0 {
			nodeCfg.Barrier.ShamirThreshold = flags.threshold
		}
	}

	return &nodeCfg
}

// openDurableInitNode opens the durable qrdb node this ceremony's admin
// factors (and, on the single-admin path, first-boot identity) are persisted
// into. It is a standalone node: `xkmsd init` is a one-shot, single-process
// bootstrap ceremony and is never a cluster member.
func openDurableInitNode(ctx context.Context, nodeCfg *config.Config, logger *slog.Logger) (*qrdbnode.Node, embeddednode.ResolvedNodeSeal, error) {
	if nodeCfg == nil || nodeCfg.Datastore.Path == "" {
		return nil, embeddednode.ResolvedNodeSeal{}, ErrNodeConfigRequired
	}
	// xkmsd init runs a real custodian-enrollment ceremony, so it always
	// builds and injects a factor registry explicitly -- OpenEmbeddedNode
	// itself no longer defaults one (that default pulled in pkg/factor,
	// which pkg/xkms's SDK/library composition path -- the other caller of
	// pkg/embeddednode, via pkg/datastore -- cannot depend on).
	registry, err := xkmsserver.NewNodeFactorRegistry()
	if err != nil {
		return nil, embeddednode.ResolvedNodeSeal{}, &WrappedError{Sentinel: ErrNodeOpenFailed, Err: err}
	}
	node, sealRes, err := embeddednode.OpenEmbeddedNode(ctx, embeddednode.EmbeddedNodeOptions{
		Config:         nodeCfg,
		Logger:         logger,
		FactorRegistry: registry,
	})
	if err != nil {
		return nil, embeddednode.ResolvedNodeSeal{}, &WrappedError{Sentinel: ErrNodeOpenFailed, Err: err}
	}
	return node, sealRes, nil
}

// unsealDurableInitNode completes the node's own barrier when the resolved
// seal posture leaves it sealed after construction.
//
// "none" and a provisioned tpm2 auto-unseal unattended at construction (see
// server.ResolveNodeSeal), so node.IsSealed() is already false for them here
// and this is a no-op. "passphrase" leaves the node sealed: `xkmsd init` IS
// the operator-present ceremony -- the operator supplied --so-pin to run it
// at all -- so it completes the unseal directly with that credential rather
// than opening a remote sealed-window listener for itself to call back into
// (which is what `xkmsd run` does, because at run time there may be no
// operator attached to the process).
//
// strategy is the resolved config.BarrierConfig.SealStrategy() value.
// "shamir" is refused with ErrNodeShamirUnsupported: splitting and
// distributing the node barrier's own Shamir quorum is a separate,
// multi-officer ceremony this function does not drive (see the sentinel's
// doc comment), and calling node.Unseal with a bare passphrase credential
// against a shamir-strategy barrier would not complete it.
func unsealDurableInitNode(ctx context.Context, node *qrdbnode.Node, sealRes embeddednode.ResolvedNodeSeal, strategy string, soPin []byte) error {
	if !sealRes.Enabled || !node.IsSealed() {
		return nil
	}
	if strategy == "shamir" {
		return ErrNodeShamirUnsupported
	}
	creds, err := seal.CredentialsFor(soPin)
	if err != nil {
		return &WrappedError{Sentinel: ErrNodeUnsealFailed, Err: err}
	}
	if err := node.Unseal(ctx, creds); err != nil {
		return &WrappedError{Sentinel: ErrNodeUnsealFailed, Err: err}
	}
	if node.IsSealed() {
		return ErrNodeStillSealed
	}
	return nil
}

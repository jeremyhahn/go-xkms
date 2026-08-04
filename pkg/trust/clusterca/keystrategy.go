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

package clusterca

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// KeyStrategyName identifies a cluster CA key custody strategy.
type KeyStrategyName string

const (
	// KeyStrategyBarrier stores the cluster CA signing key in the qrdb-routed
	// replicated datastore, encrypted at rest by each node's own barrier. Any
	// node loads it and can issue. The default.
	KeyStrategyBarrier KeyStrategyName = "barrier"

	// KeyStrategyHSM keeps the cluster CA signing key inside a shared PKCS#11
	// HSM that every node reaches under the same key label. Key material never
	// leaves the HSM; all nodes sign through it. FIPS-grade.
	KeyStrategyHSM KeyStrategyName = "hsm"

	// KeyStrategyTPMKEK wraps the replicated cluster CA key under a KEK derived
	// from a cluster seed that is distributed at attested join and sealed to
	// each node's local TPM. Hardware-rooted without a shared HSM.
	KeyStrategyTPMKEK KeyStrategyName = "tpm-kek"
)

// Cluster CA key strategy errors.
var (
	// ErrUnknownKeyStrategy is returned when the configured strategy name does
	// not match a known, implemented strategy.
	ErrUnknownKeyStrategy = errors.New("clusterca: unknown cluster CA key strategy")

	// ErrIssuanceNotLocal is returned by a strategy's RuntimeBackend when this
	// node cannot issue locally and must delegate (reserved for future
	// leader-only / sub-quorum threshold strategies).
	ErrIssuanceNotLocal = errors.New("clusterca: cluster CA issuance is not local to this node")

	// ErrStrategyMisconfigured is returned when a strategy's required
	// dependencies are absent (e.g. hsm without an HSM backend, barrier runtime
	// without replicated storage).
	ErrStrategyMisconfigured = errors.New("clusterca: cluster CA key strategy misconfigured")

	// ErrKeyStrategyNotImplemented is returned for a recognized strategy whose
	// implementation has not yet landed. It fails closed so a deployment never
	// silently runs a half-built custody model.
	ErrKeyStrategyNotImplemented = errors.New("clusterca: cluster CA key strategy not yet implemented")
)

// StrategyDeps carries the composition-root dependencies a strategy needs. The
// composition root (xkmsd, quicbaasd) supplies node-local material before the
// datastore exists and replicated material afterward; a strategy uses whichever
// its custody model requires.
type StrategyDeps struct {
	// NodeLocalDataDir is the node-local cluster identity directory
	// ({StoragePath}/cluster-ca). Bootstrap keys and the staged cert set live
	// under it.
	NodeLocalDataDir string

	// CAConfig is the CA identity hierarchy (root + cluster intermediate). A
	// strategy injects the resolved keystore password into its identities so the
	// keystore encrypts the signing keys.
	CAConfig *ca.MultiIdentityCAConfig

	// Protection selects how the node-local / replicated CA keystore is
	// protected at rest (passphrase / TPM-sealed / plaintext). For the barrier
	// strategy a shared passphrase lets every node decrypt the promoted key.
	Protection KeyProtection

	// ReplicatedKeyStorage is the qrdb-routed (replicated, barrier-encrypted)
	// key storage, available only after the datastore is up. nil pre-node.
	ReplicatedKeyStorage storage.Backend

	// ReplicatedCertStorage is the qrdb-routed certificate storage. nil pre-node.
	ReplicatedCertStorage storage.Backend

	// HSMBackend is the shared PKCS#11 HSM backend (KeyStrategyHSM only).
	HSMBackend xkms.Backend

	// TPMSealer is this node's local TPM sealer (KeyStrategyTPMKEK, and the
	// Protection Sealer for hardware keystore protection).
	TPMSealer types.Sealer

	// Credentials is the TPM credential-activation surface the tpm-kek strategy
	// uses to wrap the cluster seed to an enrolling node's EK (first node) and to
	// recover it (joining node). Nil for barrier/hsm.
	Credentials CredentialActivator

	// Bootstrapping is true on the node that pre-stages the cluster CA (the
	// first/bootstrapping node, which has no joiner directory URL). The tpm-kek
	// strategy generates the cluster seed only when true; joiners obtain it via
	// the post-enrollment secret fetch instead.
	Bootstrapping bool

	// Logger receives diagnostics.
	Logger *slog.Logger
}

func (d *StrategyDeps) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// ClusterCAKeyStrategy resolves the keystore backend that holds the cluster CA
// signing key, per the configured custody model. It is the single seam every
// product's composition root uses so cluster CA key custody — and thus which
// nodes can issue — works identically across the stack.
type ClusterCAKeyStrategy interface {
	// Name reports the strategy identifier.
	Name() KeyStrategyName

	// BootstrapBackends returns the PRE-NODE key-backend resolver the cluster
	// provisioner uses (CA keystore + node transport key) before the replicated
	// datastore exists — needed so the first node can pre-stage the CA and issue
	// its own transport certificate. The strategy retains any handles it needs
	// for runtime promotion. For a strategy whose key lives externally (hsm) the
	// resolved CA keystore is already the durable backend.
	BootstrapBackends(ctx context.Context, deps *StrategyDeps) (func(name string) (xkms.Backend, error), error)

	// RuntimeBackend returns THIS node's durable keystore for the cluster CA
	// identity once the datastore is available. On the first node it promotes
	// the bootstrap key into the durable (replicated) store as needed; on other
	// nodes it resolves the shared key. It returns ErrIssuanceNotLocal when this
	// node must delegate issuance.
	RuntimeBackend(ctx context.Context, deps *StrategyDeps) (xkms.Backend, error)
}

// NewKeyStrategy returns the cluster CA key strategy for the given name (empty
// selects the barrier default). It errors for an unknown or not-yet-implemented
// strategy so a misconfiguration fails closed rather than silently downgrading.
func NewKeyStrategy(name KeyStrategyName) (ClusterCAKeyStrategy, error) {
	switch name {
	case "", KeyStrategyBarrier:
		return &barrierStrategy{}, nil
	case KeyStrategyHSM:
		return &hsmStrategy{}, nil
	case KeyStrategyTPMKEK:
		return &tpmKEKStrategy{}, nil
	default:
		return nil, ErrUnknownKeyStrategy
	}
}

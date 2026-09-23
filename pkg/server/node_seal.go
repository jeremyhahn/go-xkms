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
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// NodeSealError is returned when the node barrier is configured to encrypt the
// data plane but the required auto-unseal material cannot be resolved.
type NodeSealError struct {
	// Reason describes the failure.
	Reason string
	// Err is the underlying error, when one exists. Nil for a NodeSealError
	// raised without an underlying cause.
	Err error
}

// Error implements the error interface.
func (e *NodeSealError) Error() string {
	return "server: node barrier seal: " + e.Reason
}

// Unwrap exposes Err so errors.Is/errors.As can reach it.
func (e *NodeSealError) Unwrap() error {
	return e.Err
}

// allowNodeLocalPlaintextKeys reports whether a node-local key provider (e.g.
// the pkcs8 backend) may persist unencrypted PKCS#8 DER. Under the seal model
// encryption-at-rest is provided by the STORAGE layer (the qrdb node barrier's
// encfs over the data-plane KV), not by a per-key password — so plaintext key
// material is acceptable exactly when either:
//
//   - the node's own barrier is engaged (nodeSealEnabled): the KV is sealed, so
//     the DER is encrypted at rest by the storage layer; or
//   - the operator has explicitly accepted an unencrypted data plane — no
//     barrier, or seal strategy "none". config.ComplianceGaps reports that, and
//     cmd/xkmsd refuses to start on it, so this case is reachable only from an
//     embedded or test caller of this package.
//
// When a barrier is configured but the node seal is NOT engaged (e.g. an
// interactive-unseal deployment, or a strategy not yet wired to the node
// barrier), it returns false: refusing plaintext key persistence protects the
// operator's encryption-at-rest intent rather than silently writing unsealed
// keys.
func (s *Server) allowNodeLocalPlaintextKeys() bool {
	if s.nodeSealEnabled {
		return true
	}
	if !s.config.Barrier.Enabled || s.config.Barrier.SealStrategy() == "none" {
		return true
	}
	return false
}

// resolveNodeSeal decides whether xkms uses the qrdb node's OWN barrier to
// encrypt the data-plane KV (the flip), and — for the one strategy that
// needs it, tpm2 — resolves and pre-builds the hardware SealingStrategy. It
// runs BEFORE the qrdb node is constructed so its result can be injected as
// a node option and so a single TPM open is shared with the tpm2 backend.
//
// The flip engages for every embedded qrdb-node deployment
// (Storage.Backend=="qrdb") with the barrier enabled AND a strategy
// BarrierConfig.NodeFlipWired reports true for: "none", "passphrase",
// "shamir" and "tpm2". go-qrdb's own node-embedded seal subsystem
// (sdk/go/node's buildNodeSealSubsystem, driven by DaemonConfig.Seal alone)
// natively builds "none" and the deferred "passphrase"/"shamir" strategies
// — xkms supplies no Go strategy object for those, only the strategy name
// and, for shamir, the M-of-N quorum, via buildXKMSQRDBConfig. Only tpm2
// needs a pre-built SealingStrategy injected via qrdbnode.WithSealStrategy,
// built here directly from Backends.TPM2 — never from s.keyProviders/any
// already-initialized backend, so the flip has no dependency on backend
// initialization (which now runs strictly after the node is unsealed; see
// Server.New).
//
// Whichever strategy engages the flip, unattended auto-unseal happens only
// for "none" and a provisioned tpm2; "passphrase"/"shamir" leave the node
// sealed at construction, and initEmbeddedQRDBNode's serveSealedWindow
// blocks Server.New — the same place go-qrdb's own qrdbd daemon blocks in
// cmd/qrdbd's awaitUnseal — until an operator completes
// `xkmsctl barrier unseal` (or `unseal-shares`) or the equivalent API call
// against the sealed-window listener, or the configured timeout/shutdown
// ends the wait.
//
// A strategy NodeFlipWired reports false for (pkcs11, awskms, gcpkms,
// azurekv, vault) keeps xkms's own (non-node) barrier instead: those
// backends' credentials are consumed by initializeBackends after this
// function returns and the credential service does not exist yet at this
// point (see Server.New's phase ordering) — the same structural cycle
// documented on NodeFlipWired. Non-qrdb-storage deployments are unaffected
// either way: the flip only ever applies to Storage.Backend=="qrdb".
func (s *Server) resolveNodeSeal() error {
	if !strings.EqualFold(s.config.Storage.Backend, "qrdb") || !s.config.Barrier.Enabled {
		return nil
	}

	strategy := s.config.Barrier.SealStrategy()

	if !s.config.Barrier.NodeFlipWired() {
		s.logger.Warn("node barrier: strategy not yet wired for the node barrier; using xkms barrier "+
			"(the qrdb node's own data plane will NOT be encrypted)",
			"strategy", strategy)
		return nil
	}

	if strategy == "tpm2" {
		tpmCfg := s.config.Backends.TPM2
		res := seal.BuildBestStrategy(seal.AutodetectOptions{
			TPM2: &seal.TPM2ProbeConfig{
				Device:          tpmCfg.DevicePath,
				KeyDir:          filepath.Join(s.config.Storage.Path, "tpm2-keys"),
				UseSimulator:    tpmCfg.UseSimulator,
				SimulatorHost:   tpmCfg.SimulatorHost,
				SimulatorPort:   tpmCfg.SimulatorPort,
				SRKHandle:       tpmCfg.SRKHandle,
				PlatformPolicy:  tpmCfg.PlatformPolicy,
				PlatformPCR:     tpmCfg.PlatformPCR,
				PlatformPCRBank: tpmCfg.PlatformPCRBank,
			},
			Logger: s.logger,
		})
		if !res.HardwareAvailable() {
			return &NodeSealError{Reason: "strategy tpm2 configured but no usable, provisioned TPM was found"}
		}
		s.nodeSealStrategy = res.Strategy
		s.nodeSealTPM = res.Sealer
		s.nodeSealClose = res.Close
		s.nodeSealEnabled = true
		s.logger.Info("node barrier: TPM-sealed data plane (single TPM open shared with the tpm2 backend)")
		return nil
	}

	// "none", "passphrase", "shamir": go-qrdb's own node seal subsystem
	// builds the strategy from DaemonConfig.Seal.Strategy (and, for shamir,
	// Seal.ShamirThreshold/ShamirTotal — see buildXKMSQRDBConfig); xkms
	// injects nothing here. Auto-unseal is unattended only for "none";
	// "passphrase"/"shamir" leave the node sealed until the operator-driven
	// ceremony below completes.
	s.nodeSealEnabled = true
	switch strategy {
	case "none":
		s.logger.Warn("node barrier: strategy 'none' — data plane is NOT encrypted (development/insecure)")
	default:
		s.logger.Info("node barrier: strategy requires operator-driven unseal via the sealed-window listener",
			"strategy", strategy)
	}
	return nil
}

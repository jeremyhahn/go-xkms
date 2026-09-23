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
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// NodeSealError is returned when the node barrier is configured to encrypt the
// data plane but the required auto-unseal material cannot be resolved.
type NodeSealError struct {
	// Reason describes the failure.
	Reason string
	// Err is the underlying error, when one exists (e.g. a
	// *types.SecretReferenceUnresolvedError from resolving Barrier.Passphrase).
	// Nil for a NodeSealError raised without an underlying cause.
	Err error
}

// Error implements the error interface.
func (e *NodeSealError) Error() string {
	return "server: node barrier seal: " + e.Reason
}

// Unwrap exposes Err so errors.Is/errors.As can reach it (e.g. to detect a
// *types.SecretReferenceUnresolvedError underneath).
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
// encrypt the data-plane KV (the flip), and resolves the auto-unseal material.
// It runs BEFORE the qrdb node is constructed so its result can be injected as
// node options and so a single TPM open is shared with the tpm2 backend.
//
// The flip engages ONLY for embedded qrdb-node deployments
// (Storage.Backend=="qrdb") with the barrier enabled AND auto-unseal
// credentials available (a usable TPM for a hardware strategy, or a boot
// passphrase for the passphrase strategy, or the explicit "none" strategy).
// In every other case it is a no-op — xkms keeps its own barrier, and interactive
// (operator-driven) unseal continues to work through the existing barrier API —
// so all non-qrdb and no-boot-credential deployments behave exactly as before.
func (s *Server) resolveNodeSeal() error {
	if !strings.EqualFold(s.config.Storage.Backend, "qrdb") || !s.config.Barrier.Enabled {
		return nil
	}

	strategy := s.config.Barrier.SealStrategy()

	if s.config.Barrier.IsHardwareSealStrategy() {
		// Only tpm2 is wired through the autodetect probe today; pkcs11/cloud
		// node-barrier sealing is a follow-up. Until then, an unresolved
		// hardware strategy keeps xkms's own barrier.
		if strategy != "tpm2" {
			s.logger.Warn("node barrier: hardware seal strategy not yet wired for the node barrier; using xkms barrier",
				"strategy", strategy)
			return nil
		}
		tpmCfg := s.config.Backends.TPM2
		keyDir, err := s.resolveTPM2KeyDir()
		if err != nil {
			return &NodeSealError{Reason: "resolving TPM2 key directory", Err: err}
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

	switch strategy {
	case "passphrase":
		passphrase, err := types.SecretValueBytes(&s.config.Barrier.Passphrase)
		if err != nil {
			return &NodeSealError{Reason: "resolving boot passphrase: " + err.Error(), Err: err}
		}
		if len(passphrase) == 0 {
			// No boot passphrase: keep xkms's own barrier so interactive
			// (operator API) unseal still works. Data-plane encryption of the
			// node KV requires an auto-unseal secret (TPM or boot passphrase).
			s.logger.Info("node barrier: passphrase strategy with no boot passphrase; using xkms barrier (interactive unseal)")
			return nil
		}
		s.nodeSealPassphrase = passphrase
		s.nodeSealEnabled = true
		s.logger.Info("node barrier: passphrase-sealed data plane (boot passphrase auto-unseal)")
	case "none":
		// Explicit unencrypted-but-present barrier — no credentials needed.
		s.nodeSealEnabled = true
		s.logger.Warn("node barrier: strategy 'none' — data plane is NOT encrypted (development/insecure)")
	case "shamir":
		// Shamir never auto-unseals (operator quorum required); keep xkms's
		// barrier and its quorum-unseal API.
		s.logger.Info("node barrier: shamir strategy requires operator quorum; using xkms barrier")
	}
	return nil
}

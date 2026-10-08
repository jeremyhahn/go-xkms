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

import "github.com/jeremyhahn/go-xkms/pkg/embeddednode"

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
// When a barrier is configured but the node seal is NOT engaged (a remote
// datastore, whose barrier this process does not hold), it returns false:
// refusing plaintext key persistence protects the operator's
// encryption-at-rest intent rather than silently writing unsealed keys.
func (s *Server) allowNodeLocalPlaintextKeys() bool {
	if s.nodeSealEnabled {
		return true
	}
	if !s.config.Barrier.Enabled || s.config.Barrier.SealStrategy() == "none" {
		return true
	}
	return false
}

// resolveNodeSeal resolves the seal of the qrdb node's barrier -- the one
// barrier, encrypting the data-plane KV -- through
// embeddednode.ResolveNodeSeal. It runs BEFORE the qrdb node is constructed so
// its result can be injected as node options (embeddednode.NodeSealOptions)
// and so a single TPM open is shared with the tpm2 backend.
//
// The node seal engages for every deployment that hosts the datastore in
// this process (Datastore.Mode=="standalone") with the barrier enabled.
// go-qrdb builds "none", "passphrase" and "shamir" from DaemonConfig.Seal
// alone; every hardware and cloud strategy (tpm2, pkcs11, awskms, gcpkms,
// azurekv, vault) is pre-built here from its own Backends.* section and the
// TPM-sealed pre-barrier store -- never from an already-initialized backend,
// so the node seal has no dependency on backend initialization (which runs
// strictly after the node is unsealed; see Server.New).
//
// "passphrase" and "shamir" leave the node sealed at construction, and
// initEmbeddedQRDBNode's serveSealedWindow blocks Server.New -- the same
// place go-qrdb's own qrdbd daemon blocks in cmd/qrdbd's awaitUnseal --
// until an operator completes `xkmsctl barrier unseal` (or `unseal-shares`)
// against the sealed-window listener, or the configured timeout/shutdown
// ends the wait. A remote datastore's barrier belongs to the remote qrdb
// server; this process builds none.
func (s *Server) resolveNodeSeal() error {
	res, err := embeddednode.ResolveNodeSeal(s.config, s.logger)
	if err != nil {
		return err
	}
	s.nodeSealEnabled = res.Enabled
	s.nodeSealStrategy = res.Strategy
	s.nodeSealTPM = res.TPM
	s.nodeSealClose = res.Close
	return nil
}

// nodeSeal returns the node seal resolveNodeSeal resolved.
func (s *Server) nodeSeal() embeddednode.ResolvedNodeSeal {
	return embeddednode.ResolvedNodeSeal{
		Enabled:  s.nodeSealEnabled,
		Strategy: s.nodeSealStrategy,
		TPM:      s.nodeSealTPM,
		Close:    s.nodeSealClose,
	}
}

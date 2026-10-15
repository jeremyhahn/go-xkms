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

// Package peergate is go-xkms's implementation of go-qrdb's attested-caller
// seam: the PeerAttestationVerifier a host passes to go-qrdb's
// PeerAttestationGate (node.WithPeerAttestationGate), together with the
// evidence cache it reads and the collector that fills it.
//
// go-qrdb owns the gate and nothing behind it: after a request is
// authenticated and RBAC has granted a gated permission, the gate asks
// VerifyPeer whether the peer on the connection is currently attested. This
// package answers from cached evidence, never by collecting on the request
// path, using the verification primitive in pkg/attestation/peer.
//
// The pieces:
//
//   - Collector issues a single-use nonce to an authenticated peer
//     (Challenge) and accepts the evidence the peer quoted over it (Submit).
//     The peer is identified by the SPKI thumbprint of the verified client
//     certificate on the connection, never by anything the request carries,
//     and the evidence is bound to that connection through the TLS exporter
//     (peer.EvidenceFromTLS). The collector stamps the receipt time.
//   - EvidenceStore holds the latest evidence per thumbprint. DAOStore
//     persists it through a qrdb DAO, so every node sharing the datastore
//     sees the same evidence.
//   - Verifier implements go-qrdb's PeerAttestationVerifier. It re-verifies
//     the cached evidence under the provisioned policy on every call, so a
//     baseline change, an expired attestation key certificate or stale
//     evidence takes effect at once, and optionally requires the connection's
//     certificate to be an IDevID naming the same TPM as the attestation key.
//   - QuoteEvidence is the quoting side: it binds a challenge to the
//     connection, quotes, and assembles the evidence a peer submits.
//
// Transport is the host's: Challenge and Submit take the *tls.ConnectionState
// the request arrived on and are mounted wherever the host serves them.
package peergate

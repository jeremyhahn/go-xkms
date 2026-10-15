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

package server

import (
	"slices"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// WithAttestedCallerPolicy supplies the attested-caller gate's policy: the
// quote policy (attestation key anchors and the PCR baseline), the gated
// permissions and the evidence age bound. attestation.peer_gate decides
// whether the gate is installed and in which mode, so the policy's own Mode
// is ignored. go-xkms ships no reference values; without this option a
// configured gate is a startup error (ErrAttestedCallerPolicyMissing).
func WithAttestedCallerPolicy(policy peergate.GatePolicy) Option {
	return func(s *Server) {
		policy.Permissions = slices.Clone(policy.Permissions)
		s.attestedCallerPolicy = &policy
	}
}

// attestedCallerNodeOptions builds the attested-caller gate when
// attestation.peer_gate is optional or required and returns the node option
// that installs it. Off, or no attestation section, installs nothing.
//
// The node is built before its datastore exists, so the gate's evidence
// store binds later (bindPeerEvidenceStorage); until then the gate refuses
// every gated request.
func (s *Server) attestedCallerNodeOptions() ([]qrdbnode.NodeOption, error) {
	mode, err := s.config.Attestation.PeerGateMode()
	if err != nil {
		return nil, err
	}
	if mode == peergate.ModeOff {
		return nil, nil
	}
	if s.attestedCallerPolicy == nil {
		return nil, ErrAttestedCallerPolicyMissing
	}
	policy := *s.attestedCallerPolicy
	policy.Mode = mode
	gate, err := peergate.NewGate(peergate.GateConfig{Policy: policy, DAOs: s.peerEvidenceStorage})
	if err != nil {
		return nil, err
	}
	s.peerGate = gate
	s.logger.Info("attested-caller gate installed",
		"mode", mode, "gated_permissions", len(policy.Permissions), "max_evidence_age", policy.MaxEvidenceAge)
	return []qrdbnode.NodeOption{qrdbnode.WithPeerAttestationGate(gate.PeerAttestationGate())}, nil
}

// peerEvidenceStorage is the gate's DAO resolver: ErrNoDatastore until
// bindPeerEvidenceStorage publishes the storage.
func (s *Server) peerEvidenceStorage() (*qrdbsdk.DAOFactory, error) {
	if daos := s.peerEvidenceDAOs.Load(); daos != nil {
		return daos, nil
	}
	return nil, ErrNoDatastore
}

// bindPeerEvidenceStorage opens the peergate database on the datastore and
// publishes it to the gate. Without a gate it does nothing.
func (s *Server) bindPeerEvidenceStorage() error {
	if s.peerGate == nil {
		return nil
	}
	daos, err := s.daoFactory(peergate.DatabaseName)
	if err != nil {
		return &ErrStorageCreate{Resource: "attested-caller evidence storage", Err: err}
	}
	s.peerEvidenceDAOs.Store(daos)
	return nil
}

// wirePeerEvidenceCollector hands the gate's evidence collector to svc so the
// peer attestation verbs can issue challenges and store the evidence the gate
// reads. Without a gate the verbs stay unconfigured.
func (s *Server) wirePeerEvidenceCollector(svc *xkms.XKMSService) {
	if s.peerGate == nil {
		return
	}
	svc.SetPeerEvidenceCollector(s.peerGate.Collector())
}

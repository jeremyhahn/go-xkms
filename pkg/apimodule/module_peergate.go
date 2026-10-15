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

package apimodule

import (
	"context"
	"slices"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
)

// attestedCallerStorage names the surface the gate's evidence storage
// reports as composing until the host's qrdb client resolves.
const attestedCallerStorage = "attested-caller evidence storage"

// AttestedCallerClientError is returned by NewModule when WithAttestedCallerGate
// is configured without WithQRDBClient: the gate's evidence lives in the
// host's datastore, so without a client every gated call would be refused.
type AttestedCallerClientError struct{}

// Error implements the error interface.
func (e *AttestedCallerClientError) Error() string {
	return "apimodule: WithAttestedCallerGate requires WithQRDBClient for its evidence storage"
}

// WithAttestedCallerGate builds go-xkms's attested-caller gate
// (pkg/attestation/peergate) from the embedder's policy. The module serves
// its Challenge/Submit verbs through the gate's collector and keeps the
// evidence in the host's datastore (requires WithQRDBClient). The host
// installs the gate on its node with go-qrdb's node.WithPeerAttestationGate,
// passing Module.PeerAttestationGate.
//
// The policy's PCR values are the embedder's; go-xkms ships none.
func WithAttestedCallerGate(policy peergate.GatePolicy) Option {
	return func(m *Module) {
		policy.Permissions = slices.Clone(policy.Permissions)
		m.attestedCallerPolicy = &policy
	}
}

// PeerAttestationGate returns the go-qrdb gate WithAttestedCallerGate built,
// for the host's node.WithPeerAttestationGate, or nil without that option.
func (m *Module) PeerAttestationGate() *qrdbsdk.PeerAttestationGate {
	if m.peerGate == nil {
		return nil
	}
	return m.peerGate.PeerAttestationGate()
}

// buildAttestedCallerGate builds the gate WithAttestedCallerGate configured.
// It is a no-op without that option.
func (m *Module) buildAttestedCallerGate() error {
	if m.attestedCallerPolicy == nil {
		return nil
	}
	if m.resolveQRDBClient == nil {
		return &AttestedCallerClientError{}
	}
	gate, err := peergate.NewGate(peergate.GateConfig{Policy: *m.attestedCallerPolicy, DAOs: m.peerEvidenceStorage})
	if err != nil {
		return err
	}
	m.peerGate = gate
	return nil
}

// peerEvidenceStorage resolves the gate's evidence storage on the host's
// datastore. Until the host's client resolves it reports the storage as
// composing, and the gate refuses.
func (m *Module) peerEvidenceStorage() (*qrdbsdk.DAOFactory, error) {
	client := m.resolveQRDBClient()
	if client == nil {
		return nil, &SurfaceComposingError{Surface: attestedCallerStorage}
	}
	ds, err := m.openDatastore(client)
	if err != nil {
		return nil, err
	}
	if _, err := ds.DatabaseKVStore(context.Background(), peergate.DatabaseName); err != nil {
		return nil, err
	}
	return ds.DAOFactory(), nil
}

// wirePeerEvidenceCollector hands the gate's collector to the resolved
// service, once, so the Challenge/Submit verbs reach it on every transport.
// Until the service resolves the verbs answer as unconfigured.
func (m *Module) wirePeerEvidenceCollector() {
	if m.peerGate == nil || m.peerGateWired.Load() {
		return
	}
	if x := m.resolve(); x != nil {
		x.SetPeerEvidenceCollector(m.peerGate.Collector())
		m.peerGateWired.Store(true)
	}
}

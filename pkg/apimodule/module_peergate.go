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
	"crypto/x509"
	"slices"
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/compose"
)

// attestedCallerStorage names the surface the gate's evidence storage
// reports as composing until the host's qrdb client resolves.
const attestedCallerStorage = "attested-caller evidence storage"

// attestedCallerTrustRootsSurface names the persisted trust-root store a gate
// policy without anchors reads its IDevID-issuer roots from.
const attestedCallerTrustRootsSurface = "attested-caller trust roots"

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
// The policy's PCR values are the embedder's; go-xkms ships none. Anchor
// pools the policy leaves nil (Quote.Anchors, DeviceIdentity.Anchors) are
// the IDevID-issuer roots in the host node's persisted trust-root store,
// opened on the first verification and read on every one.
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
	cfg := peergate.GateConfig{Policy: *m.attestedCallerPolicy, DAOs: m.peerEvidenceStorage}
	if attestedCallerNeedsAnchors(cfg.Policy) {
		cfg.Anchors = m.attestedCallerAnchorSource()
	}
	gate, err := peergate.NewGate(cfg)
	if err != nil {
		return err
	}
	m.peerGate = gate
	return nil
}

// attestedCallerNeedsAnchors reports whether policy leaves an anchor pool
// for the persisted trust-root store to fill.
func attestedCallerNeedsAnchors(policy peergate.GatePolicy) bool {
	return policy.Quote.Anchors == nil ||
		(policy.DeviceIdentity != nil && policy.DeviceIdentity.Anchors == nil)
}

// attestedCallerTrustRoots opens the host node's persisted trust-root store
// (compose.BuildTrustRootStore over truststore.DatabaseName), the store the
// trust_roots verbs serve.
func (m *Module) attestedCallerTrustRoots() (truststore.PurposeLister, error) {
	client := m.resolveQRDBClient()
	if client == nil {
		return nil, &SurfaceComposingError{Surface: attestedCallerTrustRootsSurface}
	}
	ds, err := m.openDatastore(client)
	if err != nil {
		return nil, err
	}
	if _, err := ds.DatabaseKVStore(context.Background(), truststore.DatabaseName); err != nil {
		return nil, err
	}
	return compose.BuildTrustRootStore(ds.DAOFactory())
}

// attestedCallerAnchors is the gate's anchor source over roots: the
// PurposeIDevIDIssuer roots, read on each verification, so a root
// quarantined, removed or imported takes effect on the next peer. An empty
// purpose yields an empty pool, which trusts no peer.
// attestedCallerAnchorSource is the gate's anchor source over the host
// node's trust-root store, opened on the first verification rather than at
// NewModule: the module is built before the host node exists
// (docs/attested-peer/api.md). Until the client resolves it answers
// SurfaceComposingError, which leaves the gate undecided.
func (m *Module) attestedCallerAnchorSource() peergate.AnchorSource {
	var mu sync.Mutex
	var roots truststore.PurposeLister
	return func(ctx context.Context) (*x509.CertPool, error) {
		mu.Lock()
		if roots == nil {
			opened, err := m.attestedCallerTrustRoots()
			if err != nil {
				mu.Unlock()
				return nil, err
			}
			roots = opened
		}
		current := roots
		mu.Unlock()
		return attestedCallerAnchors(current)(ctx)
	}
}

func attestedCallerAnchors(roots truststore.PurposeLister) peergate.AnchorSource {
	return func(context.Context) (*x509.CertPool, error) {
		certs, err := roots.CertificatesByPurpose(truststore.PurposeIDevIDIssuer)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		for _, cert := range certs {
			pool.AddCert(cert)
		}
		return pool, nil
	}
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

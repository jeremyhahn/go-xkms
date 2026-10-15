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

package peergate

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Mode is the attested-caller gate's posture, the value of the
// attestation.peer_gate configuration key.
type Mode string

const (
	// ModeOff installs no gate. It is the default.
	ModeOff Mode = "off"

	// ModeOptional verifies a peer's evidence when it has submitted some and
	// admits a peer that never has. Evidence that fails is refused.
	ModeOptional Mode = "optional"

	// ModeRequired refuses a gated request unless the peer's evidence is on
	// record, fresh and passing.
	ModeRequired Mode = "required"
)

// ParseMode reads a configured mode. Surrounding space and case are ignored,
// and an empty value is ModeOff. Anything else is a *ModeError.
func ParseMode(value string) (Mode, error) {
	switch mode := Mode(strings.ToLower(strings.TrimSpace(value))); mode {
	case "", ModeOff:
		return ModeOff, nil
	case ModeOptional, ModeRequired:
		return mode, nil
	default:
		return "", &ModeError{Value: value}
	}
}

// ExemptPermissions are the permissions a gate must never gate: asking for
// a challenge and submitting evidence. A gated peer reaches them unattested,
// since they are how it becomes attested; gating either would leave every
// peer refused for good.
func ExemptPermissions() []qrdbsdk.Permission {
	return []qrdbsdk.Permission{
		qrdbsdk.Permission(auth.ResourcePeerAttestation + ":" + auth.ActionChallenge),
		qrdbsdk.Permission(auth.ResourcePeerAttestation + ":" + auth.ActionSubmit),
	}
}

// GatePolicy is what an embedder decides about the gate. go-xkms ships no
// reference values: the quote policy's PCR baseline comes from the embedder.
type GatePolicy struct {
	// Mode is ModeOptional or ModeRequired. The zero value is ModeRequired,
	// so a policy that forgets to say fails closed. ModeOff is rejected: an
	// embedder that wants no gate builds none.
	Mode Mode

	// Quote is the quote policy each peer's evidence is verified under. See
	// VerifierConfig.Policy.
	Quote peer.Policy

	// DeviceIdentity optionally binds the connection certificate to the
	// quoting TPM. See VerifierConfig.DeviceIdentity.
	DeviceIdentity *peer.DevIDPolicy

	// Permissions are the gated operations. Required, and it must not name
	// an ExemptPermissions entry.
	Permissions []qrdbsdk.Permission

	// MaxEvidenceAge is the oldest evidence the gate accepts. Required and
	// positive.
	MaxEvidenceAge time.Duration
}

// DAOResolver returns the DAO factory holding DatabaseName, with that
// database ensured. It is called on first use, never at construction, so a
// gate can be built before the node whose datastore holds its evidence; until
// it succeeds, every evidence read and write fails, and the gate refuses.
type DAOResolver func() (*qrdbsdk.DAOFactory, error)

// GateConfig assembles a Gate.
type GateConfig struct {
	// Policy is the embedder's gate policy.
	Policy GatePolicy

	// DAOs resolves the evidence store's storage. Required.
	DAOs DAOResolver

	// Store sizes the evidence store. Its DAOs field is ignored: the store
	// binds to what DAOs resolves.
	Store DAOStoreConfig

	// Challenges sizes the collector. Its Store field is ignored: the
	// collector writes to the gate's evidence store.
	Challenges CollectorConfig
}

// Gate is the attested-caller gate, assembled: one evidence store, the
// Collector that fills it and the Verifier that reads it, behind the
// go-qrdb gate a node installs with node.WithPeerAttestationGate.
type Gate struct {
	mode      Mode
	verifier  *Verifier
	collector *Collector
	gate      *qrdbsdk.PeerAttestationGate
}

// NewGate builds the gate cfg describes. It returns *ConfigError for a
// policy that does not describe a gate, including one that gates an exempt
// permission.
func NewGate(cfg GateConfig, opts ...Option) (*Gate, error) {
	mode := cfg.Policy.Mode
	if mode == "" {
		mode = ModeRequired
	}
	if mode != ModeOptional && mode != ModeRequired {
		return nil, &ConfigError{Field: "Policy.Mode", Reason: "must be optional or required; build no gate for off"}
	}
	if cfg.DAOs == nil {
		return nil, &ConfigError{Field: "DAOs", Reason: "is required"}
	}
	for _, exempt := range ExemptPermissions() {
		if slices.Contains(cfg.Policy.Permissions, exempt) {
			return nil, &ConfigError{Field: "Policy.Permissions", Reason: "must not gate " + string(exempt) + ", which an unattested peer needs in order to attest"}
		}
	}

	store := &lazyStore{resolve: cfg.DAOs, config: cfg.Store, opts: opts}
	verifier, err := NewVerifier(VerifierConfig{
		Store:           store,
		Policy:          cfg.Policy.Quote,
		DeviceIdentity:  cfg.Policy.DeviceIdentity,
		AdmitUnattested: mode == ModeOptional,
	}, opts...)
	if err != nil {
		return nil, err
	}
	challenges := cfg.Challenges
	challenges.Store = store
	collector, err := NewCollector(challenges, opts...)
	if err != nil {
		return nil, err
	}
	gate, err := qrdbsdk.NewPeerAttestationGate(verifier, qrdbsdk.PeerAttestationPolicy{
		Permissions:    slices.Clone(cfg.Policy.Permissions),
		MaxEvidenceAge: cfg.Policy.MaxEvidenceAge,
	})
	if err != nil {
		return nil, &ConfigError{Field: "Policy", Reason: "does not describe a gate", Cause: err}
	}
	return &Gate{mode: mode, verifier: verifier, collector: collector, gate: gate}, nil
}

// Mode is the gate's posture: ModeOptional or ModeRequired.
func (g *Gate) Mode() Mode { return g.mode }

// PeerAttestationGate is the go-qrdb gate to install with
// node.WithPeerAttestationGate.
func (g *Gate) PeerAttestationGate() *qrdbsdk.PeerAttestationGate { return g.gate }

// Verifier renders the verdicts the gate enforces, so an embedder can report
// a peer's standing without making a gated request.
func (g *Gate) Verifier() *Verifier { return g.verifier }

// Collector issues the challenges and takes the evidence the gate verifies.
func (g *Gate) Collector() *Collector { return g.collector }

// lazyStore is a DAOStore bound on first use, so the gate can exist before
// its datastore does. Until the resolver succeeds every call fails, which the
// Verifier and the Collector report as a *StoreError: the gate fails closed.
type lazyStore struct {
	resolve DAOResolver
	config  DAOStoreConfig
	opts    []Option
	bound   atomic.Pointer[DAOStore]
}

var _ EvidenceStore = (*lazyStore)(nil)

func (l *lazyStore) store() (*DAOStore, error) {
	if s := l.bound.Load(); s != nil {
		return s, nil
	}
	daos, err := l.resolve()
	if err != nil {
		return nil, err
	}
	config := l.config
	config.DAOs = daos
	s, err := NewDAOStore(config, l.opts...)
	if err != nil {
		return nil, err
	}
	// Two first calls may race; both stores share the datastore and stay
	// coherent, but keeping one makes every later call take the same path.
	if !l.bound.CompareAndSwap(nil, s) {
		return l.bound.Load(), nil
	}
	return s, nil
}

func (l *lazyStore) Put(ctx context.Context, r Record) error {
	s, err := l.store()
	if err != nil {
		return err
	}
	return s.Put(ctx, r)
}

func (l *lazyStore) Get(ctx context.Context, thumbprint string) (Record, bool, error) {
	s, err := l.store()
	if err != nil {
		return Record{}, false, err
	}
	return s.Get(ctx, thumbprint)
}

func (l *lazyStore) Delete(ctx context.Context, thumbprint string) error {
	s, err := l.store()
	if err != nil {
		return err
	}
	return s.Delete(ctx, thumbprint)
}

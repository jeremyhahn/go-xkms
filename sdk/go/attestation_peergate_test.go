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

package xkms

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// The SDK's verifier is the value a host hands go-qrdb's gate.
var _ qrdbsdk.PeerAttestationVerifier = (*PeerGateVerifier)(nil)

// TestPeerGateSurface composes the gate's pieces through the SDK names alone,
// the way a host does, and checks the fail-closed edges a host relies on.
func TestPeerGateSurface(t *testing.T) {
	ctx := context.Background()
	store, err := NewPeerMemoryEvidenceStore(PeerMemoryEvidenceStoreConfig{})
	if err != nil {
		t.Fatalf("NewPeerMemoryEvidenceStore: %v", err)
	}
	collector, err := NewPeerEvidenceCollector(PeerEvidenceCollectorConfig{Store: store}, WithPeerGateClock(time.Now))
	if err != nil {
		t.Fatalf("NewPeerEvidenceCollector: %v", err)
	}
	verifier, err := NewPeerGateVerifier(PeerGateVerifierConfig{
		Store:  store,
		Policy: PeerPolicy{Anchors: x509.NewCertPool(), Baseline: map[int][]byte{0: make([]byte, 32)}},
	})
	if err != nil {
		t.Fatalf("NewPeerGateVerifier: %v", err)
	}
	if _, err := qrdbsdk.NewPeerAttestationGate(verifier, qrdbsdk.PeerAttestationPolicy{
		Permissions:    []qrdbsdk.Permission{qrdbsdk.PermissionAdminStatus},
		MaxEvidenceAge: time.Minute,
	}); err != nil {
		t.Fatalf("NewPeerAttestationGate: %v", err)
	}

	// No verified peer on the connection: nothing to challenge.
	var certErr *PeerCertificateError
	if _, err := collector.Challenge(ctx, nil); !errors.As(err, &certErr) {
		t.Fatalf("Challenge(nil) = %v, want *PeerCertificateError", err)
	}
	// A verifier with no store is refused at construction.
	var cfgErr *PeerGateConfigError
	if _, err := NewPeerGateVerifier(PeerGateVerifierConfig{}); !errors.As(err, &cfgErr) || cfgErr.Field != "Store" {
		t.Fatalf("NewPeerGateVerifier(empty) = %v, want *PeerGateConfigError on Store", err)
	}
	// The quoting side refuses to run without a TPM to quote with.
	var quoteErr *PeerQuoteError
	if _, err := PeerQuoteEvidence(nil, []byte("nonce"), nil, []uint{0}, nil); !errors.As(err, &quoteErr) {
		t.Fatalf("PeerQuoteEvidence(no quoter) = %v, want *PeerQuoteError", err)
	}
	// Device pairing refuses a missing credential.
	var devErr *PeerDevIDError
	if err := PeerVerifySameDevice(nil, nil); !errors.As(err, &devErr) {
		t.Fatalf("PeerVerifySameDevice(nil, nil) = %v, want *PeerDevIDError", err)
	}
	if PeerChallengeNonceLength != 32 || DefaultPeerChallengeTTL <= 0 || DefaultPeerGateMaxPeers <= 0 || DefaultPeerEvidenceRetention <= 0 {
		t.Fatal("peer gate constants drifted")
	}
}

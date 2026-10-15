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

package apierrors

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestPeerAttestationClassOf classifies the attested-caller verbs' typed and
// sentinel errors, bare and wrapped: a caller without a verified client
// certificate is unauthenticated, a missing or stale challenge a
// precondition, a full challenge table exhausted, and a server without the
// gate unavailable.
func TestPeerAttestationClassOf(t *testing.T) {
	cause := errors.New("cause")
	tests := []struct {
		name string
		err  error
		want Class
	}{
		{"no client certificate", &peergate.PeerCertificateError{Reason: "none"}, ClassUnauthenticated},
		{"no challenge", &peergate.ChallengeError{Reason: "none outstanding"}, ClassFailedPrecondition},
		{"wrapped challenge", fmt.Errorf("submit: %w", &peergate.ChallengeError{Reason: "expired"}), ClassFailedPrecondition},
		{"no exporter", &peer.ChannelBindingError{Reason: "not TLS 1.3"}, ClassFailedPrecondition},
		{"challenge table full", &peergate.CapacityError{What: "challenges", Limit: 1}, ClassResourceExhausted},
		{"store down", &peergate.StoreError{Op: "put", Cause: cause}, ClassUnavailable},
		{"nonce source", &peergate.NonceError{Cause: cause}, ClassUnavailable},
		{"no gate", xkms.ErrNotConfigured, ClassUnavailable},
		{"nil request", xkms.ErrNilRequest, ClassInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := PeerAttestationClassOf(tt.err)
			assert.True(t, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestPeerAttestationClassOf_Unclassified proves nil and an unrelated error
// are not classified.
func TestPeerAttestationClassOf_Unclassified(t *testing.T) {
	_, ok := PeerAttestationClassOf(nil)
	assert.False(t, ok)
	_, ok = PeerAttestationClassOf(errors.New("unrelated"))
	assert.False(t, ok)
}

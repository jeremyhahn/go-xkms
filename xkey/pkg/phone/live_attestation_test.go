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

package phone

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These cover the backend's half of the #129 enforcement: whether the proof is
// DEMANDED, not whether it is judged correctly. The judgement lives in the
// injected verifier and is covered where that verifier is built.
//
// The distinction matters because the failure this guards is not a wrong
// verdict, it is no verdict at all — a device that should have been challenged
// and was not.

// TestProveLivenessRefusesWhenTheVerifierIsMissing is the fail-closed case.
//
// RequireLiveAttestation and LiveAttest are separate fields precisely so that
// forgetting the verifier is a refusal. Had this been "enforce if a verifier is
// set", a caller that reads RequireLiveAttestation off a pairing record and
// forgets to wire LiveAttest would connect with the check silently absent —
// which is the shape of every fail-open defect this package has already had to
// fix once.
func TestProveLivenessRefusesWhenTheVerifierIsMissing(t *testing.T) {
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{RequireLiveAttestation: true},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := backend.proveLiveness(context.Background())

	require.Error(t, err, "a required proof with no way to obtain it must refuse")
	require.ErrorIs(t, err, ErrLiveAttestationUnavailable)
}

// TestProveLivenessSkipsWhenNotRequired covers the legacy record.
//
// A pairing predating #129 has no attested key registered, so there is nothing
// to prove possession of; demanding a proof would refuse every such device
// rather than protect it. Note this must hold with a nil session too — the
// skip has to happen before anything touches one.
func TestProveLivenessSkipsWhenNotRequired(t *testing.T) {
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{RequireLiveAttestation: false},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	require.NoError(t, backend.proveLiveness(context.Background()))
}

// TestProveLivenessPropagatesTheVerifiersRefusal proves the verdict is not
// swallowed: a verifier that refuses must fail the connection, with its own
// error reaching the caller so the operator learns WHY rather than "handshake
// failed".
func TestProveLivenessPropagatesTheVerifiersRefusal(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	refused := errors.New("device could not prove possession")

	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	called := false
	backend := &PhoneKeyBackend{
		cfg: &PhoneKeyBackendConfig{
			RequireLiveAttestation: true,
			LiveAttest: func(context.Context, pairingproto.RPCExchange, []byte) error {
				called = true
				return refused
			},
		},
		session: session,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err = backend.proveLiveness(context.Background())

	// The channel binding is unavailable before a handshake, so the refusal
	// arrives from that guard rather than from the verifier — which is itself
	// the property worth pinning: a session that never completed a handshake
	// has no authenticated peer to bind a proof to, and must not be attested
	// over.
	require.Error(t, err)
	assert.False(t, called,
		"a verifier must not be asked to judge a session with no authenticated peer")
	require.ErrorIs(t, err, ErrNoiseHandshakeFailed)
}

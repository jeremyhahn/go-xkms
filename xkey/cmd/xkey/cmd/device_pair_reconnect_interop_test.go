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

//go:build ble

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// This file is the #129 co-merge gate: the challenge-response attestation
// change must land atomically with the xkey-android prover, and this test is
// what says the two halves agree.
//
// It drives the REAL desktop path end to end, in the order a user experiences
// it:
//
//	PAIR       — attestOverSession over a live Noise session: derive the
//	             channel binding, draw a nonce, ask the device, verify the
//	             chain and the live signature, derive the stored fingerprint.
//	RECONNECT  — PerformHandshake against the same device, including the
//	             pre-handshake identity exchange and the prologue binding.
//	RE-ATTEST  — attestOverSession again on the NEW session, purpose
//	             "reattest", proving the persistent key is still there and
//	             still live.
//
// Nothing here is a byte-echoing stub. The phone runs a real
// bootstrap.NoiseSession as the XX responder, derives its own channel binding
// from its own session, and signs a transcript it lays out itself. So a green
// run means two independent implementations agreed on the prologue, the
// channel binding, the transcript layout and the fingerprint derivation — the
// four values that must match on the wire or nothing connects.
//
// The one thing it cannot prove is that KOTLIN agrees. That is what the shared
// byte-exact test vectors on the issue are for, and why the co-merge waits for
// xkey-android to go green against them.

// TestPairThenReconnectThenReattest_Interop is the #129 co-merge gate.
//
// It is one continuous story rather than three isolated assertions because the
// bug class it guards is the two halves of a flag-day disagreeing: a value the
// desktop derives at pairing and the phone must reproduce at reconnect. Split
// into separate tests, each half would state its own expectation and both
// would pass while the wire was broken.
func TestPairThenReconnectThenReattest_Interop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	trust := &xkms.AndroidDeviceTrust{Roots: ca.Pool(), Applications: attesttest.Applications()}

	// The phone: one persistent StrongBox-backed attested key, attested once at
	// first run under the contract's genesis challenge, AND one persistent
	// Noise identity. Both survive every leg below, because both survive in
	// production.
	device := attesttest.NewPhone(t, attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(),
		xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState()))

	// The desktop's Noise identity, generated once at pairing and stored in the
	// pairing record. Reusing it on the reconnect leg is what makes that leg a
	// RECONNECT rather than a second pairing.
	desktopKey, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)
	defer desktopKey.Destroy()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- PAIR -------------------------------------------------------------
	// The desktop's real pairing attestation: live session, live challenge,
	// live verification.
	pairInit, pairResp := attesttest.NewMemTransportPair()
	pairSession, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
		LocalStaticKey: desktopKey,
		IsInitiator:    true,
	})
	require.NoError(t, err)

	pairDone := make(chan error, 1)
	device.Serve(ctx, t, pairResp, false, 1, pairDone)

	require.NoError(t, pairingproto.PerformHandshake(ctx, &pairingproto.HandshakeConfig{
		Transport:            pairInit,
		Session:              pairSession,
		Logger:               logger,
		LocalStaticPublicKey: pairSession.LocalStaticPublicKey(),
	}), "the pairing handshake must complete")

	verified, err := attestation.AttestOverSession(ctx, pairInit, pairSession, trust, pairingproto.AttestPurposePair, logger)
	require.NoError(t, err, "a contract-faithful device must pair")
	require.NotNil(t, verified)
	require.NoError(t, <-pairDone, "phone responder failed during pairing")

	storedFingerprint := verified.Result.DeviceFingerprint
	require.Equal(t, pairingproto.AttestProtocolV2, verified.Result.ProtocolVersion)

	// WIRE AGREEMENT on the identity: the value the desktop persisted must be
	// the one the phone will echo, derived independently from its own key.
	require.Equal(t, hex.EncodeToString(device.DAK.Fingerprint()), storedFingerprint,
		"the desktop's stored fingerprint must equal the phone's own SPKI hash")

	// The phone stores what it derived, exactly as xkey-android must.
	device.EchoFingerprint = device.DAK.Fingerprint()

	// The phone's static key, as the desktop records it at pairing.
	pairedPhoneStatic := pairSession.RemoteStaticPublicKey()
	require.NotEmpty(t, pairedPhoneStatic)

	// ---- RECONNECT --------------------------------------------------------
	// The SAME static keys on both ends — the ones the pairing record holds —
	// with fresh ephemerals, the stored fingerprint read back the way the
	// reconnect path reads it, and the phone's key PINNED as production pins
	// it. Rotating either identity here would make this a second pairing and
	// leave reconnecting-with-persisted-keys untested.
	expected, err := phone.DecodeDeviceFingerprint(storedFingerprint)
	require.NoError(t, err)

	reconnectInit, reconnectResp := attesttest.NewMemTransportPair()
	reconnectSession, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
		LocalStaticKey:       desktopKey,
		ExpectedRemoteStatic: pairedPhoneStatic,
		IsInitiator:          true,
	})
	require.NoError(t, err)

	reconnectDone := make(chan error, 1)
	device.Serve(ctx, t, reconnectResp, true, 1, reconnectDone)

	require.NoError(t, pairingproto.PerformHandshake(ctx, &pairingproto.HandshakeConfig{
		Transport:                 reconnectInit,
		Session:                   reconnectSession,
		Logger:                    logger,
		LocalStaticPublicKey:      reconnectSession.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: expected,
	}), "a freshly paired device must reconnect under the attested-key binding")
	require.True(t, reconnectSession.IsHandshakeComplete())

	// ---- RE-ATTEST --------------------------------------------------------
	// The point of the whole model: the SAME key proves itself again, on a new
	// session, without rotating the device identity. Under the old
	// embedded-challenge model this leg was impossible on Android.
	reattested, err := attestation.AttestOverSession(ctx, reconnectInit, reconnectSession, trust, pairingproto.AttestPurposeReattest, logger)
	require.NoError(t, err, "the persistent attested key must re-attest on a new session")
	require.NoError(t, <-reconnectDone, "phone responder failed during reconnect")

	assert.Equal(t, storedFingerprint, reattested.Result.DeviceFingerprint,
		"re-attestation of the persistent key must not change the device identity")
	assert.Equal(t, pairingproto.AttestProtocolV2, reattested.Result.ProtocolVersion)

	// WHAT THE CHANNEL BINDING ACTUALLY PROVIDES — stated honestly, because the
	// first version of this assertion did not.
	//
	// It read "each connection must produce its own binding", which is a
	// property ComputeAttestChannelBinding deliberately does NOT have: it
	// hashes the two static keys and the prologue, all of which persist, so
	// two reconnects with the same identities produce the SAME binding. That
	// assertion passed only because the test rotated the static keys it was
	// meant to persist — a non-production topology asserting a non-existent
	// guarantee, which would have gone on passing if reconnecting with the
	// stored keys had broken entirely. (Codex, #124.)
	//
	// The binding is per KEY PAIR AND CONTEXT, not per session. Freshness is
	// the nonce's job, and saying so here is what keeps the two from being
	// confused again.
	pairBinding, err := pairingproto.AttestChannelBinding(pairSession)
	require.NoError(t, err)
	reconnectBinding, err := pairingproto.AttestChannelBinding(reconnectSession)
	require.NoError(t, err)

	// Pairing and reconnect DO differ, but because of the prologue, not the
	// session: a first pairing has no fingerprint to bind and runs with an
	// empty one. That is the length-prefixed case the derivation separates.
	assert.NotEqual(t, pairBinding, reconnectBinding,
		"a first pairing binds an empty prologue and a reconnect binds the "+
			"fingerprint, so the two contexts must not collide")
	require.Empty(t, pairSession.Prologue(), "the pairing leg must be the empty-prologue case")
	require.NotEmpty(t, reconnectSession.Prologue(), "the reconnect leg must bind the fingerprint")

	// A SECOND reconnect, same persisted identities, same prologue: the binding
	// is expected to be identical, and the signatures still differ because the
	// nonces do. This is the property that actually holds.
	secondInit, secondResp := attesttest.NewMemTransportPair()
	secondSession, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
		LocalStaticKey:       desktopKey,
		ExpectedRemoteStatic: pairedPhoneStatic,
		IsInitiator:          true,
	})
	require.NoError(t, err)

	secondDone := make(chan error, 1)
	device.Serve(ctx, t, secondResp, true, 1, secondDone)

	require.NoError(t, pairingproto.PerformHandshake(ctx, &pairingproto.HandshakeConfig{
		Transport:                 secondInit,
		Session:                   secondSession,
		Logger:                    logger,
		LocalStaticPublicKey:      secondSession.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: expected,
	}), "the persisted identities must keep reconnecting, not just once")

	secondBinding, err := pairingproto.AttestChannelBinding(secondSession)
	require.NoError(t, err)
	assert.Equal(t, reconnectBinding, secondBinding,
		"the binding is per key pair and context; two reconnects with the same "+
			"identities and prologue share it, and the nonce is what makes each "+
			"exchange unrepeatable")

	secondAttest, err := attestation.AttestOverSession(ctx, secondInit, secondSession, trust, pairingproto.AttestPurposeReattest, logger)
	require.NoError(t, err, "the third handshake with the persisted keys must also re-attest")
	require.NoError(t, <-secondDone, "phone responder failed during the second reconnect")
	assert.Equal(t, storedFingerprint, secondAttest.Result.DeviceFingerprint)

	// The record the desktop would persist, applied the way the CLI applies it.
	record := &PairedDevice{Name: "interop", Address: "00:11:22:33:44:55"}
	recordDeviceAttestation(record, verified.Result)
	recordDeviceAttestation(record, reattested.Result)
	assert.Equal(t, storedFingerprint, record.DeviceFingerprint)
	assert.Equal(t, pairingproto.AttestProtocolV2, record.AttestationProtocolVersion,
		"the record must remember it was bound under challenge-response")
	assert.NoError(t, attestation.DeviceBindingFor(*record).ValidateAttestedKeyMatch(reattested.Result.DeviceFingerprint),
		"an honest re-attestation must not read as a changed device")
}

// TestReconnectRefusesADeviceThatCannotProveLiveness is the negative half of
// the gate.
//
// It is the scenario the flag-day exists to make safe: the reconnect handshake
// succeeds — the peer holds the paired Noise key and echoes the right
// fingerprint, so every check that existed before #129 passes — and the device
// still cannot prove it holds the attested key. Before the challenge-response
// step, that peer was in.
func TestReconnectRefusesADeviceThatCannotProveLiveness(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	trust := &xkms.AndroidDeviceTrust{Roots: ca.Pool(), Applications: attesttest.Applications()}

	genuine := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	impostor := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	// The impostor replays the genuine device's chain — public bytes anyone
	// who has watched one pairing holds — but can only sign with its own key.
	relay := attesttest.NewPairedPhone(t, impostor, genuine.Fingerprint())
	relay.DAK = &attesttest.DAK{Key: impostor.Key, Leaf: genuine.Leaf, Chain: genuine.Chain, FP: genuine.FP}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	init, resp := attesttest.NewMemTransportPair()
	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	done := make(chan error, 1)
	relay.Serve(ctx, t, resp, true, 1, done)

	require.NoError(t, pairingproto.PerformHandshake(ctx, &pairingproto.HandshakeConfig{
		Transport:                 init,
		Session:                   session,
		Logger:                    logger,
		LocalStaticPublicKey:      session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: genuine.Fingerprint(),
	}), "the fingerprint echo and the prologue still agree; that is the point")

	verified, err := attestation.AttestOverSession(ctx, init, session, trust, pairingproto.AttestPurposeReattest, logger)

	require.Error(t, err, "a device that cannot sign the challenge must be refused")
	require.ErrorIs(t, err, pairingproto.ErrAttestSignatureInvalid)
	assert.Nil(t, verified)
	require.NoError(t, <-done, "the relay responder itself must not have errored")
}

// TestReconnectEnforcesLivenessBeforeTheSessionIsUsable is the production-path
// half of the gate, and the regression for Codex's round-2 blocking finding on
// #124.
//
// Recording `attestation_protocol_version` without enforcing it would make the
// field a claim the code does not keep: possession of a COPIED paired Noise key
// would still open a session and drive every device operation, which is the
// exact gap the persistent attested key exists to close. The earlier interop
// test called attestOverSession by hand after the handshake, so it proved the
// protocol worked and said nothing about whether anything ran it.
//
// This drives verifyReattestation — the function openDeviceSession calls, with
// its trust material stated rather than read off this machine — over a real
// Noise session, once per way the proof can fail to be one. The device is a
// legitimately paired peer every time: right Noise key, right fingerprint echo,
// handshake complete. Only the attestation answer varies.
func TestReconnectEnforcesLivenessBeforeTheSessionIsUsable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	genuine := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	impostor := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	// The record a #129 pairing writes.
	bound := &PairedDevice{
		Name:                       "bound",
		Address:                    "00:11:22:33:44:55",
		DeviceFingerprint:          hex.EncodeToString(genuine.Fingerprint()),
		AttestationProtocolVersion: pairingproto.AttestProtocolV2,
	}

	// A record from before #129: no attested key was ever registered, so there
	// is nothing to prove possession OF. Demanding a proof would refuse every
	// legacy pairing rather than protect it.
	legacy := &PairedDevice{
		Name:              "legacy",
		Address:           "00:11:22:33:44:66",
		DeviceFingerprint: hex.EncodeToString(genuine.Fingerprint()),
	}

	t.Run("a contract-faithful device connects", func(t *testing.T) {
		device := attesttest.NewPairedPhone(t, genuine, genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, bound, device, nil)
		require.NoError(t, err, "the whole point is that a genuine device still works")
	})

	t.Run("a legacy record is refused", func(t *testing.T) {
		// The phone answers version 1, as an un-upgraded app would. A legacy
		// record is now refused outright (BREAKING, go-xkms compat cleanup
		// PR5: the #129/#130 grace period for a record below version 2 is
		// removed) -- the operator must re-pair.
		device := attesttest.NewPairedPhone(t, genuine, genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, legacy, device, func(r *pairingproto.LocalAttestDeviceResult) {
			r.ProtocolVersion = pairingproto.AttestProtocolV1
			r.Signature = nil
		})
		require.Error(t, err)
		require.ErrorIs(t, err, attestation.ErrDeviceAttestationVersionUnsupported)
	})

	t.Run("a missing signature refuses the session", func(t *testing.T) {
		device := attesttest.NewPairedPhone(t, genuine, genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, bound, device, func(r *pairingproto.LocalAttestDeviceResult) {
			r.Signature = nil
		})
		require.Error(t, err)
		require.ErrorIs(t, err, pairingproto.ErrAttestSignatureMissing)
	})

	t.Run("a downgraded answer refuses the session", func(t *testing.T) {
		device := attesttest.NewPairedPhone(t, genuine, genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, bound, device, func(r *pairingproto.LocalAttestDeviceResult) {
			r.ProtocolVersion = pairingproto.AttestProtocolV1
		})
		require.Error(t, err,
			"a peer must not opt out of a check by declaring itself unable to satisfy it")
		require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	})

	t.Run("a copied Noise key without the attested key refuses the session", func(t *testing.T) {
		// The scenario the model exists for. The attacker holds the paired
		// Noise key and replays the genuine device's public chain — everything
		// the pre-#129 reconnect checked. It cannot sign.
		relay := attesttest.NewPairedPhone(t,
			&attesttest.DAK{Key: impostor.Key, Leaf: genuine.Leaf, Chain: genuine.Chain, FP: genuine.FP},
			genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, bound, relay, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, pairingproto.ErrAttestSignatureInvalid)
	})

	t.Run("a rotated attested key refuses the session", func(t *testing.T) {
		// A device that genuinely holds a different attested key: the chain
		// verifies and the signature is valid, but the identity is not the one
		// bound at pairing. Rebinding is an explicit re-pair, never a reconnect.
		rotated := attesttest.NewPairedPhone(t, impostor, genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, bound, rotated, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, attestation.ErrDeviceIdentityChanged)
	})
}

// runReattestAgainst drives one reconnect against device and returns what
// verifyReattestation decided.
//
// It runs the real handshake (identity exchange, prologue binding, Noise XX)
// and then the real enforcement function, so a failure here is the production
// decision failing rather than a re-statement of it.
func runReattestAgainst(
	t *testing.T,
	logger *slog.Logger,
	ca *attesttest.CA,
	record *PairedDevice,
	device *attesttest.Phone,
	mutate func(*pairingproto.LocalAttestDeviceResult),
) error {
	t.Helper()

	device.Mutate = mutate

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	init, resp := attesttest.NewMemTransportPair()
	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	done := make(chan error, 1)
	device.Serve(ctx, t, resp, true, 1, done)

	// Stop the responder before this helper returns, whatever happens. A legacy
	// record skips the exchange entirely, so the responder would otherwise sit
	// blocked on a receive that never comes, outlive the subtest, and read its
	// own static key while t.Cleanup was wiping it.
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("phone responder did not stop after its context was cancelled")
		}
	}()

	expected, err := phone.DecodeDeviceFingerprint(record.DeviceFingerprint)
	require.NoError(t, err)

	require.NoError(t, pairingproto.PerformHandshake(ctx, &pairingproto.HandshakeConfig{
		Transport:                 init,
		Session:                   session,
		Logger:                    logger,
		LocalStaticPublicKey:      session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: expected,
	}), "every check that existed before #129 must still pass; that is the point")

	reattestErr := attestation.VerifyReattestation(ctx, init, session, attestation.DeviceBindingFor(*record), &xkms.AndroidDeviceTrust{Roots: ca.Pool(), Applications: attesttest.Applications()}, logger)

	return reattestErr
}

// TestPairedDeviceBackendConfigCarriesEveryIdentityCheck guards the
// centralization itself, which is the thing that keeps failing.
//
// Five commands built this configuration independently — OATH sync, backup,
// sharing, attest, FIDO2 — and each was a place a check could be left out.
// None set ExpectedDeviceFingerprint, so none bound the prologue; none
// required the #129 liveness proof once it existed, so a v2 device could be
// driven through any of them with only a COPIED paired Noise key. Wiring one
// of the five and calling it done is how that gap survived a round of review
// (Codex, #124).
//
// This asserts the builder's output rather than any one command's behaviour,
// because the builder is now the single place those fields are decided: a
// command that uses it cannot omit them, and one that does not use it is the
// regression to catch in review.
func TestPairedDeviceBackendConfigCarriesEveryIdentityCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ca := attesttest.NewCA(t, "Trusted Attestation Root")
	dak := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	localKey, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)
	defer localKey.Destroy()

	// EncodeStaticKey writes HEX (NoiseHexKeySize bytes); the pairing record
	// stores base64 of the raw scalar, so decode back to raw first.
	encoded := make([]byte, bootstrap.NoiseHexKeySize)
	require.NoError(t, bootstrap.EncodeNoiseStaticKey(encoded, localKey))
	raw, err := hex.DecodeString(string(encoded))
	require.NoError(t, err)
	defer bootstrap.WipeNoiseBytes(raw)

	remote, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)
	defer remote.Destroy()

	v2 := &PairedDevice{
		Name:                       "bound",
		Address:                    "00:11:22:33:44:55",
		LocalNoisePrivateKey:       base64.StdEncoding.EncodeToString(raw),
		NoisePublicKey:             base64.StdEncoding.EncodeToString(remote.PublicBytes()),
		DeviceFingerprint:          hex.EncodeToString(dak.Fingerprint()),
		AttestationProtocolVersion: pairingproto.AttestProtocolV2,
	}

	t.Run("a v2 record demands the liveness proof and supplies a verifier", func(t *testing.T) {
		cfg, err := newPairedDeviceBackendConfig(v2, time.Minute, logger)
		require.NoError(t, err)
		defer cfg.LocalStaticKey.Destroy()

		assert.True(t, cfg.RequireLiveAttestation,
			"a record bound under challenge-response must demand the proof on every surface")
		assert.NotNil(t, cfg.LiveAttest,
			"demanding the proof without a verifier is a refusal at connect; both must be set together")
		assert.Equal(t, dak.Fingerprint(), cfg.ExpectedDeviceFingerprint,
			"the stored fingerprint must bind the prologue; none of the five call sites used to set it")
		assert.Equal(t, remote.PublicBytes(), cfg.ExpectedRemoteStatic)
		assert.True(t, cfg.OwnsStaticKey,
			"these helpers keep nothing, so the backend must own the key or it is never released")
	})

	t.Run("a legacy record still demands the proof, which its own verifier then refuses", func(t *testing.T) {
		// BREAKING, go-xkms compat cleanup PR5: RequireLiveAttestation is now
		// unconditional -- there is no #129/#130 grace period for a record
		// below version 2. LiveAttest's closure (newLiveAttestor) is what
		// actually refuses a legacy record, via DeviceBinding.Validate, the
		// first time the backend calls it.
		legacy := *v2
		legacy.AttestationProtocolVersion = 0

		cfg, err := newPairedDeviceBackendConfig(&legacy, time.Minute, logger)
		require.NoError(t, err)
		defer cfg.LocalStaticKey.Destroy()

		assert.True(t, cfg.RequireLiveAttestation)
		require.NotNil(t, cfg.LiveAttest)
		err = cfg.LiveAttest(context.Background(), nil, nil)
		require.ErrorIs(t, err, attestation.ErrDeviceAttestationVersionUnsupported)
		assert.Equal(t, dak.Fingerprint(), cfg.ExpectedDeviceFingerprint,
			"the fingerprint binding is not conditional on the protocol version")
	})

	t.Run("a corrupt stored fingerprint refuses rather than connecting unbound", func(t *testing.T) {
		corrupt := *v2
		corrupt.DeviceFingerprint = "not-hex"

		cfg, err := newPairedDeviceBackendConfig(&corrupt, time.Minute, logger)

		require.Error(t, err,
			"a malformed value must not degrade into the 'no fingerprint configured' signal")
		assert.Nil(t, cfg)
	})
}

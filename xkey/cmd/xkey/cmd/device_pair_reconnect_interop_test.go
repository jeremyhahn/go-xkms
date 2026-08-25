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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
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
// pairing.NoiseSession as the XX responder, derives its own channel binding
// from its own session, and signs a transcript it lays out itself. So a green
// run means two independent implementations agreed on the prologue, the
// channel binding, the transcript layout and the fingerprint derivation — the
// four values that must match on the wire or nothing connects.
//
// The one thing it cannot prove is that KOTLIN agrees. That is what the shared
// byte-exact test vectors on the issue are for, and why the co-merge waits for
// xkey-android to go green against them.

// memTransport is an in-memory pairing.Transport: a crossed pair carries the
// initiator's bytes to the responder and back.
type memTransport struct {
	rx <-chan []byte
	tx chan<- []byte
}

func newMemTransportPair() (initiator, responder *memTransport) {
	a2b := make(chan []byte, 8)
	b2a := make(chan []byte, 8)
	return &memTransport{rx: b2a, tx: a2b}, &memTransport{rx: a2b, tx: b2a}
}

func (t *memTransport) Send(ctx context.Context, m []byte) error {
	select {
	case t.tx <- m:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *memTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case m := <-t.rx:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *memTransport) SendAndReceive(ctx context.Context, m []byte) ([]byte, error) {
	if err := t.Send(ctx, m); err != nil {
		return nil, err
	}
	return t.Receive(ctx)
}

func (t *memTransport) IsConnected() bool { return true }
func (t *memTransport) Close() error      { return nil }

// interopPhone plays xkey-android: a persistent attested key, a real Noise XX
// responder, and a local.attestDevice handler that answers challenges by
// signing them.
//
// It holds the DAK across sessions on purpose — that persistence is the whole
// of #129, and a phone that regenerated the key per connection would fail the
// reconnect leg exactly as the old model did.
type interopPhone struct {
	dak *attesttest.DAK

	// echoFingerprint is what the phone reports in the identity exchange for a
	// KNOWN device. It is stored at pairing, mirroring the Android side, so
	// that reconnect compares a value the phone kept rather than one it
	// recomputes on demand.
	echoFingerprint []byte

	// staticKey is the phone's PERSISTENT Noise identity, the one written into
	// the pairing record. It must be the same key on every leg: production
	// reuses the paired static keys, and a phone that generated a fresh one per
	// connection would not be reconnecting at all — it would be pairing again,
	// which is a different code path with different bindings. A test that
	// rotates the identity it is meant to persist cannot see a break in
	// reconnecting with persisted keys. (Codex, #124.)
	staticKey *pairing.StaticKey

	// staticPub is a COPY of the static key's public half, taken at
	// construction. The responder goroutine derives its channel binding from
	// it, and must not read staticKey: that key is wiped by t.Cleanup when the
	// test ends, and a goroutine still running at that moment reads bytes
	// being zeroed underneath it. Measured as a data race under -race in CI
	// (the local suite does not race this package), and it is a real
	// lifetime bug rather than a test artefact — the same shape as reading a
	// destroyed key on a slow shutdown.
	staticPub []byte

	// mutate, when set, damages the otherwise contract-faithful response just
	// before it is sent. It is how the negative cases model a device that
	// answers but cannot prove what it claims — the damage happens on the WIRE,
	// after a correct response was built, so nothing about the honest path is
	// bypassed to produce it.
	mutate func(*pairing.LocalAttestDeviceResult)
}

// newInteropPhone builds a phone with a persistent Noise identity and a
// persistent attested key — the two things a real handset keeps across
// connections, and the two this test exists to exercise.
func newInteropPhone(t *testing.T, dak *attesttest.DAK) *interopPhone {
	t.Helper()

	key, err := pairing.GenerateStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	return &interopPhone{
		dak:       dak,
		staticKey: key,
		staticPub: append([]byte(nil), key.Public...),
	}
}

// newPairedInteropPhone is newInteropPhone for a device that is already paired:
// it carries the fingerprint it stored at pairing and echoes that on reconnect.
//
// Every phone needs a persistent Noise identity, so construction goes through
// here rather than a struct literal — a phone with no static key is not a
// device that reconnects, it is a device that pairs again.
func newPairedInteropPhone(t *testing.T, dak *attesttest.DAK, echoFingerprint []byte) *interopPhone {
	t.Helper()

	p := newInteropPhone(t, dak)
	p.echoFingerprint = echoFingerprint
	return p
}

// serve runs one connection: identity exchange, Noise XX responder, then
// exchanges of encrypted JSON-RPC until the transport is done. It reports the
// first failure on done and returns.
//
// known selects the identity-ack branch: false is a first pairing (the phone
// has no record of this desktop), true is a reconnect.
func (p *interopPhone) serve(ctx context.Context, t *testing.T, tr *memTransport, known bool, exchanges int, done chan<- error) {
	t.Helper()

	go func() {
		done <- p.run(ctx, tr, known, exchanges)
	}()
}

// run takes the CALLER's context rather than making its own, so a caller that
// finishes early can stop the responder deterministically instead of leaving it
// blocked on a receive that will never come. A goroutine outliving its subtest
// is what let t.Cleanup wipe the static key under it.
func (p *interopPhone) run(ctx context.Context, tr *memTransport, known bool, exchanges int) error {

	// 1. Identity exchange. The initiator sends [0x01, pubkey(32)].
	idMsg, err := tr.Receive(ctx)
	if err != nil {
		return err
	}
	if len(idMsg) != pairing.IdentityMsgSize || idMsg[0] != pairing.IdentityMsgVersion {
		return fmt.Errorf("bad identity message: len=%d", len(idMsg))
	}
	initiatorPub := append([]byte(nil), idMsg[1:]...)

	// 2. Answer as a known or a new device, and compute the prologue the same
	//    way the initiator does. An empty prologue is the first-pairing case.
	var prologue []byte
	if known {
		if err := tr.Send(ctx, append([]byte{pairing.IdentityAckKnown}, p.echoFingerprint...)); err != nil {
			return err
		}
		prologue = interopPrologue(initiatorPub, p.echoFingerprint)
	} else {
		if err := tr.Send(ctx, []byte{pairing.IdentityAckUnknown}); err != nil {
			return err
		}
	}

	// 3. Real Noise XX responder.
	sess, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey: p.staticKey,
		IsInitiator:    false,
		Prologue:       prologue,
	})
	if err != nil {
		return err
	}
	if err := sess.InitHandshake(); err != nil {
		return err
	}

	msg1, err := tr.Receive(ctx)
	if err != nil {
		return err
	}
	msg2, complete, err := sess.HandshakeMessage(msg1)
	if err != nil {
		return err
	}
	if complete {
		return fmt.Errorf("responder completed after msg1")
	}
	if err := tr.Send(ctx, msg2); err != nil {
		return err
	}

	msg3, err := tr.Receive(ctx)
	if err != nil {
		return err
	}
	if _, complete, err = sess.HandshakeMessage(msg3); err != nil {
		return err
	}
	if !complete || !sess.IsHandshakeComplete() {
		return fmt.Errorf("responder did not complete the handshake")
	}

	// 4. The phone derives its OWN channel binding, BY HAND, from raw session
	//    state — deliberately NOT by calling AttestChannelBinding().
	//
	//    This is the difference between a test that can see a wrong derivation
	//    and one that cannot. When both ends called the shared helper, a
	//    mutation to that helper moved the oracle along with the subject: a
	//    wrong-but-internally-consistent binding (sorted keys, swapped roles)
	//    left this test green, because both sides computed the same wrong
	//    value and the signature verified. Measured — and the xkey-android
	//    lane hit the identical hazard in its own E2E test. Deriving by hand
	//    here makes the phone an independent oracle, exactly as the DAK lays
	//    out the transcript by hand rather than calling BuildAttestTranscript.
	binding := interopChannelBinding(initiatorPub, p.staticPub, prologue)

	// 5. Serve the encrypted attestation exchanges.
	for i := 0; i < exchanges; i++ {
		if err := p.serveAttestExchange(ctx, tr, sess, binding); err != nil {
			return err
		}
	}
	return nil
}

// serveAttestExchange handles one encrypted local.attestDevice round trip.
func (p *interopPhone) serveAttestExchange(
	ctx context.Context,
	tr *memTransport,
	sess *pairing.NoiseSession,
	binding []byte,
) error {
	ciphertext, err := tr.Receive(ctx)
	if err != nil {
		return err
	}
	plaintext, err := sess.Decrypt(ciphertext)
	if err != nil {
		return err
	}

	req, err := pairing.DecodeRequest(plaintext)
	if err != nil {
		return err
	}
	if req.Method != pairing.MethodLocalAttestDevice {
		return fmt.Errorf("unexpected method %q", req.Method)
	}

	// Params arrives as generic JSON; re-marshal it into the wire struct the
	// same way any responder must.
	raw, err := json.Marshal(req.Params)
	if err != nil {
		return err
	}
	var params pairing.LocalAttestDeviceParams
	if err := json.Unmarshal(raw, &params); err != nil {
		return err
	}
	if params.ProtocolVersion != pairing.AttestProtocolV2 {
		return fmt.Errorf("desktop asked for protocol version %d", params.ProtocolVersion)
	}

	// The phone signs the binding IT derived, not the one it was handed. A
	// prover that echoed the desktop's channelBinding parameter back into its
	// transcript would pass this test while proving nothing about the two
	// derivations agreeing — and would hand a relay attacker exactly the
	// signature the binding exists to deny. This is the one place the test
	// deliberately ignores a field the request carries.
	sig, err := p.dak.SignRaw(params.Purpose, params.Nonce, binding)
	if err != nil {
		return err
	}

	result := &pairing.LocalAttestDeviceResult{
		ProtocolVersion:    pairing.AttestProtocolV2,
		Format:             "android-keystore",
		CertificateChain:   p.dak.Chain,
		SecurityLevel:      "strongbox",
		Nonce:              params.Nonce,
		Purpose:            params.Purpose,
		Signature:          sig,
		SignatureAlgorithm: pairing.AttestSignatureES256,
	}

	if p.mutate != nil {
		p.mutate(result)
	}

	response, err := pairing.EncodeResponse(req.ID, result)
	if err != nil {
		return err
	}
	out, err := sess.Encrypt(response)
	if err != nil {
		return err
	}
	return tr.Send(ctx, out)
}

// interopChannelBinding mirrors the published channel-binding derivation (§5 of
// the wire contract), spelled out rather than borrowed from the package under
// test:
//
//	SHA-256( "xkey-attest-channel-v1"
//	       || 0x20 || initiatorStaticPub
//	       || 0x20 || responderStaticPub
//	       || len8(prologue) || prologue )
//
// Written out on purpose. A test whose expected value comes from the function
// it is testing cannot fail when that function is wrong — it can only fail
// when the two SIDES disagree, and a shared helper guarantees they never do.
func interopChannelBinding(initiatorPub, responderPub, prologue []byte) []byte {
	h := sha256.New()
	h.Write([]byte(pairing.AttestChannelBindingDomain))
	h.Write([]byte{byte(len(initiatorPub))})
	h.Write(initiatorPub)
	h.Write([]byte{byte(len(responderPub))})
	h.Write(responderPub)
	h.Write([]byte{byte(len(prologue))})
	h.Write(prologue)
	return h.Sum(nil)
}

// interopPrologue mirrors the initiator's prologue derivation:
// SHA256(initiatorPublicKey || deviceFingerprint || "xkey-v1").
//
// It is spelled out rather than borrowed from the package under test on
// purpose: the phone has to derive this value independently on the wire, and a
// test that called the desktop's own helper could not notice the two drifting
// apart.
func interopPrologue(initiatorPub, fingerprint []byte) []byte {
	h := sha256.New()
	h.Write(initiatorPub)
	h.Write(fingerprint)
	h.Write([]byte("xkey-v1"))
	return h.Sum(nil)
}

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
	trust := &attestation.Trust{Pool: ca.Pool()}

	// The phone: one persistent StrongBox-backed attested key, attested once at
	// first run under the contract's genesis challenge, AND one persistent
	// Noise identity. Both survive every leg below, because both survive in
	// production.
	device := newInteropPhone(t, attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(),
		xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState()))

	// The desktop's Noise identity, generated once at pairing and stored in the
	// pairing record. Reusing it on the reconnect leg is what makes that leg a
	// RECONNECT rather than a second pairing.
	desktopKey, err := pairing.GenerateStaticKey()
	require.NoError(t, err)
	defer desktopKey.Destroy()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ---- PAIR -------------------------------------------------------------
	// The desktop's real pairing attestation: live session, live challenge,
	// live verification.
	pairInit, pairResp := newMemTransportPair()
	pairSession, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey: desktopKey,
		IsInitiator:    true,
	})
	require.NoError(t, err)

	pairDone := make(chan error, 1)
	device.serve(ctx, t, pairResp, false, 1, pairDone)

	require.NoError(t, pairing.PerformHandshake(ctx, &pairing.HandshakeConfig{
		Transport:            pairInit,
		Session:              pairSession,
		Logger:               logger,
		LocalStaticPublicKey: pairSession.LocalStaticPublicKey(),
	}), "the pairing handshake must complete")

	verified, err := attestation.AttestOverSession(ctx, pairInit, pairSession, trust, phone.AttestPurposePair, logger)
	require.NoError(t, err, "a contract-faithful device must pair")
	require.NotNil(t, verified)
	require.NoError(t, <-pairDone, "phone responder failed during pairing")

	storedFingerprint := verified.Result.DeviceFingerprint
	require.Equal(t, phone.AttestProtocolV2, verified.Result.ProtocolVersion)

	// WIRE AGREEMENT on the identity: the value the desktop persisted must be
	// the one the phone will echo, derived independently from its own key.
	require.Equal(t, hex.EncodeToString(device.dak.Fingerprint()), storedFingerprint,
		"the desktop's stored fingerprint must equal the phone's own SPKI hash")

	// The phone stores what it derived, exactly as xkey-android must.
	device.echoFingerprint = device.dak.Fingerprint()

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

	reconnectInit, reconnectResp := newMemTransportPair()
	reconnectSession, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey:       desktopKey,
		ExpectedRemoteStatic: pairedPhoneStatic,
		IsInitiator:          true,
	})
	require.NoError(t, err)

	reconnectDone := make(chan error, 1)
	device.serve(ctx, t, reconnectResp, true, 1, reconnectDone)

	require.NoError(t, pairing.PerformHandshake(ctx, &pairing.HandshakeConfig{
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
	reattested, err := attestation.AttestOverSession(ctx, reconnectInit, reconnectSession, trust, phone.AttestPurposeReattest, logger)
	require.NoError(t, err, "the persistent attested key must re-attest on a new session")
	require.NoError(t, <-reconnectDone, "phone responder failed during reconnect")

	assert.Equal(t, storedFingerprint, reattested.Result.DeviceFingerprint,
		"re-attestation of the persistent key must not change the device identity")
	assert.Equal(t, phone.AttestProtocolV2, reattested.Result.ProtocolVersion)

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
	pairBinding, err := pairSession.AttestChannelBinding()
	require.NoError(t, err)
	reconnectBinding, err := reconnectSession.AttestChannelBinding()
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
	secondInit, secondResp := newMemTransportPair()
	secondSession, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey:       desktopKey,
		ExpectedRemoteStatic: pairedPhoneStatic,
		IsInitiator:          true,
	})
	require.NoError(t, err)

	secondDone := make(chan error, 1)
	device.serve(ctx, t, secondResp, true, 1, secondDone)

	require.NoError(t, pairing.PerformHandshake(ctx, &pairing.HandshakeConfig{
		Transport:                 secondInit,
		Session:                   secondSession,
		Logger:                    logger,
		LocalStaticPublicKey:      secondSession.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: expected,
	}), "the persisted identities must keep reconnecting, not just once")

	secondBinding, err := secondSession.AttestChannelBinding()
	require.NoError(t, err)
	assert.Equal(t, reconnectBinding, secondBinding,
		"the binding is per key pair and context; two reconnects with the same "+
			"identities and prologue share it, and the nonce is what makes each "+
			"exchange unrepeatable")

	secondAttest, err := attestation.AttestOverSession(ctx, secondInit, secondSession, trust, phone.AttestPurposeReattest, logger)
	require.NoError(t, err, "the third handshake with the persisted keys must also re-attest")
	require.NoError(t, <-secondDone, "phone responder failed during the second reconnect")
	assert.Equal(t, storedFingerprint, secondAttest.Result.DeviceFingerprint)

	// The record the desktop would persist, applied the way the CLI applies it.
	record := &PairedDevice{Name: "interop", Address: "00:11:22:33:44:55"}
	recordDeviceAttestation(record, verified.Result)
	recordDeviceAttestation(record, reattested.Result)
	assert.Equal(t, storedFingerprint, record.DeviceFingerprint)
	assert.Equal(t, phone.AttestProtocolV2, record.AttestationProtocolVersion,
		"the record must remember it was bound under challenge-response")
	assert.NoError(t, record.attestationBinding().ValidateAttestedKeyMatch(reattested.Result.DeviceFingerprint),
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
	trust := &attestation.Trust{Pool: ca.Pool()}

	genuine := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	impostor := attesttest.NewDAK(t, ca, attesttest.GenesisChallenge(), xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())

	// The impostor replays the genuine device's chain — public bytes anyone
	// who has watched one pairing holds — but can only sign with its own key.
	relay := newPairedInteropPhone(t, impostor, genuine.Fingerprint())
	relay.dak = &attesttest.DAK{Key: impostor.Key, Leaf: genuine.Leaf, Chain: genuine.Chain, FP: genuine.FP}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	init, resp := newMemTransportPair()
	session, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	done := make(chan error, 1)
	relay.serve(ctx, t, resp, true, 1, done)

	require.NoError(t, pairing.PerformHandshake(ctx, &pairing.HandshakeConfig{
		Transport:                 init,
		Session:                   session,
		Logger:                    logger,
		LocalStaticPublicKey:      session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: genuine.Fingerprint(),
	}), "the fingerprint echo and the prologue still agree; that is the point")

	verified, err := attestation.AttestOverSession(ctx, init, session, trust, phone.AttestPurposeReattest, logger)

	require.Error(t, err, "a device that cannot sign the challenge must be refused")
	require.ErrorIs(t, err, phone.ErrAttestSignatureInvalid)
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
		AttestationProtocolVersion: phone.AttestProtocolV2,
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
		device := newPairedInteropPhone(t, genuine, genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, bound, device, nil)
		require.NoError(t, err, "the whole point is that a genuine device still works")
	})

	t.Run("a legacy record is left alone", func(t *testing.T) {
		// The phone answers version 1, as an un-upgraded app would. A legacy
		// record must still connect: enforcement begins when a record says it
		// was bound under challenge-response.
		device := newPairedInteropPhone(t, genuine, genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, legacy, device, func(r *phone.LocalAttestDeviceResult) {
			r.ProtocolVersion = phone.AttestProtocolV1
			r.Signature = nil
		})
		require.NoError(t, err,
			"a record with no registered attested key has nothing to prove; refusing it "+
				"would break every pairing that predates this change")
	})

	t.Run("a missing signature refuses the session", func(t *testing.T) {
		device := newPairedInteropPhone(t, genuine, genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, bound, device, func(r *phone.LocalAttestDeviceResult) {
			r.Signature = nil
		})
		require.Error(t, err)
		require.ErrorIs(t, err, phone.ErrAttestSignatureMissing)
	})

	t.Run("a downgraded answer refuses the session", func(t *testing.T) {
		device := newPairedInteropPhone(t, genuine, genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, bound, device, func(r *phone.LocalAttestDeviceResult) {
			r.ProtocolVersion = phone.AttestProtocolV1
		})
		require.Error(t, err,
			"a peer must not opt out of a check by declaring itself unable to satisfy it")
		require.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	})

	t.Run("a copied Noise key without the attested key refuses the session", func(t *testing.T) {
		// The scenario the model exists for. The attacker holds the paired
		// Noise key and replays the genuine device's public chain — everything
		// the pre-#129 reconnect checked. It cannot sign.
		relay := newPairedInteropPhone(t,
			&attesttest.DAK{Key: impostor.Key, Leaf: genuine.Leaf, Chain: genuine.Chain, FP: genuine.FP},
			genuine.Fingerprint())
		err := runReattestAgainst(t, logger, ca, bound, relay, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, phone.ErrAttestSignatureInvalid)
	})

	t.Run("a rotated attested key refuses the session", func(t *testing.T) {
		// A device that genuinely holds a different attested key: the chain
		// verifies and the signature is valid, but the identity is not the one
		// bound at pairing. Rebinding is an explicit re-pair, never a reconnect.
		rotated := newPairedInteropPhone(t, impostor, genuine.Fingerprint())
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
	device *interopPhone,
	mutate func(*phone.LocalAttestDeviceResult),
) error {
	t.Helper()

	device.mutate = mutate

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	init, resp := newMemTransportPair()
	session, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	done := make(chan error, 1)
	device.serve(ctx, t, resp, true, 1, done)

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

	require.NoError(t, pairing.PerformHandshake(ctx, &pairing.HandshakeConfig{
		Transport:                 init,
		Session:                   session,
		Logger:                    logger,
		LocalStaticPublicKey:      session.LocalStaticPublicKey(),
		ExpectedDeviceFingerprint: expected,
	}), "every check that existed before #129 must still pass; that is the point")

	reattestErr := attestation.VerifyReattestation(ctx, init, session, record.attestationBinding(), &attestation.Trust{Pool: ca.Pool()}, logger)

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

	localKey, err := pairing.GenerateStaticKey()
	require.NoError(t, err)
	defer localKey.Destroy()

	// EncodeStaticKey writes HEX (NoiseHexKeySize bytes); the pairing record
	// stores base64 of the raw scalar, so decode back to raw first.
	encoded := make([]byte, pairing.NoiseHexKeySize)
	require.NoError(t, pairing.EncodeStaticKey(encoded, localKey))
	raw, err := hex.DecodeString(string(encoded))
	require.NoError(t, err)
	defer pairing.WipeBytes(raw)

	remote, err := pairing.GenerateStaticKey()
	require.NoError(t, err)
	defer remote.Destroy()

	v2 := &PairedDevice{
		Name:                       "bound",
		Address:                    "00:11:22:33:44:55",
		LocalNoisePrivateKey:       base64.StdEncoding.EncodeToString(raw),
		NoisePublicKey:             base64.StdEncoding.EncodeToString(remote.Public),
		DeviceFingerprint:          hex.EncodeToString(dak.Fingerprint()),
		AttestationProtocolVersion: phone.AttestProtocolV2,
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
		assert.Equal(t, remote.Public, cfg.ExpectedRemoteStatic)
		assert.True(t, cfg.OwnsStaticKey,
			"these helpers keep nothing, so the backend must own the key or it is never released")
	})

	t.Run("a legacy record demands nothing but still binds what it has", func(t *testing.T) {
		legacy := *v2
		legacy.AttestationProtocolVersion = 0

		cfg, err := newPairedDeviceBackendConfig(&legacy, time.Minute, logger)
		require.NoError(t, err)
		defer cfg.LocalStaticKey.Destroy()

		assert.False(t, cfg.RequireLiveAttestation,
			"a pairing predating #129 has no attested key to prove possession of")
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

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
// for non-commercial use. Commercial licenses are available.
// See LICENSE and LICENSE-COMMERCIAL for details.

package attesttest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
)

// This file is the in-memory phone the pairing surfaces are tested against.
//
// It used to live in the command package's #129 interop test alone. The GUI
// pairs phones too (#115), and it needs the same responder: a real Noise XX
// peer with a persistent attested key, answering the same wire methods. A
// second copy in the GUI's test package would have been a second reading of
// the wire contract that could drift from the first without either noticing,
// which is exactly what this package exists to prevent.
//
// Nothing here is a byte-echoing stub. The phone runs a real
// bootstrap.NoiseSession as the XX responder, derives its own channel binding
// from its own session, and signs a transcript it lays out itself. So a green
// run means two independent implementations agreed on the prologue, the
// channel binding, the transcript layout and the fingerprint derivation — the
// four values that must match on the wire or nothing connects.

// MemTransport is an in-memory pairingproto.Transport: a crossed pair carries the
// initiator's bytes to the responder and back.
type MemTransport struct {
	rx <-chan []byte
	tx chan<- []byte
}

// NewMemTransportPair returns the two crossed ends of one in-memory link.
func NewMemTransportPair() (initiator, responder *MemTransport) {
	a2b := make(chan []byte, 8)
	b2a := make(chan []byte, 8)
	return &MemTransport{rx: b2a, tx: a2b}, &MemTransport{rx: a2b, tx: b2a}
}

// Send queues one message for the other end.
func (t *MemTransport) Send(ctx context.Context, m []byte) error {
	select {
	case t.tx <- m:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Receive waits for one message from the other end.
func (t *MemTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case m := <-t.rx:
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// SendAndReceive sends one message and waits for the reply.
func (t *MemTransport) SendAndReceive(ctx context.Context, m []byte) ([]byte, error) {
	if err := t.Send(ctx, m); err != nil {
		return nil, err
	}
	return t.Receive(ctx)
}

// IsConnected always reports true: an in-memory link has no radio to lose.
func (t *MemTransport) IsConnected() bool { return true }

// Close is a no-op: the channels are garbage collected with the pair.
func (t *MemTransport) Close() error { return nil }

// Phone plays xkey-android: a persistent attested key, a real Noise XX
// responder, and handlers for the encrypted methods a desktop sends while
// pairing and reconnecting.
//
// It holds the DAK across sessions on purpose — that persistence is the whole
// of #129, and a phone that regenerated the key per connection would fail the
// reconnect leg exactly as the old model did.
type Phone struct {
	// DAK is the device attestation key. Tests swap it to model a relay that
	// presents a genuine chain it does not hold the key for.
	DAK *DAK

	// EchoFingerprint is what the phone reports in the identity exchange for a
	// KNOWN device. It is stored at pairing, mirroring the Android side, so
	// that reconnect compares a value the phone kept rather than one it
	// recomputes on demand.
	EchoFingerprint []byte

	// Name is what the phone calls itself when it confirms a pairing.
	Name string

	// Mutate, when set, damages the otherwise contract-faithful attestation
	// response just before it is sent. It is how the negative cases model a
	// device that answers but cannot prove what it claims — the damage happens
	// on the WIRE, after a correct response was built, so nothing about the
	// honest path is bypassed to produce it.
	Mutate func(*pairingproto.LocalAttestDeviceResult)

	// staticKey is the phone's PERSISTENT Noise identity, the one written into
	// the pairing record. It must be the same key on every leg: production
	// reuses the paired static keys, and a phone that generated a fresh one per
	// connection would not be reconnecting at all — it would be pairing again,
	// which is a different code path with different bindings. A test that
	// rotates the identity it is meant to persist cannot see a break in
	// reconnecting with persisted keys. (Codex, #124.)
	staticKey *bootstrap.NoiseStaticKey

	// staticPub is a COPY of the static key's public half, taken at
	// construction. The responder goroutine derives its channel binding from
	// it, and must not read staticKey: that key is wiped by t.Cleanup when the
	// test ends, and a goroutine still running at that moment reads bytes
	// being zeroed underneath it. Measured as a data race under -race in CI,
	// and it is a real lifetime bug rather than a test artefact — the same
	// shape as reading a destroyed key on a slow shutdown.
	staticPub []byte
}

// NewPhone builds a phone with a persistent Noise identity and a persistent
// attested key — the two things a real handset keeps across connections, and
// the two the pairing tests exist to exercise.
func NewPhone(t *testing.T, dak *DAK) *Phone {
	t.Helper()

	key, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)
	t.Cleanup(key.Destroy)

	return &Phone{
		DAK:       dak,
		Name:      "attesttest phone",
		staticKey: key,
		staticPub: key.PublicBytes(),
	}
}

// NewPairedPhone is NewPhone for a device that is already paired: it carries
// the fingerprint it stored at pairing and echoes that on reconnect.
//
// Every phone needs a persistent Noise identity, so construction goes through
// here rather than a struct literal — a phone with no static key is not a
// device that reconnects, it is a device that pairs again.
func NewPairedPhone(t *testing.T, dak *DAK, echoFingerprint []byte) *Phone {
	t.Helper()

	p := NewPhone(t, dak)
	p.EchoFingerprint = echoFingerprint
	return p
}

// StaticPublicKey is the phone's persistent Noise identity, as a desktop
// records it at pairing.
func (p *Phone) StaticPublicKey() []byte { return append([]byte(nil), p.staticPub...) }

// Serve runs one connection on its own goroutine: identity exchange, Noise XX
// responder, then exchanges of encrypted JSON-RPC. It reports the first
// failure on done and returns.
//
// known selects the identity-ack branch: false is a first pairing (the phone
// has no record of this desktop), true is a reconnect.
func (p *Phone) Serve(ctx context.Context, t *testing.T, tr *MemTransport, known bool, exchanges int, done chan<- error) {
	t.Helper()

	go func() {
		done <- p.Run(ctx, tr, known, exchanges)
	}()
}

// Run takes the CALLER's context rather than making its own, so a caller that
// finishes early can stop the responder deterministically instead of leaving it
// blocked on a receive that will never come. A goroutine outliving its subtest
// is what let t.Cleanup wipe the static key under it.
func (p *Phone) Run(ctx context.Context, tr *MemTransport, known bool, exchanges int) error {
	// 1. Identity exchange. The initiator sends [0x01, pubkey(32)].
	idMsg, err := tr.Receive(ctx)
	if err != nil {
		return err
	}
	if len(idMsg) != pairingproto.IdentityMsgSize || idMsg[0] != pairingproto.IdentityMsgVersion {
		return fmt.Errorf("bad identity message: len=%d", len(idMsg))
	}
	initiatorPub := append([]byte(nil), idMsg[1:]...)

	// 2. Answer as a known or a new device, and compute the prologue the same
	//    way the initiator does. An empty prologue is the first-pairing case.
	var prologue []byte
	if known {
		if err := tr.Send(ctx, append([]byte{pairingproto.IdentityAckKnown}, p.EchoFingerprint...)); err != nil {
			return err
		}
		prologue = Prologue(initiatorPub, p.EchoFingerprint)
	} else {
		if err := tr.Send(ctx, []byte{pairingproto.IdentityAckUnknown}); err != nil {
			return err
		}
	}

	// 3. Real Noise XX responder.
	sess, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{
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
	//    left the test green, because both sides computed the same wrong
	//    value and the signature verified. Measured — and the xkey-android
	//    lane hit the identical hazard in its own E2E test. Deriving by hand
	//    here makes the phone an independent oracle, exactly as the DAK lays
	//    out the transcript by hand rather than calling BuildAttestTranscript.
	binding := ChannelBinding(initiatorPub, p.staticPub, prologue)

	// 5. Serve the encrypted exchanges.
	for i := 0; i < exchanges; i++ {
		if err := p.serveExchange(ctx, tr, sess, binding); err != nil {
			return err
		}
	}
	return nil
}

// exchangeHandler answers one decoded request. The binding is the channel
// binding this phone derived for the session the request arrived on.
type exchangeHandler func(p *Phone, req *pairingproto.Request, binding []byte) (any, error)

// exchangeHandlers routes a request by method. A method a real handset would
// refuse is refused here too: the loop returns an error rather than inventing
// an answer, so a desktop that sends something unexpected fails the test
// instead of being humoured.
var exchangeHandlers = map[string]exchangeHandler{
	pairingproto.MethodPairingConfirm:    (*Phone).confirmPairing,
	pairingproto.MethodLocalAttestDevice: (*Phone).attestDevice,
}

// serveExchange handles one encrypted JSON-RPC round trip.
func (p *Phone) serveExchange(
	ctx context.Context,
	tr *MemTransport,
	sess *bootstrap.NoiseSession,
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

	req, err := pairingproto.DecodeRequest(plaintext)
	if err != nil {
		return err
	}
	handler, ok := exchangeHandlers[req.Method]
	if !ok {
		return fmt.Errorf("unexpected method %q", req.Method)
	}
	result, err := handler(p, req, binding)
	if err != nil {
		return err
	}

	response, err := pairingproto.EncodeResponse(req.ID, result)
	if err != nil {
		return err
	}
	out, err := sess.Encrypt(response)
	if err != nil {
		return err
	}
	return tr.Send(ctx, out)
}

// confirmPairing answers pairing.confirm the way a handset whose user tapped
// "pair" does.
func (p *Phone) confirmPairing(req *pairingproto.Request, _ []byte) (any, error) {
	var params pairingproto.PairingConfirmParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.PublicKeyHex == "" {
		return nil, fmt.Errorf("pairing.confirm carried no desktop public key")
	}
	return &pairingproto.PairingConfirmResult{Confirmed: true, DeviceName: p.Name}, nil
}

// attestDevice answers local.attestDevice by signing the challenge with the
// persistent attested key.
func (p *Phone) attestDevice(req *pairingproto.Request, binding []byte) (any, error) {
	var params pairingproto.LocalAttestDeviceParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.ProtocolVersion != pairingproto.AttestProtocolV2 {
		return nil, fmt.Errorf("desktop asked for protocol version %d", params.ProtocolVersion)
	}

	// The phone signs the binding IT derived, not the one it was handed. A
	// prover that echoed the desktop's channelBinding parameter back into its
	// transcript would pass this test while proving nothing about the two
	// derivations agreeing — and would hand a relay attacker exactly the
	// signature the binding exists to deny. This is the one place the fixture
	// deliberately ignores a field the request carries.
	sig, err := p.DAK.SignRaw(params.Purpose, params.Nonce, binding)
	if err != nil {
		return nil, err
	}

	result := &pairingproto.LocalAttestDeviceResult{
		ProtocolVersion:    pairingproto.AttestProtocolV2,
		Format:             "android-keystore",
		CertificateChain:   p.DAK.Chain,
		SecurityLevel:      "strongbox",
		Nonce:              params.Nonce,
		Purpose:            params.Purpose,
		Signature:          sig,
		SignatureAlgorithm: pairingproto.AttestSignatureES256,
	}

	if p.Mutate != nil {
		p.Mutate(result)
	}
	return result, nil
}

// decodeParams re-marshals the generic JSON params into the wire struct, the
// same way any responder must.
func decodeParams(req *pairingproto.Request, into any) error {
	raw, err := json.Marshal(req.Params)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

// ChannelBinding mirrors the published channel-binding derivation (§5 of the
// wire contract), spelled out rather than borrowed from the package under
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
func ChannelBinding(initiatorPub, responderPub, prologue []byte) []byte {
	h := sha256.New()
	h.Write([]byte(pairingproto.AttestChannelBindingDomain))
	h.Write([]byte{byte(len(initiatorPub))})
	h.Write(initiatorPub)
	h.Write([]byte{byte(len(responderPub))})
	h.Write(responderPub)
	h.Write([]byte{byte(len(prologue))})
	h.Write(prologue)
	return h.Sum(nil)
}

// Prologue mirrors the initiator's prologue derivation:
// SHA256(initiatorPublicKey || deviceFingerprint || "xkey-v1").
//
// It is spelled out rather than borrowed from the package under test on
// purpose: the phone has to derive this value independently on the wire, and a
// test that called the desktop's own helper could not notice the two drifting
// apart.
func Prologue(initiatorPub, fingerprint []byte) []byte {
	h := sha256.New()
	h.Write(initiatorPub)
	h.Write(fingerprint)
	h.Write([]byte("xkey-v1"))
	return h.Sum(nil)
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
)

var errPipeClosed = &MessageError{Msg: "pipe closed"}

// pipe is one end of an in-memory, message-framed duplex connection. Closing
// either end closes both, as a TCP connection does, which is what wakes the
// router's receive loop during teardown.
type pipe struct {
	in     <-chan []byte
	out    chan<- []byte
	closed chan struct{}
	once   *sync.Once
}

func newPipePair() (probeEnd, phoneEnd *pipe) {
	toPhone, toProbe := make(chan []byte, 16), make(chan []byte, 16)
	closed, once := make(chan struct{}), &sync.Once{}
	return &pipe{in: toProbe, out: toPhone, closed: closed, once: once},
		&pipe{in: toPhone, out: toProbe, closed: closed, once: once}
}

func (p *pipe) Send(ctx context.Context, message []byte) error {
	select {
	case p.out <- append([]byte(nil), message...):
		return nil
	case <-p.closed:
		return errPipeClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *pipe) Receive(ctx context.Context) ([]byte, error) {
	select {
	case message := <-p.in:
		return message, nil
	case <-p.closed:
		return nil, errPipeClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *pipe) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	if err := p.Send(ctx, message); err != nil {
		return nil, err
	}
	return p.Receive(ctx)
}

func (p *pipe) IsConnected() bool {
	select {
	case <-p.closed:
		return false
	default:
		return true
	}
}

func (p *pipe) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// answerFunc encodes the phone's answer to one decoded request.
type answerFunc func(req *pairingproto.Request) ([]byte, error)

// serve plays the handset side of a first pairing over tr, a Noise XX
// responder, then answers every request with answer until the probe hangs up.
func serve(ctx context.Context, tr *pipe, answer answerFunc) error {
	identity, err := tr.Receive(ctx)
	if err != nil {
		return err
	}
	if len(identity) != pairingproto.IdentityMsgSize {
		return &MessageError{Msg: "bad identity message"}
	}
	if err := tr.Send(ctx, []byte{pairingproto.IdentityAckUnknown}); err != nil {
		return err
	}

	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: false})
	if err != nil {
		return err
	}
	if err := session.InitHandshake(); err != nil {
		return err
	}
	msg1, err := tr.Receive(ctx)
	if err != nil {
		return err
	}
	msg2, _, err := session.HandshakeMessage(msg1)
	if err != nil {
		return err
	}
	if err := tr.Send(ctx, msg2); err != nil {
		return err
	}
	msg3, err := tr.Receive(ctx)
	if err != nil {
		return err
	}
	if _, _, err := session.HandshakeMessage(msg3); err != nil {
		return err
	}

	for {
		ciphertext, err := tr.Receive(ctx)
		if err != nil {
			return nil // the probe hung up
		}
		plaintext, err := session.Decrypt(ciphertext)
		if err != nil {
			return err
		}
		req, err := pairingproto.DecodeRequest(plaintext)
		if err != nil {
			return err
		}
		response, err := answer(req)
		if err != nil {
			return err
		}
		sealed, err := session.Encrypt(response)
		if err != nil {
			return err
		}
		if err := tr.Send(ctx, sealed); err != nil {
			return nil
		}
	}
}

// answerAs answers every request the way the fake phone ph does.
func answerAs(ph *phone) answerFunc {
	var mu sync.Mutex
	return func(req *pairingproto.Request) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		result, err := ph.call(req.Method, req.Params)
		if err != nil {
			return pairingproto.EncodeErrorResponse(req.ID, req.Generation, -32000, err.Error(), nil)
		}
		return pairingproto.EncodeResponse(req.ID, req.Generation, result)
	}
}

// noiseStaticKey generates the probe's Noise static key. It is X25519, which
// fips140=only refuses: there ok is false once the refusal is asserted and the
// test has re-run itself under fips140=off, and the caller returns.
func noiseStaticKey(t *testing.T) (key *bootstrap.NoiseStaticKey, ok bool) {
	t.Helper()
	key, err := bootstrap.GenerateNoiseStaticKey()
	if !fipstest.OutsideFIPSAfterRefusal(t, err, nil) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("generate static key: %v", err)
	}
	return key, true
}

// runProbe runs probe against a handset answering with answer, and returns
// probe's verdict and output once both sides have finished. The last result is
// false when fips140=only refused the Noise key (see noiseStaticKey).
func runProbe(t *testing.T, answer answerFunc) (bool, string, bool) {
	t.Helper()
	return runProbeIn(t, context.Background(), answer)
}

// runProbeIn is runProbe with the probe and the fake phone bound to parent,
// so a test can give the whole run a deadline.
func runProbeIn(t *testing.T, parent context.Context, answer answerFunc) (bool, string, bool) {
	t.Helper()
	staticKey, ok := noiseStaticKey(t)
	if !ok {
		return false, "", false
	}
	probeEnd, phoneEnd := newPipePair()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	served := make(chan error, 1)
	go func() { served <- serve(ctx, phoneEnd, answer) }()

	var out bytes.Buffer
	passed := probe(ctx, probeEnd, staticKey, slog.New(slog.NewTextHandler(io.Discard, nil)), &out)
	if err := <-served; err != nil {
		t.Fatalf("phone side: %v", err)
	}
	if probeEnd.IsConnected() {
		t.Fatal("probe returned without closing the transport")
	}
	return passed, out.String(), true
}

func TestProbe_PassesOverARealPairingSession(t *testing.T) {
	passed, out, ok := runProbe(t, answerAs(conformantPhone(t)))
	if !ok {
		return
	}

	if !passed {
		t.Fatalf("probe failed against a conformant phone:\n%s", out)
	}
	for _, want := range []string{"OK   noise handshake", "[PASS] pairing.confirm", "E2E PASSED"} {
		if !strings.Contains(out, want) {
			t.Fatalf("probe output lacks %q:\n%s", want, out)
		}
	}
}

func TestProbe_FailsAStepOnAMalformedResult(t *testing.T) {
	conformant := answerAs(conformantPhone(t))
	answer := func(req *pairingproto.Request) ([]byte, error) {
		if req.Method == "ping" {
			return json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": req.ID, "generation": req.Generation, "result": "pong"})
		}
		return conformant(req)
	}

	passed, out, ok := runProbe(t, answer)
	if !ok {
		return
	}

	if passed {
		t.Fatalf("probe passed although ping returned a non-object result:\n%s", out)
	}
	if !strings.Contains(out, "[FAIL] ping  -> malformed rpc result for ping") {
		t.Fatalf("probe output does not fail ping as malformed:\n%s", out)
	}
}

// A phone that answers without echoing the request's generation is answering
// nobody: the router drops the response (issue #128). The probe must fail
// that step with a typed no-response error inside its deadline, not wait on
// it forever.
func TestProbe_FailsAStepWhoseResponseIsNeverRouted(t *testing.T) {
	conformant := answerAs(conformantPhone(t))
	answer := func(req *pairingproto.Request) ([]byte, error) {
		if req.Method == "ping" {
			return pairingproto.EncodeResponse(req.ID, 0, map[string]string{"status": "pong"})
		}
		return conformant(req)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	passed, out, ok := runProbeIn(t, ctx, answer)
	if !ok {
		return
	}

	if passed {
		t.Fatalf("probe passed although ping was never answered:\n%s", out)
	}
	if !strings.Contains(out, "[FAIL] ping  -> no routable response to ping") {
		t.Fatalf("probe output does not fail ping as unanswered:\n%s", out)
	}
}

func TestProbe_FailsWhenTheHandshakeFails(t *testing.T) {
	staticKey, ok := noiseStaticKey(t)
	if !ok {
		return
	}
	probeEnd, phoneEnd := newPipePair()
	// The handset hangs up before answering the identity message.
	if err := phoneEnd.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	var out bytes.Buffer

	passed := probe(context.Background(), probeEnd, staticKey, slog.New(slog.NewTextHandler(io.Discard, nil)), &out)

	if passed {
		t.Fatal("probe passed without a handshake")
	}
	if !strings.Contains(out.String(), "FAIL noise handshake") {
		t.Fatalf("probe output = %q, want the handshake failure", out.String())
	}
}

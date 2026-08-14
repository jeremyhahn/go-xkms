// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package usb

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePhone stands in for the Android USB responder. It answers the
// pre-handshake identity exchange, completes the Noise XX handshake as the
// responder, and then serves JSON-RPC requests from handler.
type fakePhone struct {
	connectErr  error
	closeErr    error
	connected   bool
	fingerprint []byte // nil replies "unknown device" to the identity exchange
	handler     func(*phone.Request) *phone.Response

	session   *phone.NoiseSession
	handshook bool
	outbox    [][]byte
	sendErr   error
}

func (f *fakePhone) Connect(_ context.Context) error {
	if f.connectErr != nil {
		return f.connectErr
	}
	f.connected = true
	return nil
}

func (f *fakePhone) Close() error {
	f.connected = false
	return f.closeErr
}

func (f *fakePhone) IsConnected() bool { return f.connected }

func (f *fakePhone) Send(_ context.Context, message []byte) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	reply, err := f.respond(message)
	if err != nil {
		return err
	}
	if reply != nil {
		f.outbox = append(f.outbox, reply)
	}
	return nil
}

func (f *fakePhone) Receive(_ context.Context) ([]byte, error) {
	if len(f.outbox) == 0 {
		return nil, errors.New("fake phone: nothing to receive")
	}
	msg := f.outbox[0]
	f.outbox = f.outbox[1:]
	return msg, nil
}

func (f *fakePhone) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	if err := f.Send(ctx, message); err != nil {
		return nil, err
	}
	return f.Receive(ctx)
}

// respond produces the responder's reply to one inbound message, or nil when
// the message completes the handshake and needs no answer.
func (f *fakePhone) respond(message []byte) ([]byte, error) {
	// Identity exchange: [0x01, 32-byte public key].
	if f.session == nil {
		if len(message) != pairing.IdentityMsgSize || message[0] != pairing.IdentityMsgVersion {
			return nil, errors.New("fake phone: expected identity message")
		}
		session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{IsInitiator: false})
		if err != nil {
			return nil, err
		}
		if len(f.fingerprint) > 0 {
			session.SetPrologue(testPrologue(message[1:], f.fingerprint))
		}
		if err := session.InitHandshake(); err != nil {
			return nil, err
		}
		f.session = session
		if len(f.fingerprint) == 0 {
			return []byte{pairing.IdentityAckUnknown}, nil
		}
		return append([]byte{pairing.IdentityAckKnown}, f.fingerprint...), nil
	}

	if !f.handshook {
		outgoing, complete, err := f.session.HandshakeMessage(message)
		if err != nil {
			return nil, err
		}
		f.handshook = complete
		if len(outgoing) == 0 {
			return nil, nil
		}
		return outgoing, nil
	}

	plaintext, err := f.session.Decrypt(message)
	if err != nil {
		return nil, err
	}
	req, err := phone.DecodeRequest(plaintext)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(f.handler(req))
	if err != nil {
		return nil, err
	}
	return f.session.Encrypt(encoded)
}

// testPrologue mirrors the prologue the handshake derives from the identity
// exchange: SHA256(public key || fingerprint || "xkey-v1").
func testPrologue(publicKey, fingerprint []byte) []byte {
	h := sha256.New()
	h.Write(publicKey)
	h.Write(fingerprint)
	h.Write([]byte("xkey-v1"))
	return h.Sum(nil)
}

// newPairedTransport returns a transport whose Noise handshake has completed
// against the fake phone, ready to serve requests.
func newPairedTransport(t *testing.T, fake *fakePhone) *Transport {
	t.Helper()

	key, err := phone.GenerateStaticKey()
	require.NoError(t, err)

	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = fake
	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: key.Private})

	require.NoError(t, tr.Connect(context.Background()))
	return tr
}

func TestNew(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.NotNil(t, tr.Config())
	assert.Equal(t, 30*time.Second, tr.Config().Timeout)
}

func TestNewWithOptions(t *testing.T) {
	tr, err := New(func(cfg *transport.Config) error {
		cfg.Timeout = 5 * time.Second
		return nil
	})
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Equal(t, 5*time.Second, tr.Config().Timeout)
}

func TestNewWithBadOption(t *testing.T) {
	tr, err := New(func(cfg *transport.Config) error {
		return assert.AnError
	})
	require.Error(t, err)
	assert.Nil(t, tr)
}

func TestNewWithConfig(t *testing.T) {
	cfg := &transport.Config{Timeout: 10 * time.Second}
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Equal(t, 10*time.Second, tr.Config().Timeout)
}

func TestNewWithConfigNil(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Equal(t, 30*time.Second, tr.Config().Timeout)
}

// TestConnectWithoutNoiseConfig proves the transport refuses to speak
// plaintext: without pairing keys it fails before touching the bus rather than
// sending JSON the phone would read as a malformed handshake message.
func TestConnectWithoutNoiseConfig(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	fake := &fakePhone{}
	tr.phoneUSB = fake

	err = tr.Connect(context.Background())
	require.ErrorIs(t, err, ErrNoiseNotConfigured)
	assert.False(t, tr.connected)
	assert.False(t, fake.connected, "the bus must not be opened without pairing keys")
}

func TestConnectWithInvalidPrivateKey(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = &fakePhone{}
	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: []byte{0x01, 0x02}})

	err = tr.Connect(context.Background())
	require.ErrorIs(t, err, ErrNoiseNotConfigured)
}

func TestConnectPerformsIdentityExchangeAndHandshake(t *testing.T) {
	fake := &fakePhone{}
	tr := newPairedTransport(t, fake)

	assert.True(t, tr.connected)
	assert.True(t, fake.handshook, "the phone side must complete the Noise XX handshake")
	assert.True(t, tr.Healthy(context.Background()))
}

func TestConnectBindsDeviceFingerprintIntoPrologue(t *testing.T) {
	fingerprint := make([]byte, 32)
	for i := range fingerprint {
		fingerprint[i] = byte(i)
	}

	key, err := phone.GenerateStaticKey()
	require.NoError(t, err)

	tr, err := New()
	require.NoError(t, err)
	fake := &fakePhone{fingerprint: fingerprint}
	tr.phoneUSB = fake
	tr.WithNoiseConfig(&NoiseConfig{
		LocalStaticPrivateKey:     key.Private,
		ExpectedDeviceFingerprint: fingerprint,
	})

	require.NoError(t, tr.Connect(context.Background()))
	assert.True(t, fake.handshook)
}

func TestConnectRejectsFingerprintMismatch(t *testing.T) {
	phoneFingerprint := make([]byte, 32)
	expected := make([]byte, 32)
	expected[0] = 0xff

	key, err := phone.GenerateStaticKey()
	require.NoError(t, err)

	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = &fakePhone{fingerprint: phoneFingerprint}
	tr.WithNoiseConfig(&NoiseConfig{
		LocalStaticPrivateKey:     key.Private,
		ExpectedDeviceFingerprint: expected,
	})

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrConnectionFailed)
	assert.False(t, tr.connected)
}

func TestConnectFailsWhenBusUnavailable(t *testing.T) {
	key, err := phone.GenerateStaticKey()
	require.NoError(t, err)

	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = &fakePhone{connectErr: errors.New("no accessory")}
	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: key.Private})

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrConnectionFailed)
}

func TestCloseNotConnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	assert.NoError(t, tr.Close())
	assert.False(t, tr.connected)
}

func TestCloseClearsSession(t *testing.T) {
	tr := newPairedTransport(t, &fakePhone{})
	require.NoError(t, tr.Close())
	assert.False(t, tr.connected)
	assert.Nil(t, tr.session)
}

func TestCloseWithPhoneUSBError(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = &fakePhone{connected: true, closeErr: errors.New("close failed")}
	tr.connected = true
	err = tr.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "close failed")
}

func TestHealthyNotConnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	assert.False(t, tr.Healthy(context.Background()))
}

func TestHealthyConnectedButNilPhoneUSB(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.connected = true
	assert.False(t, tr.Healthy(context.Background()))
}

func TestHealthyConnectedButPhoneUSBDisconnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = &fakePhone{connected: false}
	tr.connected = true
	assert.False(t, tr.Healthy(context.Background()))
}

func TestConnNotConnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	assert.Nil(t, tr.Conn())
}

func TestConnWithPhoneUSB(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	fake := &fakePhone{connected: true}
	tr.phoneUSB = fake
	assert.Equal(t, fake, tr.Conn())
}

func TestRequestNotConnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	err = tr.Request(context.Background(), "test", nil, nil)
	require.ErrorIs(t, err, ErrNotConnected)
}

// TestRequestWithoutSession proves a request cannot slip out in plaintext on a
// transport marked connected without a completed handshake.
func TestRequestWithoutSession(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = &fakePhone{connected: true}
	tr.connected = true
	err = tr.Request(context.Background(), "test", nil, nil)
	require.ErrorIs(t, err, ErrNotConnected)
}

func TestRequestMarshalError(t *testing.T) {
	tr := newPairedTransport(t, &fakePhone{})

	// Channels cannot be marshalled to JSON.
	err := tr.Request(context.Background(), "test", make(chan int), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrInvalidRequest)
}

// TestRequestSendsJSONRPCEnvelope pins the wire shape the phone expects: a
// JSON-RPC 2.0 envelope carrying the method name, not the bare request body.
func TestRequestSendsJSONRPCEnvelope(t *testing.T) {
	var seen *phone.Request
	fake := &fakePhone{
		handler: func(req *phone.Request) *phone.Response {
			seen = req
			result, _ := json.Marshal(map[string]string{"status": "ok"})
			return &phone.Response{JSONRPC: "2.0", ID: req.ID, Result: result}
		},
	}
	tr := newPairedTransport(t, fake)

	var resp struct {
		Status string `json:"status"`
	}
	require.NoError(t, tr.Request(context.Background(), "getInfo", map[string]string{"key": "val"}, &resp))

	require.NotNil(t, seen)
	assert.Equal(t, "2.0", seen.JSONRPC)
	assert.Equal(t, "getInfo", seen.Method)
	assert.NotZero(t, seen.ID)
	assert.Equal(t, "ok", resp.Status)
}

func TestRequestNilResponseTarget(t *testing.T) {
	fake := &fakePhone{
		handler: func(req *phone.Request) *phone.Response {
			result, _ := json.Marshal(map[string]bool{"pong": true})
			return &phone.Response{JSONRPC: "2.0", ID: req.ID, Result: result}
		},
	}
	tr := newPairedTransport(t, fake)

	require.NoError(t, tr.Request(context.Background(), "ping", nil, nil))
	assert.True(t, tr.connected)
}

func TestRequestPropagatesRPCError(t *testing.T) {
	fake := &fakePhone{
		handler: func(req *phone.Request) *phone.Response {
			return &phone.Response{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &phone.RPCError{Code: -32601, Message: "Method not supported"},
			}
		},
	}
	tr := newPairedTransport(t, fake)

	err := tr.Request(context.Background(), "nope", nil, nil)
	require.ErrorIs(t, err, ErrRequestFailed)
	assert.Contains(t, err.Error(), "Method not supported")
}

func TestRequestSendReceiveError(t *testing.T) {
	fake := &fakePhone{}
	tr := newPairedTransport(t, fake)
	fake.sendErr = errors.New("send failed")

	err := tr.Request(context.Background(), "test", "hello", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrConnectionFailed)
	assert.False(t, tr.connected)
}

func TestRequestUnmarshalError(t *testing.T) {
	fake := &fakePhone{
		handler: func(req *phone.Request) *phone.Response {
			return &phone.Response{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`"a string"`)}
		},
	}
	tr := newPairedTransport(t, fake)

	var resp struct {
		Status string `json:"status"`
	}
	err := tr.Request(context.Background(), "test", "hello", &resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrInvalidResponse)
}

func TestRequestStreamNotSupported(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	s, err := tr.RequestStream(context.Background(), "test", nil)
	require.Error(t, err)
	assert.Nil(t, s)
	assert.ErrorIs(t, err, ErrStreamNotSupported)
}

func TestPasswordOperationsNotSupported(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"PasswordAdd", func() error { _, e := tr.PasswordAdd(ctx, nil); return e }},
		{"PasswordGet", func() error { _, e := tr.PasswordGet(ctx, nil); return e }},
		{"PasswordList", func() error { _, e := tr.PasswordList(ctx, nil); return e }},
		{"PasswordUpdate", func() error { return tr.PasswordUpdate(ctx, nil) }},
		{"PasswordDelete", func() error { return tr.PasswordDelete(ctx, nil) }},
		{"PasswordStoreUnlock", func() error { return tr.PasswordStoreUnlock(ctx, nil) }},
		{"PasswordStoreLock", func() error { return tr.PasswordStoreLock(ctx) }},
		{"PasswordStoreStatus", func() error { _, e := tr.PasswordStoreStatus(ctx); return e }},
		{"PasswordStoreSetAccessMode", func() error { return tr.PasswordStoreSetAccessMode(ctx, nil) }},
		{"PasswordGenerate", func() error { _, e := tr.PasswordGenerate(ctx, nil); return e }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.ErrorIs(t, err, ErrNotSupported)
		})
	}
}

func TestSealStoreOperationsNotSupported(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"SealStorePut", func() error { return tr.SealStorePut(ctx, nil) }},
		{"SealStoreGet", func() error { _, e := tr.SealStoreGet(ctx, nil); return e }},
		{"SealStoreDelete", func() error { return tr.SealStoreDelete(ctx, nil) }},
		{"SealStoreList", func() error { _, e := tr.SealStoreList(ctx); return e }},
		{"SealStoreReseal", func() error { return tr.SealStoreReseal(ctx, nil) }},
		{"SealStoreStatus", func() error { _, e := tr.SealStoreStatus(ctx); return e }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.ErrorIs(t, err, ErrNotSupported)
		})
	}
}

func TestPolicyOperationsNotSupported(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"PolicyCreate", func() error { _, e := tr.PolicyCreate(ctx, nil); return e }},
		{"PolicyGet", func() error { _, e := tr.PolicyGet(ctx, nil); return e }},
		{"PolicyList", func() error { _, e := tr.PolicyList(ctx); return e }},
		{"PolicyDelete", func() error { return tr.PolicyDelete(ctx, nil) }},
		{"PolicyRefresh", func() error { _, e := tr.PolicyRefresh(ctx, nil); return e }},
		{"PolicyVerify", func() error { _, e := tr.PolicyVerify(ctx, nil); return e }},
		{"PolicyExport", func() error { _, e := tr.PolicyExport(ctx, nil); return e }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.ErrorIs(t, err, ErrNotSupported)
		})
	}
}

// TestConnectFailsWithoutUSBDevice covers the real driver path: with pairing
// keys configured but no accessory attached, the bus open fails.
func TestConnectFailsWithoutUSBDevice(t *testing.T) {
	key, err := phone.GenerateStaticKey()
	require.NoError(t, err)

	tr, err := New()
	require.NoError(t, err)
	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: key.Private})

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrConnectionFailed)
	assert.False(t, tr.connected)
}

func TestConnectWithCustomTimeout(t *testing.T) {
	key, err := phone.GenerateStaticKey()
	require.NoError(t, err)

	tr, err := New(func(cfg *transport.Config) error {
		cfg.Timeout = 1 * time.Second
		return nil
	})
	require.NoError(t, err)
	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: key.Private})

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrConnectionFailed)
}

func TestConnectWithZeroTimeout(t *testing.T) {
	key, err := phone.GenerateStaticKey()
	require.NoError(t, err)

	tr, err := NewWithConfig(&transport.Config{Timeout: 0})
	require.NoError(t, err)
	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: key.Private})

	err = tr.Connect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrConnectionFailed)
}

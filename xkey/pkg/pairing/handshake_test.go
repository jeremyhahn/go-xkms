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

package pairing

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errMockSend is returned by the mock transport when Send is configured to fail.
var errMockSend = errors.New("mock: send failure")

// errMockRecv is returned by the mock transport when Receive is configured to fail.
var errMockRecv = errors.New("mock: receive failure")

// mockPipeTransport implements Transport using a pair of channels.
// One side writes to sendCh and reads from recvCh. A paired transport
// reads from the first's sendCh and writes to its recvCh, forming a
// bidirectional in-memory pipe.
type mockPipeTransport struct {
	sendCh    chan []byte
	recvCh    chan []byte
	connected atomic.Bool
	closed    atomic.Bool

	// sendErr, if non-nil, is returned from Send instead of writing to sendCh.
	sendErr error
	// recvErr, if non-nil, is returned from Receive instead of reading from recvCh.
	recvErr error
}

func (m *mockPipeTransport) Send(_ context.Context, message []byte) error {
	if m.closed.Load() {
		return ErrBackendClosed
	}
	if !m.connected.Load() {
		return ErrNotConnected
	}
	if m.sendErr != nil {
		return m.sendErr
	}
	cp := make([]byte, len(message))
	copy(cp, message)
	m.sendCh <- cp
	return nil
}

func (m *mockPipeTransport) Receive(_ context.Context) ([]byte, error) {
	if m.closed.Load() {
		return nil, ErrBackendClosed
	}
	if !m.connected.Load() {
		return nil, ErrNotConnected
	}
	if m.recvErr != nil {
		return nil, m.recvErr
	}
	msg, ok := <-m.recvCh
	if !ok {
		return nil, ErrNotConnected
	}
	return msg, nil
}

func (m *mockPipeTransport) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	if err := m.Send(ctx, message); err != nil {
		return nil, err
	}
	return m.Receive(ctx)
}

func (m *mockPipeTransport) IsConnected() bool {
	return m.connected.Load() && !m.closed.Load()
}

func (m *mockPipeTransport) Close() error {
	if m.closed.Swap(true) {
		return nil
	}
	m.connected.Store(false)
	return nil
}

// newPipeTransports creates a connected pair of mock transports.
func newPipeTransports() (*mockPipeTransport, *mockPipeTransport) {
	ch1 := make(chan []byte, 10)
	ch2 := make(chan []byte, 10)

	initiator := &mockPipeTransport{sendCh: ch1, recvCh: ch2}
	responder := &mockPipeTransport{sendCh: ch2, recvCh: ch1}

	initiator.connected.Store(true)
	responder.connected.Store(true)

	return initiator, responder
}

// ---------------------------------------------------------------------------
// runResponder drives the responder side of a Noise XX handshake in lockstep
// with PerformHandshake on the initiator side. It reads msg1 from
// responderRecvCh (which is initiator's sendCh), processes it, writes msg2 to
// responderSendCh (which is initiator's recvCh), reads msg3, and finalizes.
// This variant does NOT handle identity exchange (for direct PerformHandshake tests).
// ---------------------------------------------------------------------------
func runResponder(t *testing.T, transport *mockPipeTransport) *NoiseSession {
	t.Helper()

	responderSession, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: false})
	require.NoError(t, err)

	err = responderSession.InitHandshake()
	require.NoError(t, err)

	// Read msg1 from the pipe (initiator wrote it).
	msg1 := <-transport.recvCh
	require.NotEmpty(t, msg1)

	// Process msg1 and generate msg2.
	msg2, complete, err := responderSession.HandshakeMessage(msg1)
	require.NoError(t, err)
	require.False(t, complete)
	require.NotEmpty(t, msg2)

	// Write msg2 to the pipe (initiator will read it).
	transport.sendCh <- msg2

	// Read msg3 from the pipe (initiator wrote it).
	msg3 := <-transport.recvCh
	require.NotEmpty(t, msg3)

	// Process msg3 - handshake should complete.
	_, complete, err = responderSession.HandshakeMessage(msg3)
	require.NoError(t, err)
	require.True(t, complete)

	return responderSession
}

// ---------------------------------------------------------------------------
// runResponderWithIdentity handles the full protocol including identity exchange.
// This is used when testing device connection flows that trigger identity exchange.
// Protocol:
// 1. Read identity message: [0x01, public_key_32_bytes]
// 2. Send identity ack: [0x00] for new device
// 3. Proceed with Noise XX handshake
// ---------------------------------------------------------------------------
func runResponderWithIdentity(t *testing.T, transport *mockPipeTransport) *NoiseSession {
	t.Helper()

	// Step 1: Read identity message from initiator
	identityMsg := <-transport.recvCh
	require.Len(t, identityMsg, IdentityMsgSize, "identity message should be 33 bytes")
	require.Equal(t, byte(IdentityMsgVersion), identityMsg[0], "identity message version should be 0x01")

	// Step 2: Send identity ack for new device (0x00)
	// For tests, we simulate a new device scenario
	transport.sendCh <- []byte{IdentityAckUnknown}

	// Step 3: Proceed with Noise XX handshake
	responderSession, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: false})
	require.NoError(t, err)

	err = responderSession.InitHandshake()
	require.NoError(t, err)

	// Read msg1 from the pipe (initiator wrote it).
	msg1 := <-transport.recvCh
	require.NotEmpty(t, msg1)

	// Process msg1 and generate msg2.
	msg2, complete, err := responderSession.HandshakeMessage(msg1)
	require.NoError(t, err)
	require.False(t, complete)
	require.NotEmpty(t, msg2)

	// Write msg2 to the pipe (initiator will read it).
	transport.sendCh <- msg2

	// Read msg3 from the pipe (initiator wrote it).
	msg3 := <-transport.recvCh
	require.NotEmpty(t, msg3)

	// Process msg3 - handshake should complete.
	_, complete, err = responderSession.HandshakeMessage(msg3)
	require.NoError(t, err)
	require.True(t, complete)

	return responderSession
}

// ---------------------------------------------------------------------------
// 1. PerformHandshake tests
// ---------------------------------------------------------------------------

func TestPerformHandshake_Success(t *testing.T) {
	t.Parallel()

	initiatorTransport, responderTransport := newPipeTransports()

	initiatorSession, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	// Run responder in background.
	responderDone := make(chan *NoiseSession, 1)
	go func() {
		responderDone <- runResponder(t, responderTransport)
	}()

	// Initiator performs handshake.
	err = PerformHandshake(context.Background(), &HandshakeConfig{
		Transport: initiatorTransport,
		Session:   initiatorSession,
		Logger:    slog.Default(),
	})
	require.NoError(t, err)

	responderSession := <-responderDone

	// Both sides should have completed the handshake.
	assert.True(t, initiatorSession.IsHandshakeComplete())
	assert.True(t, responderSession.IsHandshakeComplete())

	// Verify mutual key agreement: each side knows the other's static key.
	assert.Equal(t, initiatorSession.LocalStaticPublicKey(), responderSession.RemoteStaticPublicKey())
	assert.Equal(t, responderSession.LocalStaticPublicKey(), initiatorSession.RemoteStaticPublicKey())

	// Verify encrypted communication works after the handshake.
	plaintext := []byte("transport-agnostic handshake works")
	ciphertext, err := initiatorSession.Encrypt(plaintext)
	require.NoError(t, err)

	decrypted, err := responderSession.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestPerformHandshake_NilLogger(t *testing.T) {
	t.Parallel()

	initiatorTransport, responderTransport := newPipeTransports()

	initiatorSession, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	responderDone := make(chan *NoiseSession, 1)
	go func() {
		responderDone <- runResponder(t, responderTransport)
	}()

	// Pass nil logger -- PerformHandshake should default to slog.Default().
	err = PerformHandshake(context.Background(), &HandshakeConfig{
		Transport: initiatorTransport,
		Session:   initiatorSession,
		Logger:    nil,
	})
	require.NoError(t, err)

	responderSession := <-responderDone
	assert.True(t, initiatorSession.IsHandshakeComplete())
	assert.True(t, responderSession.IsHandshakeComplete())
}

func TestPerformHandshake_InvalidMsg2(t *testing.T) {
	t.Parallel()

	// Test the error path where the responder sends an invalid msg2 and
	// the initiator's HandshakeMessage fails during processing.
	initiatorTransport, _ := newPipeTransports()

	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	// Simulate a responder that sends garbage as msg2.
	go func() {
		// Drain msg1 from the initiator.
		<-initiatorTransport.sendCh
		// Send garbage as msg2 -- this will cause the initiator's
		// HandshakeMessage to fail with a decryption error.
		initiatorTransport.recvCh <- []byte("this-is-not-a-valid-noise-msg2-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	}()

	err = PerformHandshake(context.Background(), &HandshakeConfig{
		Transport: initiatorTransport,
		Session:   session,
		Logger:    slog.Default(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)
}

func TestPerformHandshake_SendError(t *testing.T) {
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorTransport.sendErr = errMockSend

	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	err = PerformHandshake(context.Background(), &HandshakeConfig{
		Transport: initiatorTransport,
		Session:   session,
		Logger:    slog.Default(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)
}

func TestPerformHandshake_ReceiveError(t *testing.T) {
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorTransport.recvErr = errMockRecv

	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	// We need the send to succeed (msg1 goes into the channel) but the
	// subsequent receive to fail.
	go func() {
		// Drain the msg1 that PerformHandshake writes so the test doesn't block.
		<-initiatorTransport.sendCh
	}()

	err = PerformHandshake(context.Background(), &HandshakeConfig{
		Transport: initiatorTransport,
		Session:   session,
		Logger:    slog.Default(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)
}

func TestPerformHandshake_SendMsg3Error(t *testing.T) {
	t.Parallel()

	// Test the error path where Send fails on msg3 (after successful msg1 send
	// and msg2 receive/processing).
	initiatorTransport, responderTransport := newPipeTransports()

	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	responderSession, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: false})
	require.NoError(t, err)
	err = responderSession.InitHandshake()
	require.NoError(t, err)

	go func() {
		// Read msg1 and produce valid msg2.
		msg1 := <-responderTransport.recvCh
		msg2, _, _ := responderSession.HandshakeMessage(msg1)
		responderTransport.sendCh <- msg2
	}()

	// Inject a send error after msg1 has been sent.
	// We use a wrapper transport that fails on the second Send call.
	countingSend := &countingSendTransport{
		inner:       initiatorTransport,
		failOnCount: 2,
		failErr:     errMockSend,
	}

	err = PerformHandshake(context.Background(), &HandshakeConfig{
		Transport: countingSend,
		Session:   session,
		Logger:    slog.Default(),
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoiseHandshakeFailed)
}

// countingSendTransport wraps a Transport and fails Send on a specific call count.
type countingSendTransport struct {
	inner       Transport
	failOnCount int32
	failErr     error
	count       atomic.Int32
}

func (c *countingSendTransport) Send(ctx context.Context, message []byte) error {
	n := c.count.Add(1)
	if int32(c.failOnCount) == n {
		return c.failErr
	}
	return c.inner.Send(ctx, message)
}

func (c *countingSendTransport) Receive(ctx context.Context) ([]byte, error) {
	return c.inner.Receive(ctx)
}

func (c *countingSendTransport) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	if err := c.Send(ctx, message); err != nil {
		return nil, err
	}
	return c.Receive(ctx)
}

func (c *countingSendTransport) IsConnected() bool {
	return c.inner.IsConnected()
}

func (c *countingSendTransport) Close() error {
	return c.inner.Close()
}

// ---------------------------------------------------------------------------
// 2. HandshakeConfig tests
// ---------------------------------------------------------------------------

func TestHandshakeConfig_TransportInterface(t *testing.T) {
	t.Parallel()

	// Verify that HandshakeConfig.Transport accepts any Transport implementation.
	var transport Transport

	// mockPipeTransport satisfies Transport.
	pipe := &mockPipeTransport{}
	transport = pipe
	cfg := HandshakeConfig{Transport: transport}
	assert.NotNil(t, cfg.Transport)

	// TCPTransport (concrete type) also satisfies Transport.
	tcp, err := NewTCPTransport(nil)
	require.NoError(t, err)
	transport = tcp
	cfg = HandshakeConfig{Transport: transport}
	assert.NotNil(t, cfg.Transport)
}

func TestHandshakeConfig_DefaultEnvelopeHeaderSize(t *testing.T) {
	t.Parallel()

	initiatorTransport, responderTransport := newPipeTransports()

	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)

	responderDone := make(chan struct{}, 1)
	go func() {
		runResponder(t, responderTransport)
		responderDone <- struct{}{}
	}()

	// EnvelopeHeaderSize is 0 -- PerformHandshake should default it to 12.
	cfg := &HandshakeConfig{
		Transport:          initiatorTransport,
		Session:            session,
		EnvelopeHeaderSize: 0,
	}
	err = PerformHandshake(context.Background(), cfg)
	require.NoError(t, err)

	<-responderDone

	// Verify the default was applied.
	assert.Equal(t, 12, cfg.EnvelopeHeaderSize)
}

// ---------------------------------------------------------------------------
// 3. stripEnvelopeHeader tests
// ---------------------------------------------------------------------------

func TestStripEnvelopeHeader_Disabled(t *testing.T) {
	t.Parallel()

	original := make([]byte, NoiseXXMsg2Size+12)
	for i := range original {
		original[i] = byte(i)
	}

	cfg := &HandshakeConfig{
		StripEnvelopeHeader: false,
		EnvelopeHeaderSize:  12,
	}

	result := stripEnvelopeHeader(original, cfg, slog.Default())
	assert.Equal(t, original, result, "message should be returned unchanged when stripping is disabled")
}

func TestStripEnvelopeHeader_Msg2Size(t *testing.T) {
	t.Parallel()

	headerSize := 12
	// Build a message that is exactly NoiseXXMsg2Size + headerSize.
	header := make([]byte, headerSize)
	for i := range header {
		header[i] = 0xAA
	}
	payload := make([]byte, NoiseXXMsg2Size)
	for i := range payload {
		payload[i] = byte(i)
	}
	msg := append(header, payload...)

	cfg := &HandshakeConfig{
		StripEnvelopeHeader: true,
		EnvelopeHeaderSize:  headerSize,
	}

	result := stripEnvelopeHeader(msg, cfg, slog.Default())
	assert.Equal(t, payload, result, "header should be stripped for msg2-sized message")
	assert.Len(t, result, NoiseXXMsg2Size)
}

func TestStripEnvelopeHeader_Msg1Size(t *testing.T) {
	t.Parallel()

	headerSize := 12
	header := make([]byte, headerSize)
	payload := make([]byte, NoiseXXMsg1Size)
	for i := range payload {
		payload[i] = byte(i)
	}
	msg := append(header, payload...)

	cfg := &HandshakeConfig{
		StripEnvelopeHeader: true,
		EnvelopeHeaderSize:  headerSize,
	}

	result := stripEnvelopeHeader(msg, cfg, slog.Default())
	assert.Equal(t, payload, result, "header should be stripped for msg1-sized message")
	assert.Len(t, result, NoiseXXMsg1Size)
}

func TestStripEnvelopeHeader_Msg3Size(t *testing.T) {
	t.Parallel()

	headerSize := 12
	header := make([]byte, headerSize)
	payload := make([]byte, NoiseXXMsg3Size)
	for i := range payload {
		payload[i] = byte(i)
	}
	msg := append(header, payload...)

	cfg := &HandshakeConfig{
		StripEnvelopeHeader: true,
		EnvelopeHeaderSize:  headerSize,
	}

	result := stripEnvelopeHeader(msg, cfg, slog.Default())
	assert.Equal(t, payload, result, "header should be stripped for msg3-sized message")
	assert.Len(t, result, NoiseXXMsg3Size)
}

func TestStripEnvelopeHeader_WithPayloadTag(t *testing.T) {
	t.Parallel()

	headerSize := 12
	// Message with payload tag: expected + NoiseTagSize + header.
	header := make([]byte, headerSize)
	payload := make([]byte, NoiseXXMsg2Size+NoiseTagSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	msg := append(header, payload...)

	cfg := &HandshakeConfig{
		StripEnvelopeHeader: true,
		EnvelopeHeaderSize:  headerSize,
	}

	result := stripEnvelopeHeader(msg, cfg, slog.Default())
	assert.Equal(t, payload, result, "header should be stripped for message with payload tag")
}

func TestStripEnvelopeHeader_NoMatch(t *testing.T) {
	t.Parallel()

	headerSize := 12
	// Create a message whose size does not match any expected pattern
	// and whose extra bytes relative to msg2 exceed 2*headerSize.
	oddSize := NoiseXXMsg2Size + (headerSize * 3)
	msg := make([]byte, oddSize)
	for i := range msg {
		msg[i] = byte(i)
	}

	cfg := &HandshakeConfig{
		StripEnvelopeHeader: true,
		EnvelopeHeaderSize:  headerSize,
	}

	result := stripEnvelopeHeader(msg, cfg, slog.Default())
	assert.Equal(t, msg, result, "message should be unchanged when size does not match any expected pattern")
}

func TestStripEnvelopeHeader_FallbackStrip(t *testing.T) {
	t.Parallel()

	headerSize := 12
	// Build a message that doesn't match exact sizes but has extra bytes
	// within the 2*headerSize threshold. This triggers the fallback strip path.
	extraBytes := headerSize + 5 // 0 < extra <= 2*headerSize
	msg := make([]byte, NoiseXXMsg2Size+extraBytes)
	for i := range msg {
		msg[i] = byte(i)
	}

	cfg := &HandshakeConfig{
		StripEnvelopeHeader: true,
		EnvelopeHeaderSize:  headerSize,
	}

	result := stripEnvelopeHeader(msg, cfg, slog.Default())
	assert.Len(t, result, len(msg)-headerSize, "fallback should strip headerSize bytes")
}

func TestStripEnvelopeHeader_TooShort(t *testing.T) {
	t.Parallel()

	headerSize := 12
	// Message shorter than header -- should be returned unchanged.
	msg := make([]byte, 5)

	cfg := &HandshakeConfig{
		StripEnvelopeHeader: true,
		EnvelopeHeaderSize:  headerSize,
	}

	result := stripEnvelopeHeader(msg, cfg, slog.Default())
	assert.Equal(t, msg, result, "short message should be returned unchanged")
}

// ---------------------------------------------------------------------------
// 4. safeSlice tests
// ---------------------------------------------------------------------------

func TestSafeSlice_Normal(t *testing.T) {
	t.Parallel()

	data := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	result := safeSlice(data, 2, 3)
	assert.Equal(t, []byte{2, 3, 4}, result)
}

func TestSafeSlice_StartBeyondLength(t *testing.T) {
	t.Parallel()

	data := []byte{0, 1, 2}
	result := safeSlice(data, 10, 5)
	assert.Nil(t, result)
}

func TestSafeSlice_EndBeyondLength(t *testing.T) {
	t.Parallel()

	data := []byte{0, 1, 2, 3}
	result := safeSlice(data, 2, 100)
	assert.Equal(t, []byte{2, 3}, result)
}

func TestSafeSlice_ZeroLength(t *testing.T) {
	t.Parallel()

	data := []byte{0, 1, 2}
	result := safeSlice(data, 1, 0)
	assert.Empty(t, result)
}

func TestSafeSlice_EmptyData(t *testing.T) {
	t.Parallel()

	result := safeSlice(nil, 0, 5)
	assert.Nil(t, result)

	result = safeSlice([]byte{}, 0, 5)
	assert.Nil(t, result)
}

func TestSafeSlice_FullSlice(t *testing.T) {
	t.Parallel()

	data := []byte{10, 20, 30}
	result := safeSlice(data, 0, 3)
	assert.Equal(t, data, result)
}

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
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/stretchr/testify/require"
)

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

// testPhoneKeyBackendConfig returns a test configuration for PhoneKeyBackend.
func testPhoneKeyBackendConfig() *PhoneKeyBackendConfig {
	return &PhoneKeyBackendConfig{
		TrustNewDevices: true,
	}
}

// runResponderWithIdentity handles the full protocol including identity exchange.
// Protocol:
// 1. Read identity message: [0x01, public_key_32_bytes]
// 2. Send identity ack: [0x00] for new device
// 3. Proceed with Noise XX handshake
func runResponderWithIdentity(t *testing.T, transport *mockPipeTransport) *NoiseSession {
	t.Helper()

	// Step 1: Read identity message from initiator
	identityMsg := <-transport.recvCh
	require.Len(t, identityMsg, pairing.IdentityMsgSize, "identity message should be 33 bytes")
	require.Equal(t, byte(pairing.IdentityMsgVersion), identityMsg[0], "identity message version should be 0x01")

	// Step 2: Send identity ack for new device (0x00)
	transport.sendCh <- []byte{pairing.IdentityAckUnknown}

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

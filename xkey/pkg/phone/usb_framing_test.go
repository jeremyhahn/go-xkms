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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errUSBIO is a synthetic non-EOF endpoint failure.
var errUSBIO = errors.New("usb: pipe error")

// fakeOutEndpoint records every bulk write and can report short writes or
// failures, mirroring how libusb behaves on real hardware.
type fakeOutEndpoint struct {
	writes  [][]byte
	written bytes.Buffer

	// chunkLimit caps the number of bytes accepted per write (0 = unlimited),
	// simulating a short bulk transfer.
	chunkLimit int
	// failAfter makes the (failAfter+1)-th write fail. Negative disables.
	failAfter int
	err       error
}

func (f *fakeOutEndpoint) WriteContext(_ context.Context, p []byte) (int, error) {
	if f.failAfter >= 0 && len(f.writes) == f.failAfter {
		return 0, f.err
	}
	n := len(p)
	if f.chunkLimit > 0 && n > f.chunkLimit {
		n = f.chunkLimit
	}
	f.writes = append(f.writes, append([]byte(nil), p[:n]...))
	f.written.Write(p[:n])
	return n, nil
}

// fakeInEndpoint replays a scripted sequence of bulk reads.
type fakeInEndpoint struct {
	data []byte
	// chunk caps bytes returned per read (0 = fill the buffer).
	chunk int
	// err is returned once the scripted data is exhausted.
	err   error
	reads int
}

func (f *fakeInEndpoint) ReadContext(_ context.Context, p []byte) (int, error) {
	f.reads++
	if len(f.data) == 0 {
		if f.err != nil {
			return 0, f.err
		}
		return 0, io.EOF
	}
	n := len(p)
	if n > len(f.data) {
		n = len(f.data)
	}
	if f.chunk > 0 && n > f.chunk {
		n = f.chunk
	}
	copy(p, f.data[:n])
	f.data = f.data[n:]
	return n, nil
}

// newConnectedUSBTransport builds a USBTransport wired to fake endpoints and
// marked connected, bypassing libusb device enumeration.
func newConnectedUSBTransport(t *testing.T, in usbInEndpoint, out usbOutEndpoint) *USBTransport {
	t.Helper()

	transport, err := NewUSBTransport(&USBTransportConfig{Logger: slog.New(slog.DiscardHandler)})
	require.NoError(t, err)

	transport.inEP = in
	transport.outEP = out
	transport.connected.Store(true)

	return transport
}

func TestUSBTransport_SendFramesMessageWithLengthPrefix(t *testing.T) {
	t.Parallel()

	out := &fakeOutEndpoint{failAfter: -1}
	transport := newConnectedUSBTransport(t, nil, out)

	payload := []byte("hello phone")
	require.NoError(t, transport.Send(context.Background(), payload))

	frame := out.written.Bytes()
	require.Len(t, frame, usbFrameHeaderSize+len(payload))
	assert.Equal(t, uint16(len(payload)), binary.BigEndian.Uint16(frame[:usbFrameHeaderSize]))
	assert.Equal(t, payload, frame[usbFrameHeaderSize:])
	assert.Len(t, out.writes, 1, "a small message must fit in a single bulk transfer")
}

func TestUSBTransport_SendChunksAtBulkTransferSize(t *testing.T) {
	t.Parallel()

	out := &fakeOutEndpoint{failAfter: -1}
	transport := newConnectedUSBTransport(t, nil, out)

	// One byte past a whole number of bulk transfers, header included.
	payload := bytes.Repeat([]byte{0x5a}, 2*usbBulkTransferSize-usbFrameHeaderSize+1)
	require.NoError(t, transport.Send(context.Background(), payload))

	require.Len(t, out.writes, 3, "the frame must be split at the bulk transfer size")
	assert.Len(t, out.writes[0], usbBulkTransferSize)
	assert.Len(t, out.writes[1], usbBulkTransferSize)
	assert.Len(t, out.writes[2], 1)
	assert.Equal(t, uint16(len(payload)), binary.BigEndian.Uint16(out.written.Bytes()[:usbFrameHeaderSize]))
}

func TestUSBTransport_SendResumesAfterShortWrite(t *testing.T) {
	t.Parallel()

	out := &fakeOutEndpoint{failAfter: -1, chunkLimit: 4}
	transport := newConnectedUSBTransport(t, nil, out)

	payload := []byte("0123456789")
	require.NoError(t, transport.Send(context.Background(), payload))

	assert.Equal(t, append([]byte{0x00, 0x0a}, payload...), out.written.Bytes(),
		"a short bulk write must be resumed at the correct offset")
	assert.Len(t, out.writes, 3)
}

func TestUSBTransport_SendWriteErrorMarksDisconnected(t *testing.T) {
	t.Parallel()

	out := &fakeOutEndpoint{failAfter: 0, err: errUSBIO}
	transport := newConnectedUSBTransport(t, nil, out)

	err := transport.Send(context.Background(), []byte("payload"))
	assert.ErrorIs(t, err, ErrConnectionFailed)
	assert.False(t, transport.IsConnected(), "a write failure must drop the connection state")
}

func TestUSBTransport_SendWithoutEndpointFails(t *testing.T) {
	t.Parallel()

	transport := newConnectedUSBTransport(t, nil, nil)

	err := transport.Send(context.Background(), []byte("payload"))
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUSBTransport_ReceiveReassemblesChunkedReads(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte{0xab}, 300)
	frame := make([]byte, usbFrameHeaderSize+len(payload))
	binary.BigEndian.PutUint16(frame[:usbFrameHeaderSize], uint16(len(payload)))
	copy(frame[usbFrameHeaderSize:], payload)

	in := &fakeInEndpoint{data: frame, chunk: 7}
	transport := newConnectedUSBTransport(t, in, nil)

	got, err := transport.Receive(context.Background())
	require.NoError(t, err)
	assert.Equal(t, payload, got)
	assert.Greater(t, in.reads, 1, "the payload must be reassembled from several bulk reads")
}

func TestUSBTransport_ReceiveZeroLengthFrame(t *testing.T) {
	t.Parallel()

	in := &fakeInEndpoint{data: []byte{0x00, 0x00}}
	transport := newConnectedUSBTransport(t, in, nil)

	got, err := transport.Receive(context.Background())
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestUSBTransport_ReceiveTruncatedPayloadDisconnects(t *testing.T) {
	t.Parallel()

	// Header announces 8 bytes but only 3 arrive before EOF.
	in := &fakeInEndpoint{data: []byte{0x00, 0x08, 1, 2, 3}}
	transport := newConnectedUSBTransport(t, in, nil)

	_, err := transport.Receive(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.False(t, transport.IsConnected())
}

func TestUSBTransport_ReceiveHeaderErrorIsConnectionFailure(t *testing.T) {
	t.Parallel()

	in := &fakeInEndpoint{err: errUSBIO}
	transport := newConnectedUSBTransport(t, in, nil)

	_, err := transport.Receive(context.Background())
	assert.ErrorIs(t, err, ErrConnectionFailed)
	assert.False(t, transport.IsConnected())
}

func TestUSBTransport_ReceiveWithoutEndpointFails(t *testing.T) {
	t.Parallel()

	transport := newConnectedUSBTransport(t, nil, nil)

	_, err := transport.Receive(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUSBTransport_SendAndReceiveRoundTrip(t *testing.T) {
	t.Parallel()

	response := []byte("pong")
	frame := append([]byte{0x00, byte(len(response))}, response...)

	in := &fakeInEndpoint{data: frame}
	out := &fakeOutEndpoint{failAfter: -1}
	transport := newConnectedUSBTransport(t, in, out)

	got, err := transport.SendAndReceive(context.Background(), []byte("ping"))
	require.NoError(t, err)
	assert.Equal(t, response, got)
	assert.Equal(t, append([]byte{0x00, 0x04}, []byte("ping")...), out.written.Bytes())
}

func TestUSBTransport_SendAndReceiveStopsOnSendFailure(t *testing.T) {
	t.Parallel()

	in := &fakeInEndpoint{data: []byte{0x00, 0x01, 0xff}}
	out := &fakeOutEndpoint{failAfter: 0, err: errUSBIO}
	transport := newConnectedUSBTransport(t, in, out)

	_, err := transport.SendAndReceive(context.Background(), []byte("ping"))
	assert.ErrorIs(t, err, ErrConnectionFailed)
	assert.Zero(t, in.reads, "no read may be attempted after the send failed")
}

func TestUSBTransport_OperationsAfterCloseFail(t *testing.T) {
	t.Parallel()

	in := &fakeInEndpoint{data: []byte{0x00, 0x01, 0xff}}
	out := &fakeOutEndpoint{failAfter: -1}
	transport := newConnectedUSBTransport(t, in, out)

	require.NoError(t, transport.Close())
	require.NoError(t, transport.Close(), "Close must be idempotent")

	assert.ErrorIs(t, transport.Send(context.Background(), []byte("x")), ErrBackendClosed)
	_, err := transport.Receive(context.Background())
	assert.ErrorIs(t, err, ErrBackendClosed)
	assert.False(t, transport.IsConnected())
	assert.Zero(t, out.written.Len(), "a closed transport must not touch the endpoints")
}

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

package vtpm

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/google/go-tpm/tpm2/transport"
)

// tpmHeaderSize is the size of a TPM 2.0 command/response header: tag (2),
// size (4) and code (4) -- TPM 2.0 Part 1, section 18.
const tpmHeaderSize = 10

// maxTPMResponse bounds a response a vTPM may declare. TPM 2.0 caps a
// command or response buffer well below this; anything larger is a corrupt
// or hostile stream, not a response to buffer.
const maxTPMResponse = 64 * 1024

// socketTransport is a transport.TPMCloser over a vTPM's command socket. It
// frames each command/response by the TPM header's size field and
// reconnects on the next Send after the connection drops -- which is how a
// client follows a vTPM the Manager restarted.
//
// A command whose write failed was never delivered, so it is retried once on
// a fresh connection. A command whose response could not be read may have
// run; it is reported as ErrConnectionLost rather than repeated, because a
// TPM command is not idempotent.
type socketTransport struct {
	mu   sync.Mutex
	dial func() (net.Conn, error)
	conn net.Conn
}

// Compile-time interface check.
var _ transport.TPMCloser = (*socketTransport)(nil)

// Send writes one TPM command and returns its complete response.
func (t *socketTransport) Send(input []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if err := t.write(input); err != nil {
		if dropErr := t.drop(); dropErr != nil {
			return nil, errors.Join(err, dropErr)
		}
		if err := t.write(input); err != nil {
			return nil, errors.Join(err, t.drop())
		}
	}

	resp, err := readResponse(t.conn)
	if err != nil {
		return nil, errors.Join(ErrConnectionLost, err, t.drop())
	}
	return resp, nil
}

// Close closes the current connection, if any.
func (t *socketTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	return err
}

// write sends input on the current connection, dialing one first when there
// is none.
func (t *socketTransport) write(input []byte) error {
	if t.conn == nil {
		conn, err := t.dial()
		if err != nil {
			return err
		}
		t.conn = conn
	}
	_, err := t.conn.Write(input)
	return err
}

// drop discards the current connection so the next write dials a new one.
// A connection the peer already closed reports net.ErrClosed, which is the
// expected state here and not an error.
func (t *socketTransport) drop() error {
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// readResponse reads one framed TPM response: the header, then the rest of
// the size the header declares.
func readResponse(r io.Reader) ([]byte, error) {
	header := make([]byte, tpmHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[2:6])
	if size < tpmHeaderSize || size > maxTPMResponse {
		return nil, ErrResponseTooLarge
	}
	resp := make([]byte, size)
	copy(resp, header)
	if _, err := io.ReadFull(r, resp[tpmHeaderSize:]); err != nil {
		return nil, err
	}
	return resp, nil
}

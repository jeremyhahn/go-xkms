package vtpm

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// answerOnce serves one command on server with a success response.
func answerOnce(t *testing.T, server net.Conn) {
	t.Helper()
	go func() {
		buf := make([]byte, tpmHeaderSize)
		if _, err := io.ReadFull(server, buf); err != nil {
			return
		}
		if _, err := server.Write(response(0)); err != nil {
			return
		}
	}()
}

func TestIsRetryResponse_IgnoresATruncatedHeader(t *testing.T) {
	assert.False(t, isRetryResponse(response(0x922)[:tpmHeaderSize-1]))
	assert.True(t, isRetryResponse(response(0x922)))
	assert.False(t, isRetryResponse(response(0)))
}

func TestSend_ReportsADialFailure(t *testing.T) {
	dialErr := errors.New("no socket")
	dials := 0
	tr := &socketTransport{dial: func() (net.Conn, error) {
		dials++
		return nil, dialErr
	}}
	_, err := tr.Send(response(0))
	assert.ErrorIs(t, err, dialErr)
	assert.Equal(t, 2, dials, "a failed write is retried once on a fresh connection")
}

func TestSend_RedialsAStaleConnection(t *testing.T) {
	stale, staleServer := net.Pipe()
	require.NoError(t, stale.Close())
	require.NoError(t, staleServer.Close())

	fresh, server := net.Pipe()
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	answerOnce(t, server)

	tr := &socketTransport{conn: stale, dial: func() (net.Conn, error) { return fresh, nil }}
	rsp, err := tr.Send(response(0))
	require.NoError(t, err)
	assert.Equal(t, response(0), rsp)
	require.NoError(t, tr.Close())
}

func TestSend_ALostResponseDropsTheConnection(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		buf := make([]byte, tpmHeaderSize)
		if _, err := io.ReadFull(server, buf); err != nil {
			return
		}
		if err := server.Close(); err != nil {
			return
		}
	}()

	tr := &socketTransport{dial: func() (net.Conn, error) { return client, nil }}
	_, err := tr.Send(response(0))
	assert.ErrorIs(t, err, ErrConnectionLost)
	assert.ErrorIs(t, err, io.EOF)
	assert.Nil(t, tr.conn, "the dead connection is dropped so the next command redials")
	assert.NoError(t, tr.Close())
}

func TestClose_ClosesTheConnectionOnce(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	tr := &socketTransport{conn: client}
	require.NoError(t, tr.Close())
	assert.Nil(t, tr.conn)
	assert.NoError(t, tr.Close())

	_, err := client.Write([]byte{0})
	assert.ErrorIs(t, err, io.ErrClosedPipe)
}

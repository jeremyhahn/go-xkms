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

package tpm2

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingCloser records its Close calls.
type countingCloser struct {
	closes int
	err    error
}

func (c *countingCloser) Close() error {
	c.closes++
	return c.err
}

// TestClose_ClosesTheNetworkConnection proves Close releases a TCP or
// Unix-socket TPM connection the TPM opened: a swtpm serves one client at a
// time, so a connection left open blocks every other client of it.
func TestClose_ClosesTheNetworkConnection(t *testing.T) {
	conn := &countingCloser{}
	tpm := &TPM2{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), conn: conn}
	require.NoError(t, tpm.Close())
	assert.Equal(t, 1, conn.closes)
	assert.Nil(t, tpm.conn)
	require.NoError(t, tpm.Close(), "a second Close is a no-op")
	assert.Equal(t, 1, conn.closes)
}

func TestClose_ReleasesTheTPMWhenTheConnectionFailsToClose(t *testing.T) {
	// Close logs a failing connection close, as it does a failing device
	// close, and still releases the TPM.
	conn := &countingCloser{err: errors.New("broken pipe")}
	tpm := &TPM2{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), conn: conn}
	require.NoError(t, tpm.Close())
	assert.Equal(t, 1, conn.closes)
	assert.Nil(t, tpm.conn)
}

// TestNewTPM2_ClosesTheTCPConnectionWhenTheConfigIsInvalid proves an open
// that fails after dialling the TPM releases the connection.
func TestNewTPM2_ClosesTheTCPConnectionWhenTheConfigIsInvalid(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	cfg := DefaultConfig
	cfg.CommandAddress = listener.Addr().String()
	cfg.PlatformAddress = listener.Addr().String()
	cfg.Hash = "not-a-hash"
	_, err = NewTPM2(&Params{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Config: &cfg})
	require.Error(t, err)

	// Both channels the transport dialled are closed: reading them ends.
	for range 2 {
		c := <-accepted
		buf := make([]byte, 1)
		_, readErr := c.Read(buf)
		assert.ErrorIs(t, readErr, io.EOF, "the TPM closed its connection")
		_ = c.Close()
	}
}

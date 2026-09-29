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
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// response builds a bare TPM response header with rc.
func response(rc uint32) []byte {
	rsp := make([]byte, tpmHeaderSize)
	binary.BigEndian.PutUint16(rsp[0:2], 0x8001)
	binary.BigEndian.PutUint32(rsp[2:6], tpmHeaderSize)
	binary.BigEndian.PutUint32(rsp[6:10], rc)
	return rsp
}

// fakeVTPM answers each command it reads with the next of rcs.
func fakeVTPM(t *testing.T, rcs ...uint32) (*socketTransport, *int) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	commands := new(int)
	go func() {
		buf := make([]byte, tpmHeaderSize)
		for _, rc := range rcs {
			if _, err := io.ReadFull(server, buf); err != nil {
				return
			}
			*commands++
			if _, err := server.Write(response(rc)); err != nil {
				return
			}
		}
	}()
	return &socketTransport{dial: func() (net.Conn, error) { return client, nil }}, commands
}

// TestSend_ResendsARetryWarning proves a command the vTPM declined with
// TPM_RC_RETRY (swtpm's answer while it self-tests an algorithm) is sent
// again and the real answer returned.
func TestSend_ResendsARetryWarning(t *testing.T) {
	tr, commands := fakeVTPM(t, 0x922, 0x90A, 0)
	rsp, err := tr.Send(response(0))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), binary.BigEndian.Uint32(rsp[6:10]))
	assert.Equal(t, 3, *commands)
}

// TestSend_StopsResendingAfterTheBound proves a vTPM that keeps asking for a
// retry gets its warning back after maxCommandRetries resends, not a loop.
func TestSend_StopsResendingAfterTheBound(t *testing.T) {
	rcs := make([]uint32, maxCommandRetries+1)
	for i := range rcs {
		rcs[i] = 0x922
	}
	tr, commands := fakeVTPM(t, rcs...)
	rsp, err := tr.Send(response(0))
	require.NoError(t, err)
	assert.True(t, isRetryResponse(rsp))
	assert.Equal(t, maxCommandRetries+1, *commands)
}

// TestReadResponse_RefusesAnOversizedHeader proves a corrupt size field is
// an error, not an allocation.
func TestReadResponse_RefusesAnOversizedHeader(t *testing.T) {
	rsp := response(0)
	binary.BigEndian.PutUint32(rsp[2:6], maxTPMResponse+1)
	client, server := net.Pipe()
	written := make(chan error, 1)
	go func() {
		_, err := server.Write(rsp)
		written <- err
	}()
	_, err := readResponse(client)
	assert.ErrorIs(t, err, ErrResponseTooLarge)
	require.NoError(t, <-written)
	require.NoError(t, client.Close())
	require.NoError(t, server.Close())
}

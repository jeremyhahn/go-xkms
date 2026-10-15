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
	"encoding/binary"
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tpmReply is one scripted transport answer: a TPM response code, or a
// transport error when err is set.
type tpmReply struct {
	rc  tpm2.TPMRC
	err error
}

// scriptedTransport answers each command with the next reply in order.
type scriptedTransport struct {
	replies []tpmReply
	sent    int
}

func (s *scriptedTransport) Send([]byte) ([]byte, error) {
	reply := s.replies[s.sent]
	s.sent++
	if reply.err != nil {
		return nil, reply.err
	}
	// A bare response header: TPM_ST_NO_SESSIONS, size 10, response code.
	rsp := make([]byte, 10)
	binary.BigEndian.PutUint16(rsp[0:2], uint16(tpm2.TPMSTNoSessions))
	binary.BigEndian.PutUint32(rsp[2:6], 10)
	binary.BigEndian.PutUint32(rsp[6:10], uint32(reply.rc))
	return rsp, nil
}

func newTPM2WithReplies(t *testing.T, replies ...tpmReply) (TrustedPlatformModule, *scriptedTransport, error) {
	t.Helper()
	transport := &scriptedTransport{replies: replies}
	tpm, err := NewTPM2(&Params{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Transport: transport,
	})
	return tpm, transport, err
}

// TestNewTPM2_DeviceNeverAnswersIsAnError is the regression for a TPM whose
// transport fails before any response code: NewTPM2 reported it as an
// unprovisioned TPM, and callers that accept ErrNotInitialized went on to
// provision a device that was never there.
func TestNewTPM2_DeviceNeverAnswersIsAnError(t *testing.T) {
	tpm, transport, err := newTPM2WithReplies(t, tpmReply{err: io.EOF})

	require.Nil(t, tpm)
	require.ErrorIs(t, err, ErrDeviceNoResponse)
	assert.ErrorIs(t, err, io.EOF)
	assert.NotErrorIs(t, err, ErrNotInitialized)
	assert.Equal(t, 1, transport.sent, "no NV read may follow a dead transport")
}

// TestNewTPM2_NVReadNeverAnswersIsAnError covers the second probe: the EK
// handle read gets a TPM answer, then the device stops answering.
func TestNewTPM2_NVReadNeverAnswersIsAnError(t *testing.T) {
	tpm, _, err := newTPM2WithReplies(t,
		tpmReply{rc: tpm2.TPMRCHandle},
		tpmReply{err: io.ErrUnexpectedEOF})

	require.Nil(t, tpm)
	require.ErrorIs(t, err, ErrDeviceNoResponse)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.NotErrorIs(t, err, ErrNotInitialized)
}

// TestNewTPM2_TPMAnswersWithNoEKIsUnprovisioned keeps the case the
// fallback exists for: a TPM that answers both probes with an error code
// has no EK yet, and NewTPM2 returns it for provisioning.
func TestNewTPM2_TPMAnswersWithNoEKIsUnprovisioned(t *testing.T) {
	tpm, _, err := newTPM2WithReplies(t,
		tpmReply{rc: tpm2.TPMRCHandle},
		tpmReply{rc: tpm2.TPMRCHandle})

	require.ErrorIs(t, err, ErrNotInitialized)
	assert.NotErrorIs(t, err, ErrDeviceNoResponse)
	require.NotNil(t, tpm)
}

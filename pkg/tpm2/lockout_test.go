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
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDictionaryAttackLockoutReset_NoTransport proves the method refuses to
// build and send a TPM2_DictionaryAttackLockReset command against a TPM2
// that was never opened, rather than dereferencing a nil transport.
func TestDictionaryAttackLockoutReset_NoTransport(t *testing.T) {
	tpm := &TPM2{}
	err := tpm.DictionaryAttackLockoutReset([]byte("lockout-auth"))
	assert.ErrorIs(t, err, ErrTransportNotInitialized)
}

// TestDictionaryAttackLockoutReset_EncodesPasswordSession pins the
// hand-built command: TPM_ST_SESSIONS, the DictionaryAttackLockReset command
// code against TPM_RH_LOCKOUT, and the lockout auth as the trailing
// password-session HMAC.
func TestDictionaryAttackLockoutReset_EncodesPasswordSession(t *testing.T) {
	transport := &lockoutTransport{rsp: []byte{0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0}}
	tpm := &TPM2{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		transport: transport,
	}
	auth := []byte("lockout-auth")

	require.NoError(t, tpm.DictionaryAttackLockoutReset(auth))

	sent := transport.sent
	require.Len(t, sent, 27+len(auth))
	assert.Equal(t, uint16(0x8002), binary.BigEndian.Uint16(sent[0:2]))
	assert.Equal(t, uint32(len(sent)), binary.BigEndian.Uint32(sent[2:6]))
	assert.Equal(t, uint32(tpm2.TPMCCDictionaryAttackLockReset), binary.BigEndian.Uint32(sent[6:10]))
	assert.Equal(t, uint32(tpm2.TPMRHLockout), binary.BigEndian.Uint32(sent[10:14]))
	assert.Equal(t, auth, sent[len(sent)-len(auth):])
}

// TestDictionaryAttackLockoutReset_TransportFailures covers a failed send,
// a response too short to carry a header, and a TPM error code.
func TestDictionaryAttackLockoutReset_TransportFailures(t *testing.T) {
	errSend := errors.New("transport down")
	tests := []struct {
		name  string
		rsp   []byte
		err   error
		check func(t *testing.T, err error)
	}{
		{
			name:  "send error",
			err:   errSend,
			check: func(t *testing.T, err error) { assert.ErrorIs(t, err, errSend) },
		},
		{
			name:  "short response",
			rsp:   []byte{0x80, 0x01, 0, 0},
			check: func(t *testing.T, err error) { assert.ErrorContains(t, err, "response too short") },
		},
		{
			name: "TPM error code",
			rsp:  []byte{0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x09, 0x21},
			check: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, tpm2.TPMRC(0x921))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := &TPM2{transport: &lockoutTransport{rsp: tt.rsp, err: tt.err}}
			err := tpm.DictionaryAttackLockoutReset(nil)
			require.Error(t, err)
			tt.check(t, err)
		})
	}
}

// lockoutTransport records the command it is sent and answers with a fixed
// response or error.
type lockoutTransport struct {
	rsp  []byte
	err  error
	sent []byte
}

func (l *lockoutTransport) Send(cmd []byte) ([]byte, error) {
	l.sent = bytes.Clone(cmd)
	return l.rsp, l.err
}

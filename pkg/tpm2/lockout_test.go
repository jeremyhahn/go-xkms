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
	"errors"
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

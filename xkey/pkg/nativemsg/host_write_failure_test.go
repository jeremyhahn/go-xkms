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

package nativemsg

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// failingWriter always returns an error, simulating a browser that has
// already closed its end of the native messaging pipe.
type failingWriter struct{}

var errWriteFailed = errors.New("write failed: pipe closed")

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteFailed }

// TestSendHandshakeOK_WriteFails proves a stdout write failure is reported
// as a typed handshake error rather than a raw write error.
func TestSendHandshakeOK_WriteFails(t *testing.T) {
	host := NewHostWithIO("", testLogger(), &bytes.Buffer{}, failingWriter{}, nil)

	err := host.sendHandshakeOK(make([]byte, X25519KeySize))
	assert.ErrorIs(t, err, ErrHandshakeFailed)
	assert.ErrorIs(t, err, errWriteFailed)
}

// TestSendPairingRequired_WriteFails proves a stdout write failure is
// reported as a typed handshake error.
func TestSendPairingRequired_WriteFails(t *testing.T) {
	host := NewHostWithIO("", testLogger(), &bytes.Buffer{}, failingWriter{}, nil)

	err := host.sendPairingRequired(make([]byte, X25519KeySize))
	assert.ErrorIs(t, err, ErrHandshakeFailed)
	assert.ErrorIs(t, err, errWriteFailed)
}

// TestSendHandshakeRejected_WriteFails proves a stdout write failure during
// a rejection is itself reported as a typed handshake error, rather than the
// identity-mismatch sentinel the write would otherwise have carried.
func TestSendHandshakeRejected_WriteFails(t *testing.T) {
	host := NewHostWithIO("", testLogger(), &bytes.Buffer{}, failingWriter{}, nil)

	err := host.sendHandshakeRejected(make([]byte, X25519KeySize), "reason")
	assert.ErrorIs(t, err, ErrHandshakeFailed)
	assert.ErrorIs(t, err, errWriteFailed)
	assert.False(t, errors.Is(err, ErrIdentityMismatch), "a write failure must not be reported as an identity mismatch")
}

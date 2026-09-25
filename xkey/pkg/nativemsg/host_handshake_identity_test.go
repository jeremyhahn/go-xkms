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
	"encoding/base64"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pairedVerifier returns a PairingVerifier with one origin already paired,
// so handshakeWithIdentity takes the "already paired" branches rather than
// initiating a fresh pairing ceremony.
func pairedVerifier(t *testing.T) (*PairingVerifier, []byte) {
	t.Helper()
	dir := t.TempDir()
	v, err := NewPairingVerifier(filepath.Join(dir, "state.json"))
	require.NoError(t, err)

	pub, _ := generateTestIdentity(t)
	completePairingCeremony(t, v, pub, testOrigin)
	return v, pub
}

func newHandshakeTestHost(t *testing.T, pairing *PairingVerifier) (*Host, *bytes.Buffer) {
	t.Helper()
	stdout := &bytes.Buffer{}
	host := NewHostWithIO("", testLogger(), &bytes.Buffer{}, stdout, pairing)
	return host, stdout
}

// TestHandshakeWithIdentity_PairedButNoIdentity proves a paired host that
// receives a handshake with no identity key is rejected rather than treated
// as a fresh pairing request.
func TestHandshakeWithIdentity_PairedButNoIdentity(t *testing.T) {
	v, _ := pairedVerifier(t)
	host, stdout := newHandshakeTestHost(t, v)

	ourPubKey := make([]byte, X25519KeySize)
	err := host.handshakeWithIdentity(&NativeMessage{Origin: testOrigin}, ourPubKey)
	assert.ErrorIs(t, err, ErrIdentityMismatch)

	resp, readErr := ReadMessage(stdout)
	require.NoError(t, readErr)
	assert.Equal(t, MsgTypeHandshakeRejected, resp.Type)
	assert.Equal(t, "identity key required", resp.Error)
}

// TestHandshakeWithIdentity_InvalidIdentityKeyEncoding proves a malformed
// base64 identity key is rejected with a typed handshake_rejected response.
func TestHandshakeWithIdentity_InvalidIdentityKeyEncoding(t *testing.T) {
	v, _ := pairedVerifier(t)
	host, stdout := newHandshakeTestHost(t, v)

	ourPubKey := make([]byte, X25519KeySize)
	msg := &NativeMessage{Origin: testOrigin, IdentityKey: "not-valid-base64!!!"}
	err := host.handshakeWithIdentity(msg, ourPubKey)
	assert.ErrorIs(t, err, ErrIdentityMismatch)

	resp, readErr := ReadMessage(stdout)
	require.NoError(t, readErr)
	assert.Equal(t, MsgTypeHandshakeRejected, resp.Type)
	assert.Equal(t, "invalid identity key encoding", resp.Error)
}

// TestHandshakeWithIdentity_SignatureRequired proves a paired origin that
// sends an identity key but no signature is rejected.
func TestHandshakeWithIdentity_SignatureRequired(t *testing.T) {
	v, pub := pairedVerifier(t)
	host, stdout := newHandshakeTestHost(t, v)

	ourPubKey := make([]byte, X25519KeySize)
	msg := &NativeMessage{
		Origin:      testOrigin,
		IdentityKey: base64.StdEncoding.EncodeToString(pub),
	}
	err := host.handshakeWithIdentity(msg, ourPubKey)
	assert.ErrorIs(t, err, ErrIdentityMismatch)

	resp, readErr := ReadMessage(stdout)
	require.NoError(t, readErr)
	assert.Equal(t, MsgTypeHandshakeRejected, resp.Type)
	assert.Equal(t, "identity signature required", resp.Error)
}

// TestHandshakeWithIdentity_InvalidSignatureEncoding proves a malformed
// base64 signature is rejected.
func TestHandshakeWithIdentity_InvalidSignatureEncoding(t *testing.T) {
	v, pub := pairedVerifier(t)
	host, stdout := newHandshakeTestHost(t, v)

	ourPubKey := make([]byte, X25519KeySize)
	msg := &NativeMessage{
		Origin:      testOrigin,
		IdentityKey: base64.StdEncoding.EncodeToString(pub),
		IdentitySig: "not-valid-base64!!!",
	}
	err := host.handshakeWithIdentity(msg, ourPubKey)
	assert.ErrorIs(t, err, ErrIdentityMismatch)

	resp, readErr := ReadMessage(stdout)
	require.NoError(t, readErr)
	assert.Equal(t, "invalid signature encoding", resp.Error)
}

// TestHandshakeWithIdentity_InvalidPublicKeyEncoding proves a malformed
// base64 ephemeral public key (msg.PubKey) is rejected.
func TestHandshakeWithIdentity_InvalidPublicKeyEncoding(t *testing.T) {
	v, pub := pairedVerifier(t)
	host, stdout := newHandshakeTestHost(t, v)

	ourPubKey := make([]byte, X25519KeySize)
	msg := &NativeMessage{
		Origin:      testOrigin,
		IdentityKey: base64.StdEncoding.EncodeToString(pub),
		IdentitySig: base64.StdEncoding.EncodeToString([]byte("sig")),
		PubKey:      "not-valid-base64!!!",
	}
	err := host.handshakeWithIdentity(msg, ourPubKey)
	assert.ErrorIs(t, err, ErrIdentityMismatch)

	resp, readErr := ReadMessage(stdout)
	require.NoError(t, readErr)
	assert.Equal(t, "invalid public key encoding", resp.Error)
}

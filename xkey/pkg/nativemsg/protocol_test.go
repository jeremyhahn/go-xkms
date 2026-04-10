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
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadWriteMessage_Roundtrip(t *testing.T) {
	original := &NativeMessage{
		Type:       MsgTypeEncrypted,
		Nonce:      42,
		Ciphertext: "c2VjcmV0",
	}

	var buf bytes.Buffer
	err := WriteMessage(&buf, original)
	require.NoError(t, err)

	got, err := ReadMessage(&buf)
	require.NoError(t, err)
	assert.Equal(t, original.Type, got.Type)
	assert.Equal(t, original.Nonce, got.Nonce)
	assert.Equal(t, original.Ciphertext, got.Ciphertext)
}

func TestReadWriteMessage_HandshakeMessage(t *testing.T) {
	original := &NativeMessage{
		Type:   MsgTypeHandshake,
		PubKey: "dGVzdHB1YmtleQ==",
	}

	var buf bytes.Buffer
	err := WriteMessage(&buf, original)
	require.NoError(t, err)

	got, err := ReadMessage(&buf)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshake, got.Type)
	assert.Equal(t, original.PubKey, got.PubKey)
	assert.Empty(t, got.Ciphertext)
	assert.Zero(t, got.Nonce)
}

func TestReadWriteMessage_HandshakeOKMessage(t *testing.T) {
	original := &NativeMessage{
		Type:   MsgTypeHandshakeOK,
		PubKey: "c2VydmVycHVia2V5",
	}

	var buf bytes.Buffer
	err := WriteMessage(&buf, original)
	require.NoError(t, err)

	got, err := ReadMessage(&buf)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshakeOK, got.Type)
	assert.Equal(t, original.PubKey, got.PubKey)
}

func TestReadWriteMessage_ErrorMessage(t *testing.T) {
	original := &NativeMessage{
		Type:  MsgTypeError,
		Error: "something went wrong",
	}

	var buf bytes.Buffer
	err := WriteMessage(&buf, original)
	require.NoError(t, err)

	got, err := ReadMessage(&buf)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeError, got.Type)
	assert.Equal(t, "something went wrong", got.Error)
}

func TestReadWriteMessage_EncryptedMessage(t *testing.T) {
	original := &NativeMessage{
		Type:       MsgTypeEncrypted,
		Nonce:      99,
		Ciphertext: "ZW5jcnlwdGVk",
	}

	var buf bytes.Buffer
	err := WriteMessage(&buf, original)
	require.NoError(t, err)

	got, err := ReadMessage(&buf)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeEncrypted, got.Type)
	assert.Equal(t, uint64(99), got.Nonce)
	assert.Equal(t, "ZW5jcnlwdGVk", got.Ciphertext)
}

func TestReadMessage_TooLarge(t *testing.T) {
	// Write a length header that exceeds MaxMessageSize.
	var buf bytes.Buffer
	var lengthBuf [4]byte
	binary.LittleEndian.PutUint32(lengthBuf[:], MaxMessageSize+1)
	buf.Write(lengthBuf[:])
	// No need to write actual payload bytes, the length check happens first.

	_, err := ReadMessage(&buf)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMessageTooLarge))
}

func TestReadMessage_TruncatedLength(t *testing.T) {
	// Only 2 bytes instead of 4.
	buf := bytes.NewReader([]byte{0x01, 0x02})

	_, err := ReadMessage(buf)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrReadFailed))
}

func TestReadMessage_ZeroLength(t *testing.T) {
	var buf bytes.Buffer
	var lengthBuf [4]byte
	binary.LittleEndian.PutUint32(lengthBuf[:], 0)
	buf.Write(lengthBuf[:])

	_, err := ReadMessage(&buf)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrReadFailed))
}

func TestReadMessage_TruncatedPayload(t *testing.T) {
	// Header says 100 bytes, but we only provide 10.
	var buf bytes.Buffer
	var lengthBuf [4]byte
	binary.LittleEndian.PutUint32(lengthBuf[:], 100)
	buf.Write(lengthBuf[:])
	buf.Write(make([]byte, 10))

	_, err := ReadMessage(&buf)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrReadFailed))
}

func TestReadMessage_InvalidJSON(t *testing.T) {
	payload := []byte("not valid json{{{")
	var buf bytes.Buffer
	var lengthBuf [4]byte
	binary.LittleEndian.PutUint32(lengthBuf[:], uint32(len(payload)))
	buf.Write(lengthBuf[:])
	buf.Write(payload)

	_, err := ReadMessage(&buf)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrReadFailed))
}

func TestWriteMessage_TooLarge(t *testing.T) {
	// Create a message whose JSON serialization exceeds MaxMessageSize.
	msg := &NativeMessage{
		Type:       MsgTypeEncrypted,
		Ciphertext: strings.Repeat("A", MaxMessageSize+1),
	}

	var buf bytes.Buffer
	err := WriteMessage(&buf, msg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMessageTooLarge))
}

func TestWriteError_Success(t *testing.T) {
	var buf bytes.Buffer
	err := WriteError(&buf, "test error message")
	require.NoError(t, err)

	got, err := ReadMessage(&buf)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeError, got.Type)
	assert.Equal(t, "test error message", got.Error)
}

func TestReadWriteMessage_MultipleMessages(t *testing.T) {
	messages := []*NativeMessage{
		{Type: MsgTypeHandshake, PubKey: "key1"},
		{Type: MsgTypeHandshakeOK, PubKey: "key2"},
		{Type: MsgTypeEncrypted, Nonce: 1, Ciphertext: "ct1"},
		{Type: MsgTypeEncrypted, Nonce: 2, Ciphertext: "ct2"},
	}

	var buf bytes.Buffer
	for _, msg := range messages {
		err := WriteMessage(&buf, msg)
		require.NoError(t, err)
	}

	for _, expected := range messages {
		got, err := ReadMessage(&buf)
		require.NoError(t, err)
		assert.Equal(t, expected.Type, got.Type)
		assert.Equal(t, expected.PubKey, got.PubKey)
		assert.Equal(t, expected.Nonce, got.Nonce)
		assert.Equal(t, expected.Ciphertext, got.Ciphertext)
	}
}

func TestReadMessage_EmptyReader(t *testing.T) {
	buf := bytes.NewReader([]byte{})
	_, err := ReadMessage(buf)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrReadFailed))
}

func TestWriteMessage_WriterError(t *testing.T) {
	msg := &NativeMessage{Type: MsgTypeHandshake, PubKey: "test"}
	w := &failWriter{failAfter: 0}

	err := WriteMessage(w, msg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWriteFailed))
}

func TestWriteMessage_WriterErrorOnPayload(t *testing.T) {
	msg := &NativeMessage{Type: MsgTypeHandshake, PubKey: "test"}
	// Succeed on length header write, fail on payload write.
	w := &failWriter{failAfter: headerSize}

	err := WriteMessage(w, msg)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWriteFailed))
}

// failWriter is a writer that fails after writing failAfter bytes.
type failWriter struct {
	written   int
	failAfter int
}

func (fw *failWriter) Write(p []byte) (int, error) {
	if fw.written >= fw.failAfter {
		return 0, errors.New("write error")
	}
	fw.written += len(p)
	if fw.written > fw.failAfter {
		return 0, errors.New("write error")
	}
	return len(p), nil
}

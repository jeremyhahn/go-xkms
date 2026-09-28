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
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bufLogger returns a logger that captures Warn/Error records into buf so
// tests can assert on defensive log-only branches that don't change control
// flow (e.g. a write failure that is logged but not returned).
func bufLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})), buf
}

// failFirstNWriter forwards writes to an underlying writer, but fails the
// first n calls to Write. It lets a test choose precisely which framed
// message (WriteMessage always issues two Write calls: header then payload)
// fails, without disturbing writes that came before it.
type failFirstNWriter struct {
	underlying io.Writer
	remaining  int
}

func (w *failFirstNWriter) Write(p []byte) (int, error) {
	if w.remaining > 0 {
		w.remaining--
		return 0, errWriteFailed
	}
	return w.underlying.Write(p)
}

// panicReader fails the test if Read is ever called. It proves a code path
// never reaches a blocking read.
type panicReader struct{ t *testing.T }

func (r panicReader) Read([]byte) (int, error) {
	r.t.Fatal("stdin must not be read")
	return 0, nil
}

// rawFrame writes a hand-crafted length-prefixed frame directly, bypassing
// WriteMessage, so a test can send a header the protocol rejects (e.g. a
// length that exceeds MaxMessageSize) without needing a matching payload.
func rawFrame(t *testing.T, w io.Writer, length uint32) {
	t.Helper()
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], length)
	_, err := w.Write(hdr[:])
	require.NoError(t, err)
}

// --- awaitPairingConfirmation ---

// TestAwaitPairingConfirmation_UnexpectedMessageType covers the "deny" path:
// the extension responds with something other than pairing_confirm (e.g. the
// user dismissed the pairing dialog and the extension sent a fresh
// handshake). The host must reject the ceremony rather than hang.
func TestAwaitPairingConfirmation_UnexpectedMessageType(t *testing.T) {
	tmpDir := t.TempDir()
	pairing, err := NewPairingVerifier(filepath.Join(tmpDir, "pairing.json"))
	require.NoError(t, err)
	_, err = pairing.StartPairing(nil, "origin")
	require.NoError(t, err)

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)
	host := NewHostWithIO("", testLogger(), stdinR, stdoutW, pairing)

	require.NoError(t, WriteMessage(stdinW, &NativeMessage{Type: MsgTypeHandshake}))

	errCh := make(chan error, 1)
	go func() {
		errCh <- host.awaitPairingConfirmation(make([]byte, X25519KeySize), "origin")
	}()

	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypePairingFailed, resp.Type)
	assert.Contains(t, resp.Error, "expected pairing_confirm")

	err = <-errCh
	assert.ErrorIs(t, err, ErrPairingRejected)
}

// TestAwaitPairingConfirmation_EmptyCode covers the case where the extension
// submits a pairing_confirm with no code at all.
func TestAwaitPairingConfirmation_EmptyCode(t *testing.T) {
	tmpDir := t.TempDir()
	pairing, err := NewPairingVerifier(filepath.Join(tmpDir, "pairing.json"))
	require.NoError(t, err)
	_, err = pairing.StartPairing(nil, "origin")
	require.NoError(t, err)

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)
	host := NewHostWithIO("", testLogger(), stdinR, stdoutW, pairing)

	require.NoError(t, WriteMessage(stdinW, &NativeMessage{Type: MsgTypePairingConfirm, Code: ""}))

	errCh := make(chan error, 1)
	go func() {
		errCh <- host.awaitPairingConfirmation(make([]byte, X25519KeySize), "origin")
	}()

	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypePairingFailed, resp.Type)
	assert.Contains(t, resp.Error, "pairing code is required")

	err = <-errCh
	assert.ErrorIs(t, err, ErrPairingInvalidCode)
}

// TestAwaitPairingConfirmation_InvalidIdentityKeyEncoding covers a
// pairing_confirm whose identity_key is not valid base64.
func TestAwaitPairingConfirmation_InvalidIdentityKeyEncoding(t *testing.T) {
	tmpDir := t.TempDir()
	pairing, err := NewPairingVerifier(filepath.Join(tmpDir, "pairing.json"))
	require.NoError(t, err)
	code, err := pairing.StartPairing(nil, "origin")
	require.NoError(t, err)

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)
	host := NewHostWithIO("", testLogger(), stdinR, stdoutW, pairing)

	require.NoError(t, WriteMessage(stdinW, &NativeMessage{
		Type:        MsgTypePairingConfirm,
		Code:        code,
		IdentityKey: "not-valid-base64!!!",
	}))

	errCh := make(chan error, 1)
	go func() {
		errCh <- host.awaitPairingConfirmation(make([]byte, X25519KeySize), "origin")
	}()

	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypePairingFailed, resp.Type)
	assert.Contains(t, resp.Error, "invalid identity key encoding")

	err = <-errCh
	assert.ErrorIs(t, err, ErrPairingRejected)
}

// TestAwaitPairingConfirmation_MalformedFrame covers a non-EOF read failure
// while waiting for pairing_confirm (e.g. the extension sent a corrupted
// frame). This must not be classified as a clean disconnect.
func TestAwaitPairingConfirmation_MalformedFrame(t *testing.T) {
	tmpDir := t.TempDir()
	pairing, err := NewPairingVerifier(filepath.Join(tmpDir, "pairing.json"))
	require.NoError(t, err)
	_, err = pairing.StartPairing(nil, "origin")
	require.NoError(t, err)

	stdinR, stdinW := osPipe(t)
	_, stdoutW := osPipe(t)
	host := NewHostWithIO("", testLogger(), stdinR, stdoutW, pairing)

	// A length prefix over MaxMessageSize is rejected by ReadMessage before
	// it ever reads a payload.
	rawFrame(t, stdinW, MaxMessageSize+1)

	err = host.awaitPairingConfirmation(make([]byte, X25519KeySize), "origin")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingRejected)
	assert.ErrorIs(t, err, ErrMessageTooLarge)
	assert.False(t, isEOF(err), "an oversized frame must not be treated as a clean disconnect")
}

// TestAwaitPairingConfirmation_CodeExpired covers the "timeout" case: the
// extension submits the correct code, but only after it expired.
func TestAwaitPairingConfirmation_CodeExpired(t *testing.T) {
	tmpDir := t.TempDir()
	pairing, err := NewPairingVerifier(filepath.Join(tmpDir, "pairing.json"))
	require.NoError(t, err)
	code, err := pairing.StartPairing(nil, "origin")
	require.NoError(t, err)

	// Force the pending ceremony into the past without sleeping.
	pairing.mu.Lock()
	pairing.pending.expiresAt = time.Now().Add(-time.Minute)
	pairing.mu.Unlock()

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)
	host := NewHostWithIO("", testLogger(), stdinR, stdoutW, pairing)

	require.NoError(t, WriteMessage(stdinW, &NativeMessage{Type: MsgTypePairingConfirm, Code: code}))

	errCh := make(chan error, 1)
	go func() {
		errCh <- host.awaitPairingConfirmation(make([]byte, X25519KeySize), "origin")
	}()

	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypePairingFailed, resp.Type)

	err = <-errCh
	assert.ErrorIs(t, err, ErrPairingExpired)
	assert.False(t, pairing.IsPaired())
}

// TestAwaitPairingConfirmation_SendPairingFailedWriteFailure covers the
// defensive log-only branch taken when the pairing_failed response itself
// cannot be written to stdout. The original completion error must still be
// returned, not the write failure.
func TestAwaitPairingConfirmation_SendPairingFailedWriteFailure(t *testing.T) {
	tmpDir := t.TempDir()
	pairing, err := NewPairingVerifier(filepath.Join(tmpDir, "pairing.json"))
	require.NoError(t, err)
	_, err = pairing.StartPairing(nil, "origin")
	require.NoError(t, err)

	stdinR, stdinW := osPipe(t)
	logger, logs := bufLogger()
	host := NewHostWithIO("", logger, stdinR, &failFirstNWriter{remaining: 1}, pairing)

	// Wrong code triggers CompletePairing's failure path, which tries to
	// write pairing_failed and fails.
	require.NoError(t, WriteMessage(stdinW, &NativeMessage{Type: MsgTypePairingConfirm, Code: "000000"}))

	err = host.awaitPairingConfirmation(make([]byte, X25519KeySize), "origin")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingInvalidCode, "the completion error must win over the write failure")
	assert.Contains(t, logs.String(), "failed to write pairing_failed")
}

// TestAwaitPairingConfirmation_NotifyCompletedFailureIsNonFatal covers the
// warn-only branch when the GUI/headless IPC server cannot be reached to
// announce pairing completion. The ceremony must still succeed from the
// extension's point of view.
func TestAwaitPairingConfirmation_NotifyCompletedFailureIsNonFatal(t *testing.T) {
	tmpDir := t.TempDir()
	pairing, err := NewPairingVerifier(filepath.Join(tmpDir, "pairing.json"))
	require.NoError(t, err)

	extIdentityPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	code, err := pairing.StartPairing(extIdentityPub, "origin")
	require.NoError(t, err)

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)
	logger, logs := bufLogger()

	// No listener on this socket: notifyPairingCompleted's IPC round trip
	// will fail, but the ceremony must still complete.
	deadSocket := filepath.Join(tmpDir, "nonexistent.sock")
	host := NewHostWithIO(deadSocket, logger, stdinR, stdoutW, pairing)

	require.NoError(t, WriteMessage(stdinW, &NativeMessage{
		Type:        MsgTypePairingConfirm,
		Code:        code,
		IdentityKey: base64.StdEncoding.EncodeToString(extIdentityPub),
	}))

	err = host.awaitPairingConfirmation(make([]byte, X25519KeySize), "origin")
	require.NoError(t, err)

	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypePairingOK, resp.Type)

	assert.True(t, pairing.IsPaired())
	assert.Contains(t, logs.String(), "failed to notify IPC server of pairing completion")
}

// --- relayLoop ---

// TestRelayLoop_ContextAlreadyCancelled proves relayLoop checks ctx.Done()
// before ever blocking on a read: stdin panics if touched.
func TestRelayLoop_ContextAlreadyCancelled(t *testing.T) {
	host := NewHostWithIO("", testLogger(), panicReader{t}, &bytes.Buffer{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := host.relayLoop(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestRelayLoop_EOFAuditFailurePropagates proves a failing audit write on
// the clean-disconnect path is surfaced to the caller instead of swallowed.
func TestRelayLoop_EOFAuditFailurePropagates(t *testing.T) {
	stdinR, stdinW := osPipe(t)
	require.NoError(t, stdinW.Close()) // immediate EOF

	host := NewHostWithIO("", testLogger(), stdinR, &bytes.Buffer{}, nil)
	al := &mockHostAuditLogger{logErr: errors.New("audit store unavailable")}
	host.SetAuditLogger(al)

	err := host.relayLoop(context.Background())
	require.Error(t, err)
	assert.Equal(t, al.logErr, err)
	require.Len(t, al.entries, 1)
	assert.Equal(t, audit.OpExtensionDisconnected, al.entries[0].Operation)
}

// TestRelayLoop_NonEOFReadErrorStopsTheLoop covers a malformed frame in the
// steady-state relay loop (not the pairing ceremony): it must be reported,
// not treated as a clean disconnect.
func TestRelayLoop_NonEOFReadErrorStopsTheLoop(t *testing.T) {
	stdinR, stdinW := osPipe(t)
	rawFrame(t, stdinW, MaxMessageSize+1)

	host := NewHostWithIO("", testLogger(), stdinR, &bytes.Buffer{}, nil)

	err := host.relayLoop(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMessageTooLarge)
	assert.False(t, isEOF(err))
}

// TestRelayLoop_UnexpectedMessageTypeIsReportedAndLoopContinues covers a
// non-"encrypted" message arriving mid-session: the loop must report the
// error and keep serving the connection rather than exit.
func TestRelayLoop_UnexpectedMessageTypeIsReportedAndLoopContinues(t *testing.T) {
	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO("", testLogger(), stdinR, stdoutW, nil)

	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- host.relayLoop(context.Background())
	}()

	require.NoError(t, WriteMessage(stdinW, &NativeMessage{Type: MsgTypeHandshake}))

	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeError, resp.Type)
	assert.Contains(t, resp.Error, "expected encrypted message")

	// The loop must still be alive: close stdin for a clean shutdown.
	require.NoError(t, stdinW.Close())
	wg.Wait()
	assert.NoError(t, <-errCh)
}

// TestRelayLoop_UnexpectedMessageType_WriteErrorIsLoggedNotFatal covers the
// defensive branch where the loop cannot even write the "expected encrypted
// message" error back to the extension. The loop must not crash; it logs
// and keeps running.
func TestRelayLoop_UnexpectedMessageType_WriteErrorIsLoggedNotFatal(t *testing.T) {
	stdinR, stdinW := osPipe(t)
	logger, logs := bufLogger()

	// The very first stdout write (the "expected encrypted message" error
	// response) fails; nothing has been written yet in this test.
	host := NewHostWithIO("", logger, stdinR, &failFirstNWriter{remaining: 2}, nil)

	require.NoError(t, WriteMessage(stdinW, &NativeMessage{Type: MsgTypeHandshake}))
	require.NoError(t, stdinW.Close())

	err := host.relayLoop(context.Background())
	assert.NoError(t, err, "a write failure while reporting an error must not itself terminate the loop")
	assert.Contains(t, logs.String(), "failed to write error response")
}

// TestRelayLoop_EncryptedMessageAuditFailureIsLoggedNotFatal covers the
// defensive branch where handleEncryptedMessage fails and the audit write
// about that failure *also* fails. The loop logs both and continues, rather
// than losing the relay error while chasing an audit error.
func TestRelayLoop_EncryptedMessageAuditFailureIsLoggedNotFatal(t *testing.T) {
	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)
	logger, logs := bufLogger()

	host := NewHostWithIO("", logger, stdinR, stdoutW, nil)
	al := &mockHostAuditLogger{logErr: errors.New("audit store unavailable")}
	host.SetAuditLogger(al)

	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- host.relayLoop(context.Background())
	}()

	// Invalid base64 ciphertext fails before host.crypto is ever touched, so
	// this does not require a completed handshake.
	require.NoError(t, WriteMessage(stdinW, &NativeMessage{
		Type:       MsgTypeEncrypted,
		Ciphertext: "not-valid-base64!!!",
	}))

	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeError, resp.Type)

	require.NoError(t, stdinW.Close())
	wg.Wait()

	// The disconnect-audit call on EOF also uses the same failing logger,
	// so the loop's final return is that audit failure.
	require.Error(t, <-errCh)
	assert.Contains(t, logs.String(), "audit log failed")

	var sawRelay bool
	for _, e := range al.entries {
		if e.Operation == audit.OpExtensionRelay {
			sawRelay = true
		}
	}
	assert.True(t, sawRelay, "the relay failure must have been audited")
}

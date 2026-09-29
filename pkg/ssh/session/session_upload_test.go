// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package session_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/session"
)

// dialPinned spins up a pinned, host-key-verified session against srv using
// a fresh enclave-backed client key. The session owns the key on success;
// callers defer sess.Close(). The bool return is false when the handshake
// was refused for the expected GODEBUG=fips140=only reason (see
// requireHandshake); the caller must return immediately in that case.
func dialPinned(t *testing.T, srv *testServer, hostSigner ssh.Signer) (session.Session, bool) {
	t.Helper()
	store, sc := pinHost(t, srv.host(), hostSigner, "alice")
	clientKey := generateClientKey(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	sess, err := session.Dial(ctx, session.DialRequest{
		Host:            srv.host(),
		Port:            srv.port(),
		User:            "testuser",
		Key:             clientKey,
		HostKeyScope:    sc,
		HostKeyOwner:    "alice",
		KnownHostsStore: store,
		Timeout:         3 * time.Second,
	})
	if !requireHandshake(t, err) {
		clientKey.Destroy()
		return nil, false
	}
	return sess, true
}

// execCommand extracts the command string from an "exec" request payload.
func execCommand(req *ssh.Request) string {
	if len(req.Payload) < 4 {
		return ""
	}
	n := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
	if 4+n > len(req.Payload) {
		return ""
	}
	return string(req.Payload[4 : 4+n])
}

// uploadResult carries what a capturing upload handler observed.
type uploadResult struct {
	cmd  string
	data []byte
}

// captureUploadHandler returns an exec handler that records the command and
// the full stdin stream, then exits 0. The result is delivered on resCh.
func captureUploadHandler(resCh chan<- uploadResult) func(ch ssh.Channel, req *ssh.Request) {
	return func(ch ssh.Channel, req *ssh.Request) {
		cmd := execCommand(req)
		req.Reply(true, nil)
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, ch)
		resCh <- uploadResult{cmd: cmd, data: buf.Bytes()}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	}
}

// TestUpload_StreamsPayloadAndBuildsCommand verifies the payload arrives
// byte-for-byte and that the remote command stages a .partial file, chmods
// it to the requested mode, and atomically renames it onto the final path.
func TestUpload_StreamsPayloadAndBuildsCommand(t *testing.T) {
	hostSigner := generateHostSigner(t)
	resCh := make(chan uploadResult, 1)
	srv := newTestServer(t, hostSigner, captureUploadHandler(resCh))
	defer srv.close()

	sess, ok := dialPinned(t, srv, hostSigner)
	if !ok {
		return
	}
	defer sess.Close()

	payload := []byte("streamed ISO payload \x00\x01\x02\xff binary data spanning bytes")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sess.Upload(ctx, bytes.NewReader(payload), "/data/test.iso", 0o644); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	res := <-resCh
	if !bytes.Equal(res.data, payload) {
		t.Fatalf("streamed payload mismatch:\n got %q\nwant %q", res.data, payload)
	}
	for _, want := range []string{
		"cat > '/data/test.iso.partial'",
		"chmod 0644 '/data/test.iso.partial'",
		"mv -f '/data/test.iso.partial' '/data/test.iso'",
	} {
		if !strings.Contains(res.cmd, want) {
			t.Fatalf("remote command %q missing %q", res.cmd, want)
		}
	}
}

// TestUpload_ZeroModeSkipsChmod asserts a zero FileMode preserves the remote
// umask default — no chmod is emitted, but the .partial stage + atomic
// rename are still present.
func TestUpload_ZeroModeSkipsChmod(t *testing.T) {
	hostSigner := generateHostSigner(t)
	resCh := make(chan uploadResult, 1)
	srv := newTestServer(t, hostSigner, captureUploadHandler(resCh))
	defer srv.close()

	sess, ok := dialPinned(t, srv, hostSigner)
	if !ok {
		return
	}
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sess.Upload(ctx, strings.NewReader("payload"), "/srv/file.bin", 0); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	res := <-resCh
	if strings.Contains(res.cmd, "chmod") {
		t.Fatalf("expected no chmod for zero mode, got %q", res.cmd)
	}
	if !strings.Contains(res.cmd, "mv -f '/srv/file.bin.partial' '/srv/file.bin'") {
		t.Fatalf("remote command %q missing atomic rename", res.cmd)
	}
}

// TestUpload_RejectsSingleQuotePath locks in the fail-closed quoting policy:
// a path containing a single quote is rejected before any exec runs.
func TestUpload_RejectsSingleQuotePath(t *testing.T) {
	hostSigner := generateHostSigner(t)
	srv := newTestServer(t, hostSigner, echoHandler)
	defer srv.close()

	sess, ok := dialPinned(t, srv, hostSigner)
	if !ok {
		return
	}
	defer sess.Close()

	err := sess.Upload(context.Background(), strings.NewReader("x"), "/data/it's.iso", 0o644)
	var up *session.UnsafePathError
	if !errors.As(err, &up) {
		t.Fatalf("expected UnsafePathError, got %T: %v", err, err)
	}
	if up.Path != "/data/it's.iso" {
		t.Fatalf("unexpected path in error: %q", up.Path)
	}
}

// TestUpload_NilSrc rejects a nil reader with a NilInputError.
func TestUpload_NilSrc(t *testing.T) {
	hostSigner := generateHostSigner(t)
	srv := newTestServer(t, hostSigner, echoHandler)
	defer srv.close()

	sess, ok := dialPinned(t, srv, hostSigner)
	if !ok {
		return
	}
	defer sess.Close()

	err := sess.Upload(context.Background(), nil, "/data/file", 0o644)
	var nie *session.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError, got %T: %v", err, err)
	}
	if nie.Field != "src" {
		t.Fatalf("expected Field=src, got %q", nie.Field)
	}
}

// TestUpload_EmptyPath rejects an empty remote path with a NilInputError.
func TestUpload_EmptyPath(t *testing.T) {
	hostSigner := generateHostSigner(t)
	srv := newTestServer(t, hostSigner, echoHandler)
	defer srv.close()

	sess, ok := dialPinned(t, srv, hostSigner)
	if !ok {
		return
	}
	defer sess.Close()

	err := sess.Upload(context.Background(), strings.NewReader("x"), "", 0o644)
	var nie *session.NilInputError
	if !errors.As(err, &nie) {
		t.Fatalf("expected NilInputError, got %T: %v", err, err)
	}
	if nie.Field != "remotePath" {
		t.Fatalf("expected Field=remotePath, got %q", nie.Field)
	}
}

// TestUpload_AfterClose_ReturnsClosedError rejects uploads on a closed
// session.
func TestUpload_AfterClose_ReturnsClosedError(t *testing.T) {
	hostSigner := generateHostSigner(t)
	srv := newTestServer(t, hostSigner, echoHandler)
	defer srv.close()

	sess, ok := dialPinned(t, srv, hostSigner)
	if !ok {
		return
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err := sess.Upload(context.Background(), strings.NewReader("x"), "/data/file", 0o644)
	var ce *session.ClosedError
	if !errors.As(err, &ce) {
		t.Fatalf("expected ClosedError, got %T: %v", err, err)
	}
}

// TestUpload_NonZeroExit surfaces a CommandError carrying the remote exit
// code and stderr when the remote write/rename pipeline fails.
func TestUpload_NonZeroExit(t *testing.T) {
	hostSigner := generateHostSigner(t)
	failHandler := func(ch ssh.Channel, req *ssh.Request) {
		req.Reply(true, nil)
		_, _ = io.Copy(io.Discard, ch)
		ch.Stderr().Write([]byte("No space left on device"))
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
	}
	srv := newTestServer(t, hostSigner, failHandler)
	defer srv.close()

	sess, ok := dialPinned(t, srv, hostSigner)
	if !ok {
		return
	}
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := sess.Upload(ctx, strings.NewReader("payload"), "/data/file", 0o644)
	var ce *session.CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("expected CommandError, got %T: %v", err, err)
	}
	if ce.ExitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", ce.ExitCode)
	}
	if !strings.Contains(ce.Stderr, "No space left on device") {
		t.Fatalf("expected remote stderr in CommandError, got %q", ce.Stderr)
	}
}

// TestUpload_ContextCancellation aborts an in-flight upload when the context
// fires and surfaces a TimeoutError. The server accepts the exec but never
// reports completion, so only cancellation can unblock the client.
func TestUpload_ContextCancellation(t *testing.T) {
	hostSigner := generateHostSigner(t)
	done := make(chan struct{})
	blockHandler := func(ch ssh.Channel, req *ssh.Request) {
		req.Reply(true, nil)
		// Never drain stdin to completion, never send exit-status: hold the
		// channel open until teardown so only ctx cancellation unblocks the
		// client.
		<-done
	}
	srv := newTestServer(t, hostSigner, blockHandler)
	defer func() {
		close(done)
		srv.close()
	}()

	sess, ok := dialPinned(t, srv, hostSigner)
	if !ok {
		return
	}
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := sess.Upload(ctx, strings.NewReader("payload that will not complete"), "/data/file", 0o644)
	var te *session.TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("expected TimeoutError on cancellation, got %T: %v", err, err)
	}
}

// TestUploadError_ErrorAndUnwrap covers the UploadError string + unwrap.
func TestUploadError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("broken pipe")
	e := &session.UploadError{Path: "/data/file", Err: inner}
	if e.Error() == "" {
		t.Fatal("UploadError.Error() returned empty string")
	}
	if !errors.Is(e, inner) {
		t.Fatal("UploadError.Unwrap() should expose inner error")
	}
}

// TestUnsafePathError_Error covers the UnsafePathError string.
func TestUnsafePathError_Error(t *testing.T) {
	e := &session.UnsafePathError{Path: "/x'y", Reason: "bad"}
	if !strings.Contains(e.Error(), "/x'y") {
		t.Fatalf("UnsafePathError.Error() = %q, expected to contain path", e.Error())
	}
}

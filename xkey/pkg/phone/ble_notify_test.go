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

package phone

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
)

// errNotifyWrite is the transport failure injected by captureWriter.
var errNotifyWrite = errors.New("test: notify write failed")

// captureWriter is an in-memory FragmentWriter. It records every fragment it
// accepts and can be configured to fail or truncate a specific write, which is
// how the notify path is exercised without Bluetooth hardware.
// The handler goroutine writes while the test goroutine inspects what was
// captured, so every access to fragments is guarded by mu.
type captureWriter struct {
	mu        sync.Mutex
	fragments [][]byte

	// complete is closed as soon as a fragment carrying FlagLastFragment has
	// been captured, so a test can wait for a whole message instead of
	// sleeping for one.
	complete chan struct{}

	// failAt is the index of the write that returns errNotifyWrite.
	// Negative disables the failure.
	failAt int

	// shortAt is the index of the write that reports fewer bytes written
	// than it was given. Negative disables truncation.
	shortAt int

	// shortBy is the number of bytes to under-report at shortAt.
	shortBy int
}

func newCaptureWriter() *captureWriter {
	return &captureWriter{failAt: -1, shortAt: -1, complete: make(chan struct{})}
}

// signalComplete closes the complete channel the first time a message has been
// fully captured. The caller must hold w.mu.
func (w *captureWriter) signalComplete(fragment []byte) {
	if len(fragment) < FragmentHeaderSize || fragment[0]&FlagLastFragment == 0 {
		return
	}
	select {
	case <-w.complete:
	default:
		close(w.complete)
	}
}

// waitForCompleteMessage blocks until a whole message has been captured or ctx
// is done, in which case the test fails rather than reassembling a partial
// message.
func (w *captureWriter) waitForCompleteMessage(ctx context.Context, t *testing.T) {
	t.Helper()

	select {
	case <-w.complete:
	case <-ctx.Done():
		t.Fatalf("no complete message was notified: %v (captured %d fragment(s))",
			ctx.Err(), w.count())
	}
}

func (w *captureWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	index := len(w.fragments)
	if w.failAt >= 0 && index == w.failAt {
		return 0, errNotifyWrite
	}

	cp := make([]byte, len(p))
	copy(cp, p)
	w.fragments = append(w.fragments, cp)

	w.signalComplete(cp)

	if w.shortAt >= 0 && index == w.shortAt {
		return len(p) - w.shortBy, nil
	}
	return len(p), nil
}

// snapshot returns a copy of the fragment slice header, so callers can iterate
// it without holding the lock while the handler goroutine keeps writing.
func (w *captureWriter) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()

	out := make([][]byte, len(w.fragments))
	copy(out, w.fragments)
	return out
}

// count reports how many fragments have been captured so far.
func (w *captureWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return len(w.fragments)
}

// fragment returns the fragment recorded at index i.
func (w *captureWriter) fragment(i int) []byte {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.fragments[i]
}

// reassemble decodes and reassembles everything the writer captured, exactly
// as the peer's receive path does.
func (w *captureWriter) reassemble(t *testing.T) []byte {
	t.Helper()

	fragments := w.snapshot()

	r := NewReassembler()
	for i, raw := range fragments {
		frag, err := DecodeFragment(raw)
		if err != nil {
			t.Fatalf("fragment %d failed to decode: %v", i, err)
		}
		complete, err := r.AddFragment(frag)
		if err != nil {
			t.Fatalf("fragment %d failed to reassemble: %v", i, err)
		}
		if complete && i != len(fragments)-1 {
			t.Fatalf("message completed early at fragment %d of %d", i, len(fragments))
		}
	}
	if !r.IsComplete() {
		received, total := r.Progress()
		t.Fatalf("message incomplete: %d of %d fragments", received, total)
	}
	message, err := r.Assemble()
	if err != nil {
		t.Fatalf("assemble failed: %v", err)
	}
	return message
}

// payload returns a deterministic message of the requested size.
func payload(size int) []byte {
	msg := make([]byte, size)
	for i := range msg {
		msg[i] = byte(i%251 + 1)
	}
	return msg
}

func TestFragmentSender_SendSingleFragment(t *testing.T) {
	writer := newCaptureWriter()
	sender := newFragmentSender(writer, NewFragmenter(DefaultMTU-bleNotifyOverhead), nil)

	message := payload(32)
	if err := sender.send(context.Background(), message); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	if writer.count() != 1 {
		t.Fatalf("expected 1 fragment, got %d", writer.count())
	}
	got := writer.reassemble(t)
	if string(got) != string(message) {
		t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(message))
	}
}

func TestFragmentSender_SendMultiFragment(t *testing.T) {
	tests := []struct {
		name         string
		mtu          int
		size         int
		wantFragment int
	}{
		{name: "two fragments at default MTU", mtu: DefaultMTU - bleNotifyOverhead, size: 400, wantFragment: 2},
		{name: "many fragments at default MTU", mtu: DefaultMTU - bleNotifyOverhead, size: 4096, wantFragment: 18},
		{name: "minimum MTU", mtu: MinMTU, size: 100, wantFragment: 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := newCaptureWriter()
			sender := newFragmentSender(writer, NewFragmenter(tt.mtu), nil)

			message := payload(tt.size)
			if err := sender.send(context.Background(), message); err != nil {
				t.Fatalf("send failed: %v", err)
			}

			if writer.count() != tt.wantFragment {
				t.Fatalf("expected %d fragments, got %d", tt.wantFragment, writer.count())
			}
			for i, frag := range writer.snapshot() {
				if len(frag) > tt.mtu {
					t.Fatalf("fragment %d is %d bytes, exceeds MTU %d", i, len(frag), tt.mtu)
				}
			}

			got := writer.reassemble(t)
			if string(got) != string(message) {
				t.Fatalf("round trip mismatch for %d byte message", tt.size)
			}
		})
	}
}

func TestFragmentSender_SendEmptyPayload(t *testing.T) {
	writer := newCaptureWriter()
	sender := newFragmentSender(writer, NewFragmenter(DefaultMTU-bleNotifyOverhead), nil)

	if err := sender.send(context.Background(), nil); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// An empty message is still a message: the peer must see one header-only
	// fragment so it can complete the reassembly.
	if writer.count() != 1 {
		t.Fatalf("expected 1 fragment for empty payload, got %d", writer.count())
	}
	if len(writer.fragment(0)) != FragmentHeaderSize {
		t.Fatalf("expected header-only fragment, got %d bytes", len(writer.fragment(0)))
	}
	if got := writer.reassemble(t); len(got) != 0 {
		t.Fatalf("expected empty message, got %d bytes", len(got))
	}
}

func TestFragmentSender_ShortWriteAborts(t *testing.T) {
	writer := newCaptureWriter()
	writer.shortAt = 1
	writer.shortBy = 3
	sender := newFragmentSender(writer, NewFragmenter(DefaultMTU-bleNotifyOverhead), nil)

	err := sender.send(context.Background(), payload(4096))
	if err == nil {
		t.Fatal("expected a short write to fail the send")
	}

	var shortErr *ShortWriteError
	if !errors.As(err, &shortErr) {
		t.Fatalf("expected *ShortWriteError, got %T: %v", err, err)
	}
	if shortErr.Index != 1 {
		t.Fatalf("expected failure on fragment 1, got %d", shortErr.Index)
	}
	if shortErr.Written != shortErr.Size-3 {
		t.Fatalf("expected %d bytes written, got %d", shortErr.Size-3, shortErr.Written)
	}
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected errors.Is(err, io.ErrShortWrite), got %v", err)
	}
	// The send must stop at the truncated fragment, not push the rest.
	if writer.count() != 2 {
		t.Fatalf("expected the send to abort after 2 writes, got %d", writer.count())
	}
	if shortErr.Error() == "" {
		t.Fatal("expected a non-empty error message")
	}
}

func TestFragmentSender_WriteErrorMidStreamAborts(t *testing.T) {
	writer := newCaptureWriter()
	writer.failAt = 2
	sender := newFragmentSender(writer, NewFragmenter(DefaultMTU-bleNotifyOverhead), nil)

	err := sender.send(context.Background(), payload(4096))
	if err == nil {
		t.Fatal("expected a transport failure to fail the send")
	}

	var writeErr *FragmentWriteError
	if !errors.As(err, &writeErr) {
		t.Fatalf("expected *FragmentWriteError, got %T: %v", err, err)
	}
	if writeErr.Index != 2 {
		t.Fatalf("expected failure on fragment 2, got %d", writeErr.Index)
	}
	if writeErr.Total != 18 {
		t.Fatalf("expected 18 total fragments, got %d", writeErr.Total)
	}
	if !errors.Is(err, errNotifyWrite) {
		t.Fatalf("expected the transport error to be preserved, got %v", err)
	}
	// Fragments 0 and 1 were accepted; nothing after the failure is sent.
	if writer.count() != 2 {
		t.Fatalf("expected the send to abort after 2 writes, got %d", writer.count())
	}
	if writeErr.Error() == "" {
		t.Fatal("expected a non-empty error message")
	}
}

func TestFragmentSender_FirstWriteErrorAborts(t *testing.T) {
	writer := newCaptureWriter()
	writer.failAt = 0
	sender := newFragmentSender(writer, NewFragmenter(DefaultMTU-bleNotifyOverhead), nil)

	err := sender.send(context.Background(), payload(64))
	if !errors.Is(err, errNotifyWrite) {
		t.Fatalf("expected the transport error, got %v", err)
	}
	if writer.count() != 0 {
		t.Fatalf("expected no fragments to be recorded, got %d", writer.count())
	}
}

func TestFragmentSender_OversizedPayload(t *testing.T) {
	writer := newCaptureWriter()
	// At the minimum MTU each fragment carries 16 payload bytes, so a message
	// larger than 65535*16 bytes cannot be addressed by the 16-bit sequence
	// number and must be rejected outright.
	sender := newFragmentSender(writer, NewFragmenter(MinMTU), nil)

	err := sender.send(context.Background(), payload(65536*(MinMTU-FragmentHeaderSize)))
	if err == nil {
		t.Fatal("expected an oversized payload to be rejected")
	}
	if !errors.Is(err, ErrFragmentationError) {
		t.Fatalf("expected ErrFragmentationError, got %v", err)
	}
	if writer.count() != 0 {
		t.Fatalf("expected nothing to be transmitted, got %d fragments", writer.count())
	}
}

func TestFragmentSender_UnavailableWriter(t *testing.T) {
	tests := []struct {
		name   string
		sender *fragmentSender
	}{
		{name: "nil sender", sender: nil},
		{name: "nil writer", sender: newFragmentSender(nil, NewFragmenter(DefaultMTU), nil)},
		{name: "nil fragmenter", sender: newFragmentSender(newCaptureWriter(), nil, nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sender.send(context.Background(), payload(8))
			if !errors.Is(err, ErrNotifyUnavailable) {
				t.Fatalf("expected ErrNotifyUnavailable, got %v", err)
			}
		})
	}
}

func TestFragmentSender_ContextCancelled(t *testing.T) {
	writer := newCaptureWriter()
	sender := newFragmentSender(writer, NewFragmenter(DefaultMTU-bleNotifyOverhead), nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sender.send(ctx, payload(4096))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	var writeErr *FragmentWriteError
	if !errors.As(err, &writeErr) {
		t.Fatalf("expected *FragmentWriteError, got %T", err)
	}
	if writeErr.Index != 0 {
		t.Fatalf("expected the send to abort before the first fragment, got index %d", writeErr.Index)
	}
	if writer.count() != 0 {
		t.Fatalf("expected nothing to be transmitted, got %d fragments", writer.count())
	}
}

func TestFragmentSender_NilLoggerDefaults(t *testing.T) {
	sender := newFragmentSender(newCaptureWriter(), NewFragmenter(DefaultMTU), nil)
	if sender.log == nil {
		t.Fatal("expected a default logger")
	}
}

func TestShortWriteError_Message(t *testing.T) {
	err := &ShortWriteError{Index: 3, Total: 9, Written: 10, Size: 240}
	const want = "phone: short notify write on fragment 3/9: wrote 10 of 240 bytes"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
}

func TestFragmentWriteError_Message(t *testing.T) {
	err := &FragmentWriteError{Index: 1, Total: 4, Err: errNotifyWrite}
	const want = "phone: failed to notify fragment 1/4: test: notify write failed"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, errNotifyWrite) {
		t.Fatal("expected the cause to be preserved")
	}
}

func TestSafeSlice_NilData(t *testing.T) {
	if result := safeSlice(nil, 0, 16); result != nil {
		t.Fatalf("expected nil for nil data, got %v", result)
	}
}

func TestSafeSlice_EmptyData(t *testing.T) {
	if result := safeSlice([]byte{}, 0, 16); result != nil {
		t.Fatalf("expected nil for empty data, got %v", result)
	}
}

func TestSafeSlice_StartBeyondLength(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	if result := safeSlice(data, 10, 16); result != nil {
		t.Fatalf("expected nil when start > len(data), got %v", result)
	}
}

func TestSafeSlice_StartAtLength(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	if result := safeSlice(data, 3, 16); result != nil {
		t.Fatalf("expected nil when start == len(data), got %v", result)
	}
}

func TestSafeSlice_ShorterThanMax(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	result := safeSlice(data, 0, 16)
	if len(result) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(result))
	}
	for i, b := range data {
		if result[i] != b {
			t.Fatalf("byte %d: expected %x, got %x", i, b, result[i])
		}
	}
}

func TestSafeSlice_ExactMax(t *testing.T) {
	data := payload(16)
	if result := safeSlice(data, 0, 16); len(result) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(result))
	}
}

func TestSafeSlice_TruncatesLonger(t *testing.T) {
	data := payload(64)
	result := safeSlice(data, 0, 16)
	if len(result) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(result))
	}
	if result[15] != data[15] {
		t.Fatalf("expected byte 15 to be %x, got %x", data[15], result[15])
	}
}

func TestSafeSlice_WithOffset(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	result := safeSlice(data, 2, 3)
	if len(result) != 3 {
		t.Fatalf("expected 3 bytes, got %d", len(result))
	}
	if result[0] != 0x02 || result[1] != 0x03 || result[2] != 0x04 {
		t.Fatalf("expected [02 03 04], got %v", result)
	}
}

func TestSafeSlice_OffsetClipsEnd(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03}
	result := safeSlice(data, 2, 16)
	if len(result) != 2 {
		t.Fatalf("expected 2 bytes (clipped), got %d", len(result))
	}
	if result[0] != 0x02 || result[1] != 0x03 {
		t.Fatalf("expected [02 03], got %v", result)
	}
}

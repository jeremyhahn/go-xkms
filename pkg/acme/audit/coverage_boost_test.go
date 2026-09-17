//go:build codec_json

package audit

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errForcedWrite is a sentinel error for the failing writer.
var errForcedWrite = errors.New("forced write error")

// failingWriter is an io.WriteCloser that always returns an error on Write.
type failingWriter struct {
	closed bool
}

func (w *failingWriter) Write(p []byte) (int, error) {
	return 0, errForcedWrite
}

func (w *failingWriter) Close() error {
	w.closed = true
	return nil
}

// newTestAuditEvent creates a valid audit event for testing.
func newTestAuditEvent() *AuditEvent {
	return &AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: EventCertificateIssued,
		Actor:     "account:test",
		Resource:  "order:test",
		Action:    "issue",
		Result:    ResultSuccess,
	}
}

// TestCoverageBoost_WriteEvent_MarshalError tests writeEvent when the codec
// returns a marshal error (e.g., unmarshalable value in Details).
func TestCoverageBoost_WriteEvent_MarshalError(t *testing.T) {
	fw := &failingWriter{}
	logger := &FileAuditLogger{
		writer:  fw,
		codec:   DefaultCodec(),
		buffer:  make(chan *AuditEvent, 10),
		enabled: true,
	}

	// Create an event with a channel in Details which cannot be marshaled to JSON
	event := newTestAuditEvent()
	event.Details = map[string]interface{}{
		"unmarshalable": make(chan int),
	}

	err := logger.writeEvent(event)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal")
}

// TestCoverageBoost_WriteEvent_WriteError tests writeEvent when the writer
// returns an error on the data write.
func TestCoverageBoost_WriteEvent_WriteError(t *testing.T) {
	fw := &failingWriter{}
	logger := &FileAuditLogger{
		writer:  fw,
		codec:   DefaultCodec(),
		buffer:  make(chan *AuditEvent, 10),
		enabled: true,
	}

	event := newTestAuditEvent()

	err := logger.writeEvent(event)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write event data")
}

// countingWriter counts Write calls and fails on the second Write (the newline).
type countingWriter struct {
	callCount int
	failAfter int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.callCount++
	if w.callCount > w.failAfter {
		return 0, errForcedWrite
	}
	return len(p), nil
}

func (w *countingWriter) Close() error {
	return nil
}

// TestCoverageBoost_WriteEvent_NewlineWriteError tests writeEvent when the
// newline write (second Write call) fails.
func TestCoverageBoost_WriteEvent_NewlineWriteError(t *testing.T) {
	cw := &countingWriter{failAfter: 1} // First write succeeds, second fails
	logger := &FileAuditLogger{
		writer:  cw,
		codec:   DefaultCodec(),
		buffer:  make(chan *AuditEvent, 10),
		enabled: true,
	}

	event := newTestAuditEvent()

	err := logger.writeEvent(event)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write event newline")
}

// TestCoverageBoost_DrainBuffer_WriteError tests drainBuffer when writeEvent
// returns an error. The drainBuffer function logs the error to stderr but
// continues processing.
func TestCoverageBoost_DrainBuffer_WriteError(t *testing.T) {
	fw := &failingWriter{}
	buf := make(chan *AuditEvent, 10)
	logger := &FileAuditLogger{
		writer:  fw,
		codec:   DefaultCodec(),
		buffer:  buf,
		enabled: true,
	}

	// Put an event in the buffer
	event := newTestAuditEvent()
	buf <- event

	// drainBuffer should not panic even when writeEvent fails
	logger.drainBuffer()

	// Buffer should be drained
	assert.Equal(t, 0, len(buf))
}

// TestCoverageBoost_DrainBufferInternal_WriteError tests drainBufferInternal
// when writeEvent returns an error.
func TestCoverageBoost_DrainBufferInternal_WriteError(t *testing.T) {
	fw := &failingWriter{}
	buf := make(chan *AuditEvent, 10)
	logger := &FileAuditLogger{
		writer:  fw,
		codec:   DefaultCodec(),
		buffer:  buf,
		enabled: true,
	}

	event := newTestAuditEvent()
	buf <- event

	err := logger.drainBufferInternal()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write event data")
}

// TestCoverageBoost_DrainBuffer_ChannelClosed tests drainBuffer when the
// buffer channel is closed.
func TestCoverageBoost_DrainBuffer_ChannelClosed(t *testing.T) {
	buf := make(chan *AuditEvent, 10)
	logger := &FileAuditLogger{
		writer:  &countingWriter{failAfter: 100},
		codec:   DefaultCodec(),
		buffer:  buf,
		enabled: true,
	}

	// Put an event, then close the channel
	event := newTestAuditEvent()
	buf <- event
	close(buf)

	// drainBuffer should handle closed channel gracefully
	logger.drainBuffer()
}

// TestCoverageBoost_DrainBufferInternal_ChannelClosed tests drainBufferInternal
// when the buffer channel is closed.
func TestCoverageBoost_DrainBufferInternal_ChannelClosed(t *testing.T) {
	buf := make(chan *AuditEvent, 10)
	logger := &FileAuditLogger{
		writer:  &countingWriter{failAfter: 100},
		codec:   DefaultCodec(),
		buffer:  buf,
		enabled: true,
	}

	event := newTestAuditEvent()
	buf <- event
	close(buf)

	err := logger.drainBufferInternal()
	require.NoError(t, err)
}

// TestCoverageBoost_DrainBuffer_EmptyBuffer tests drainBuffer with an empty
// buffer returns immediately.
func TestCoverageBoost_DrainBuffer_EmptyBuffer(t *testing.T) {
	buf := make(chan *AuditEvent, 10)
	logger := &FileAuditLogger{
		writer:  &countingWriter{failAfter: 100},
		codec:   DefaultCodec(),
		buffer:  buf,
		enabled: true,
	}

	// Should return immediately without blocking
	logger.drainBuffer()
}

// TestCoverageBoost_DrainBufferInternal_EmptyBuffer tests drainBufferInternal
// with an empty buffer.
func TestCoverageBoost_DrainBufferInternal_EmptyBuffer(t *testing.T) {
	buf := make(chan *AuditEvent, 10)
	logger := &FileAuditLogger{
		writer:  &countingWriter{failAfter: 100},
		codec:   DefaultCodec(),
		buffer:  buf,
		enabled: true,
	}

	err := logger.drainBufferInternal()
	require.NoError(t, err)
}

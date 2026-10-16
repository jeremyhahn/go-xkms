package presence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

var errAuditWrite = errors.New("audit: write failed")

// presenceEvent is one LogUserPresenceEvent call seen by recordingAuditLogger.
type presenceEvent struct {
	op      audit.OperationType
	source  string
	success bool
	details map[string]any
}

// recordingAuditLogger records user-presence events and fails the
// operation named in failOn. Every other audit.Logger method is left to
// the embedded nil interface: the presence handler must never call them.
type recordingAuditLogger struct {
	audit.Logger

	failOn audit.OperationType

	mu     sync.Mutex
	events []presenceEvent
}

func (l *recordingAuditLogger) LogUserPresenceEvent(op audit.OperationType, source string, success bool, details map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, presenceEvent{op: op, source: source, success: success, details: details})
	if op == l.failOn {
		return errAuditWrite
	}
	return nil
}

func (l *recordingAuditLogger) recorded() []presenceEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]presenceEvent(nil), l.events...)
}

func auditTestRequest(timeout time.Duration) *authenticator.UserPresenceRequest {
	return &authenticator.UserPresenceRequest{
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  "alice",
		Operation: "register",
		Timeout:   timeout,
	}
}

// runPresence starts RequestUserPresence and returns a channel carrying its error.
func runPresence(h *SocketHandler, req *authenticator.UserPresenceRequest) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := h.RequestUserPresence(context.Background(), req)
		done <- err
	}()
	return done
}

func awaitResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("RequestUserPresence did not return")
		return nil
	}
}

func assertOps(t *testing.T, got []presenceEvent, want ...audit.OperationType) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("recorded %d audit events, want %d: %+v", len(got), len(want), got)
	}
	for i, op := range want {
		if got[i].op != op {
			t.Errorf("event %d op = %q, want %q", i, got[i].op, op)
		}
		if got[i].source != "fido2" {
			t.Errorf("event %d source = %q, want fido2", i, got[i].source)
		}
		if got[i].details["rpid"] != "example.com" {
			t.Errorf("event %d rpid = %v, want example.com", i, got[i].details["rpid"])
		}
	}
}

func TestSocketHandler_Audit_ApprovedRecordsRequestAndConfirm(t *testing.T) {
	t.Parallel()

	logger := &recordingAuditLogger{}
	h := NewSocketHandler(nil, newTestLogger())
	h.SetAuditLogger(logger)

	done := runPresence(h, auditTestRequest(5*time.Second))
	waitForPending(t, h, true)
	if !h.Approve() {
		t.Fatal("Approve returned false with a pending request")
	}
	if err := awaitResult(t, done); err != nil {
		t.Fatalf("RequestUserPresence: %v", err)
	}

	events := logger.recorded()
	assertOps(t, events, audit.OpUserPresenceRequested, audit.OpUserPresenceConfirmed)
	if !events[0].success || !events[1].success {
		t.Errorf("request and confirm must be logged as successes: %+v", events)
	}
	if events[0].details["user_name"] != "alice" || events[0].details["rp_name"] != "Example Corp" {
		t.Errorf("request event details = %+v, want user and RP name", events[0].details)
	}
}

func TestSocketHandler_Audit_DeniedRecordsCancel(t *testing.T) {
	t.Parallel()

	logger := &recordingAuditLogger{}
	h := NewSocketHandler(nil, newTestLogger())
	h.SetAuditLogger(logger)

	done := runPresence(h, auditTestRequest(5*time.Second))
	waitForPending(t, h, true)
	h.Deny()
	if err := awaitResult(t, done); !errors.Is(err, authenticator.ErrUserPresenceDenied) {
		t.Fatalf("error = %v, want ErrUserPresenceDenied", err)
	}

	events := logger.recorded()
	assertOps(t, events, audit.OpUserPresenceRequested, audit.OpUserPresenceCancelled)
	if events[1].success {
		t.Error("a denied request must be logged as a failure")
	}
}

func TestSocketHandler_Audit_TimeoutRecordsTimedOut(t *testing.T) {
	t.Parallel()

	logger := &recordingAuditLogger{}
	h := NewSocketHandler(nil, newTestLogger())
	h.SetAuditLogger(logger)

	err := awaitResult(t, runPresence(h, auditTestRequest(20*time.Millisecond)))
	if !errors.Is(err, authenticator.ErrUserPresenceTimeout) {
		t.Fatalf("error = %v, want ErrUserPresenceTimeout", err)
	}

	events := logger.recorded()
	assertOps(t, events, audit.OpUserPresenceRequested, audit.OpUserPresenceTimedOut)
	if events[1].success {
		t.Error("a timed-out request must be logged as a failure")
	}
}

// A request whose audit record cannot be written must fail closed and
// leave nothing pending: a later Approve must not resolve an orphan.
func TestSocketHandler_Audit_RequestLogFailureLeavesNothingPending(t *testing.T) {
	t.Parallel()

	h := NewSocketHandler(nil, newTestLogger())
	h.SetAuditLogger(&recordingAuditLogger{failOn: audit.OpUserPresenceRequested})

	err := awaitResult(t, runPresence(h, auditTestRequest(5*time.Second)))
	if !errors.Is(err, errAuditWrite) {
		t.Fatalf("error = %v, want the audit write error", err)
	}
	if h.HasPending() {
		t.Fatal("a request that failed its audit write is still pending")
	}
	if h.Approve() {
		t.Fatal("Approve resolved a request that already failed")
	}
}

func TestSocketHandler_Audit_ResolutionLogFailureFailsTheRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		failOn  audit.OperationType
		timeout time.Duration
		resolve func(*SocketHandler) bool
	}{
		{name: "confirm", failOn: audit.OpUserPresenceConfirmed, timeout: 5 * time.Second, resolve: (*SocketHandler).Approve},
		{name: "cancel", failOn: audit.OpUserPresenceCancelled, timeout: 5 * time.Second, resolve: (*SocketHandler).Deny},
		{name: "timeout", failOn: audit.OpUserPresenceTimedOut, timeout: 20 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := NewSocketHandler(nil, newTestLogger())
			h.SetAuditLogger(&recordingAuditLogger{failOn: tt.failOn})

			done := runPresence(h, auditTestRequest(tt.timeout))
			if tt.resolve != nil {
				waitForPending(t, h, true)
				tt.resolve(h)
			}
			if err := awaitResult(t, done); !errors.Is(err, errAuditWrite) {
				t.Fatalf("error = %v, want the audit write error", err)
			}
		})
	}
}

package presence

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

// capturingNotifier records every TouchRequest the handler publishes.
type capturingNotifier struct {
	mu   sync.Mutex
	reqs []*notify.TouchRequest
	sent chan *notify.TouchRequest
}

func newCapturingNotifier() *capturingNotifier {
	return &capturingNotifier{sent: make(chan *notify.TouchRequest, 8)}
}

func (n *capturingNotifier) NotifyTouchRequired(req *notify.TouchRequest) error {
	n.mu.Lock()
	n.reqs = append(n.reqs, req)
	n.mu.Unlock()
	n.sent <- req
	return nil
}

func (n *capturingNotifier) Close() error { return nil }

func (n *capturingNotifier) next(t *testing.T) *notify.TouchRequest {
	t.Helper()
	select {
	case req := <-n.sent:
		return req
	case <-time.After(3 * time.Second):
		t.Fatal("no touch notification")
		return nil
	}
}

// TestSocketHandler_LateApprovalForCancelledRequestDoesNotApproveNext covers
// the Codex P1 on #2271 (authenticator.go:1199): a Selection that another
// authenticator wins cancels request A, but A's dialog keeps running; when it
// is approved later, the approval must resolve A only, never the unrelated
// request B that became pending in the meantime. The notification carries
// the request ID and a Done channel closed when A's context ends, so the
// dialog can stop and its touch can name the request it approves.
func TestSocketHandler_LateApprovalForCancelledRequestDoesNotApproveNext(t *testing.T) {
	t.Parallel()
	n := newCapturingNotifier()
	h := NewSocketHandler(n, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctxA, cancelA := context.WithCancel(context.Background())
	doneA := make(chan error, 1)
	go func() {
		_, err := h.RequestUserPresence(ctxA, &authenticator.UserPresenceRequest{
			Operation: "selection", RPID: "a.example", Timeout: 10 * time.Second,
		})
		doneA <- err
	}()
	reqA := n.next(t)
	if reqA.RequestID == "" {
		t.Fatal("touch notification for request A carries no RequestID")
	}
	if reqA.Done == nil {
		t.Fatal("touch notification for request A carries no Done channel")
	}
	cancelA()
	select {
	case <-doneA:
	case <-time.After(3 * time.Second):
		t.Fatal("request A did not end on context cancel")
	}
	select {
	case <-reqA.Done:
	case <-time.After(3 * time.Second):
		t.Fatal("request A's Done channel stayed open after its context was cancelled")
	}

	doneB := make(chan error, 1)
	go func() {
		_, err := h.RequestUserPresence(context.Background(), &authenticator.UserPresenceRequest{
			Operation: "register", RPID: "b.example", Timeout: 10 * time.Second,
		})
		doneB <- err
	}()
	reqB := n.next(t)
	if reqB.RequestID == reqA.RequestID {
		t.Fatalf("requests A and B share the ID %q", reqA.RequestID)
	}

	if h.ApproveRequest(reqA.RequestID) {
		t.Fatal("a late approval carrying request A's ID approved request B")
	}
	if !h.HasPending() {
		t.Fatal("request B is no longer pending after a late approval for A")
	}
	if h.ApproveRequest("") {
		t.Fatal("an approval with an empty request ID resolved request B")
	}
	if !h.ApproveRequest(reqB.RequestID) {
		t.Fatal("an approval carrying request B's ID did not approve B")
	}
	select {
	case err := <-doneB:
		if err != nil {
			t.Fatalf("request B: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request B did not resolve")
	}
}

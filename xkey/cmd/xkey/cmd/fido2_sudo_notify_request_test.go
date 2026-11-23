package cmd

import (
	"context"
	"io"
	"log/slog"
	"os/exec"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/presence"
)

// recordingRunner stands in for runuser: the dialog runs dialogBin, the
// touch runs "true", and every argv is recorded.
type recordingRunner struct {
	dialogBin []string
	mu        sync.Mutex
	argvs     [][]string
}

func (r *recordingRunner) command(ctx context.Context, name string, arg ...string) *exec.Cmd {
	argv := append([]string{name}, arg...)
	r.mu.Lock()
	r.argvs = append(r.argvs, argv)
	first := len(r.argvs) == 1
	r.mu.Unlock()
	if first {
		return exec.CommandContext(ctx, r.dialogBin[0], r.dialogBin[1:]...)
	}
	return exec.CommandContext(ctx, "true")
}

func (r *recordingRunner) recorded() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.argvs)
}

// TestSudoDialogNotifier_StopsDialogWhenRequestEnds covers the Codex P1 on
// #2271 through the production notifier: when the presence request a dialog
// was opened for ends (a hardware key won the Selection), the dialog stops
// and its touch never runs, so it cannot approve a later request.
func TestSudoDialogNotifier_StopsDialogWhenRequestEnds(t *testing.T) {
	t.Parallel()
	r := &recordingRunner{dialogBin: []string{"sleep", "30"}}
	n := newSudoDialogNotifier("alice", "/usr/bin/xkey", "/run/xkey.sock", 30*time.Second,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.command = r.command
	ended := make(chan struct{})
	n.dialogDone = func() { close(ended) }

	done := make(chan struct{})
	if err := n.NotifyTouchRequired(&notify.TouchRequest{
		Operation: "selection", RPID: "a.example", RequestID: "req-a", Done: done,
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	close(done)
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the dialog kept running after its presence request ended")
	}
	if got := r.recorded(); len(got) != 1 {
		t.Fatalf("expected only the dialog to run, got %q", got)
	}
}

// TestSudoDialogNotifier_TouchNamesItsRequest asserts an approved dialog runs
// "xkey touch" with the ID of the request it was opened for.
func TestSudoDialogNotifier_TouchNamesItsRequest(t *testing.T) {
	t.Parallel()
	r := &recordingRunner{dialogBin: []string{"true"}}
	n := newSudoDialogNotifier("alice", "/usr/bin/xkey", "/run/xkey.sock", 30*time.Second,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.command = r.command
	ended := make(chan struct{})
	n.dialogDone = func() { close(ended) }

	if err := n.NotifyTouchRequired(&notify.TouchRequest{
		Operation: "register", RPID: "b.example", RequestID: "req-b", Done: make(chan struct{}),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("dialog goroutine did not finish")
	}
	got := r.recorded()
	if len(got) != 2 {
		t.Fatalf("expected the dialog and the touch to run, got %q", got)
	}
	want := []string{sudoRunuserBin, "-u", "alice", "--", "/usr/bin/xkey", "touch",
		"--socket", "/run/xkey.sock", "--request-id", "req-b"}
	if !slices.Equal(got[1], want) {
		t.Fatalf("touch argv = %q, want %q", got[1], want)
	}
}

// idNotifier hands each published request ID to the test.
type idNotifier struct{ ids chan string }

func (n *idNotifier) NotifyTouchRequired(req *notify.TouchRequest) error {
	n.ids <- req.RequestID
	return nil
}

func (n *idNotifier) Close() error { return nil }

// TestFIDO2Device_TouchRequestApprovesOnlyItsRequest drives the daemon's
// touch handler: a touch naming a cancelled request leaves the next pending
// request untouched, and a touch naming the pending request approves it.
func TestFIDO2Device_TouchRequestApprovesOnlyItsRequest(t *testing.T) {
	t.Parallel()
	n := &idNotifier{ids: make(chan string, 2)}
	h := presence.NewSocketHandler(n, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d := &fido2Device{socketHandler: h}

	ctxA, cancelA := context.WithCancel(context.Background())
	doneA := make(chan struct{})
	go func() {
		defer close(doneA)
		_, _ = h.RequestUserPresence(ctxA, &authenticator.UserPresenceRequest{Operation: "selection", Timeout: 10 * time.Second})
	}()
	idA := <-n.ids
	cancelA()
	<-doneA

	doneB := make(chan error, 1)
	go func() {
		_, err := h.RequestUserPresence(context.Background(), &authenticator.UserPresenceRequest{Operation: "register", Timeout: 10 * time.Second})
		doneB <- err
	}()
	idB := <-n.ids

	resp, err := d.HandleTouchRequest(idA)
	if err != nil || resp.Action != ipc.ActionNoPending {
		t.Fatalf("touch for cancelled request A: resp=%+v err=%v, want %s", resp, err, ipc.ActionNoPending)
	}
	if !h.HasPending() {
		t.Fatal("a touch naming request A resolved request B")
	}
	resp, err = d.HandleTouchRequest(idB)
	if err != nil || resp.Action != ipc.ActionApprovedUP {
		t.Fatalf("touch for request B: resp=%+v err=%v, want %s", resp, err, ipc.ActionApprovedUP)
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

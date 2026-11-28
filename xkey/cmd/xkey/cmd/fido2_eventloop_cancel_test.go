package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/uhid"
)

// fakePacketSource stands in for the UHID device: it hands the event loop
// the packets a test queues, and reports uhid.ErrTimeout while none is
// queued, exactly as the real device's poll does.
type fakePacketSource struct {
	packets chan []byte
	// cancelReturned is closed when a CTAPHID_CANCEL packet has been
	// returned to the event loop.
	cancelReturned chan struct{}
	cancelAt       atomic.Int64
}

func newFakePacketSource() *fakePacketSource {
	return &fakePacketSource{
		packets:        make(chan []byte, 16),
		cancelReturned: make(chan struct{}),
	}
}

func (f *fakePacketSource) ReadOutput() ([]byte, error) {
	select {
	case p := <-f.packets:
		if p[4] == authenticator.CTAPHIDCancel && f.cancelAt.Load() == 0 {
			f.cancelAt.Store(time.Now().UnixNano())
			close(f.cancelReturned)
		}
		return p, nil
	case <-time.After(10 * time.Millisecond):
		return nil, uhid.ErrTimeout
	}
}

// blockingPresence blocks every presence request until its ctx ends, the
// way a prompt nobody answers does.
type blockingPresence struct {
	started   chan struct{}
	cancelled atomic.Bool
	once      atomic.Bool
}

func (b *blockingPresence) RequestUserPresence(ctx context.Context, _ *authenticator.UserPresenceRequest) (*authenticator.UserPresenceResult, error) {
	if b.once.CompareAndSwap(false, true) {
		close(b.started)
	}
	<-ctx.Done()
	if errors.Is(ctx.Err(), context.Canceled) {
		b.cancelled.Store(true)
	}
	return nil, ctx.Err()
}

func (b *blockingPresence) RequestUserVerification(context.Context, *authenticator.UserVerificationRequest) (*authenticator.UserVerificationResult, error) {
	return nil, errors.New("user verification not available in this test")
}

type hidFrame struct {
	cid     uint32
	cmd     byte
	payload []byte
}

type eventLoopHarness struct {
	t        *testing.T
	src      *fakePacketSource
	frames   chan hidFrame
	cancel   context.CancelFunc
	loopDone chan error
}

func startEventLoopHarness(t *testing.T, presence authenticator.UserPresenceHandler) *eventLoopHarness {
	t.Helper()
	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		AAGUID:              authenticator.DefaultAAGUID,
		Storage:             authenticator.NewMemoryStorage(),
		UserPresenceHandler: presence,
		UserPresenceTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	handler := authenticator.NewCTAPHIDHandler(auth)

	h := &eventLoopHarness{
		t:        t,
		src:      newFakePacketSource(),
		frames:   make(chan hidFrame, 64),
		loopDone: make(chan error, 1),
	}
	// Reassemble response packets into frames per CID.
	var cur *hidFrame
	var want int
	handler.SetResponseHandler(func(pkt []byte) {
		p := append([]byte(nil), pkt...)
		cid := binary.BigEndian.Uint32(p[0:4])
		if p[4]&0x80 != 0 {
			want = int(binary.BigEndian.Uint16(p[5:7]))
			cur = &hidFrame{cid: cid, cmd: p[4]}
			n := min(want, authenticator.HIDPacketSize-7)
			cur.payload = append(cur.payload, p[7:7+n]...)
		} else if cur != nil {
			n := min(want-len(cur.payload), authenticator.HIDPacketSize-5)
			cur.payload = append(cur.payload, p[5:5+n]...)
		}
		if cur != nil && len(cur.payload) == want {
			h.frames <- *cur
			cur = nil
		}
	})

	d := &fido2Device{
		logger:       discardLogger(),
		hidHandler:   handler,
		packetSource: h.src,
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.loopDone <- d.eventLoop(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = handler.Close()
	})
	return h
}

// initPacket builds a CTAPHID initialization packet.
func initPacket(cid uint32, cmd byte, total int, data []byte) []byte {
	p := make([]byte, authenticator.HIDPacketSize)
	binary.BigEndian.PutUint32(p[0:4], cid)
	p[4] = cmd
	binary.BigEndian.PutUint16(p[5:7], uint16(total))
	copy(p[7:], data)
	return p
}

// contPacket builds a CTAPHID continuation packet.
func contPacket(cid uint32, seq byte, data []byte) []byte {
	p := make([]byte, authenticator.HIDPacketSize)
	binary.BigEndian.PutUint32(p[0:4], cid)
	p[4] = seq
	copy(p[5:], data)
	return p
}

// nextFrame returns the next non-keepalive response frame.
func (h *eventLoopHarness) nextFrame(within time.Duration) hidFrame {
	h.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case f := <-h.frames:
			if f.cmd == authenticator.CTAPHIDKeepalive {
				continue
			}
			return f
		case <-deadline:
			h.t.Fatalf("no response frame within %v", within)
			return hidFrame{}
		}
	}
}

// allocateChannel runs CTAPHID_INIT on the broadcast CID and returns the
// allocated CID.
func (h *eventLoopHarness) allocateChannel() uint32 {
	h.t.Helper()
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	h.src.packets <- initPacket(0xFFFFFFFF, authenticator.CTAPHIDInit, len(nonce), nonce)
	f := h.nextFrame(2 * time.Second)
	if f.cmd != authenticator.CTAPHIDInit || len(f.payload) < 12 || !bytes.Equal(f.payload[:8], nonce) {
		h.t.Fatalf("unexpected INIT response cmd=0x%02x len=%d", f.cmd, len(f.payload))
	}
	return binary.BigEndian.Uint32(f.payload[8:12])
}

func (h *eventLoopHarness) stopAndWait() {
	h.t.Helper()
	h.cancel()
	select {
	case <-h.loopDone:
	case <-time.After(2 * time.Second):
		h.t.Fatal("event loop did not return within 2s of ctx cancel")
	}
}

// TestEventLoop_CancelEndsPendingSelection: a browser sends
// authenticatorSelection to every key and CTAPHID_CANCEL to the losers. The
// event loop must read that CANCEL while the Selection waits for presence,
// so the prompt closes and the Selection answers KEEPALIVE_CANCEL at once.
func TestEventLoop_CancelEndsPendingSelection(t *testing.T) {
	presence := &blockingPresence{started: make(chan struct{})}
	h := startEventLoopHarness(t, presence)

	cid := h.allocateChannel()
	h.src.packets <- initPacket(cid, authenticator.CTAPHIDCBOR, 1, []byte{authenticator.CmdSelection})

	select {
	case <-presence.started:
	case <-time.After(2 * time.Second):
		t.Fatal("Selection never asked for presence")
	}
	h.src.packets <- initPacket(cid, authenticator.CTAPHIDCancel, 0, nil)

	select {
	case <-h.src.cancelReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("event loop never read the CTAPHID_CANCEL packet")
	}
	f := h.nextFrame(2 * time.Second)
	elapsed := time.Since(time.Unix(0, h.src.cancelAt.Load()))
	if f.cid != cid || f.cmd != authenticator.CTAPHIDCBOR {
		t.Fatalf("response on cid=0x%08x cmd=0x%02x, want CBOR on 0x%08x", f.cid, f.cmd, cid)
	}
	if !bytes.Equal(f.payload, []byte{authenticator.StatusKeepaliveCancel}) {
		t.Fatalf("Selection answered % x, want 2d (KEEPALIVE_CANCEL)", f.payload)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Selection answered %v after CANCEL, want within 2s", elapsed)
	}
	if !presence.cancelled.Load() {
		t.Fatal("presence prompt ctx was not cancelled")
	}
	h.stopAndWait()
}

// TestEventLoop_KeepsPacketOrder: packets other than CANCEL reach the
// handler in the order read, including a message split over an init and a
// continuation packet.
func TestEventLoop_KeepsPacketOrder(t *testing.T) {
	h := startEventLoopHarness(t, &blockingPresence{started: make(chan struct{})})

	cid := h.allocateChannel()

	// A 2-packet message (init + continuation): a PING the handler echoes
	// byte for byte, so the reassembly is checked exactly; then a CBOR
	// GetInfo that must answer after it.
	ping := make([]byte, 100)
	for i := range ping {
		ping[i] = byte(i)
	}
	first := authenticator.HIDPacketSize - 7
	h.src.packets <- initPacket(cid, authenticator.CTAPHIDPing, len(ping), ping[:first])
	h.src.packets <- contPacket(cid, 0, ping[first:])
	h.src.packets <- initPacket(cid, authenticator.CTAPHIDCBOR, 1, []byte{authenticator.CmdGetInfo})

	f := h.nextFrame(2 * time.Second)
	if f.cid != cid || f.cmd != authenticator.CTAPHIDPing || !bytes.Equal(f.payload, ping) {
		t.Fatalf("first response cmd=0x%02x len=%d, want the PING echo", f.cmd, len(f.payload))
	}
	f = h.nextFrame(2 * time.Second)
	if f.cid != cid || f.cmd != authenticator.CTAPHIDCBOR || len(f.payload) < 2 || f.payload[0] != 0x00 {
		t.Fatalf("second response cmd=0x%02x payload len=%d, want a GetInfo success", f.cmd, len(f.payload))
	}
	h.stopAndWait()
}

// A CANCEL read while its Selection is still queued behind a busy worker
// ends that Selection without a presence wait.
func TestEventLoop_CancelEndsQueuedSelection(t *testing.T) {
	presence := &blockingPresence{started: make(chan struct{})}
	h := startEventLoopHarness(t, presence)

	busy := h.allocateChannel()
	queued := h.allocateChannel()
	h.src.packets <- initPacket(busy, authenticator.CTAPHIDCBOR, 1, []byte{authenticator.CmdSelection})
	select {
	case <-presence.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the first Selection never asked for presence")
	}

	h.src.packets <- initPacket(queued, authenticator.CTAPHIDCBOR, 1, []byte{authenticator.CmdSelection})
	h.src.packets <- initPacket(queued, authenticator.CTAPHIDCancel, 0, nil)
	select {
	case <-h.src.cancelReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("event loop never read the CTAPHID_CANCEL packet")
	}
	time.Sleep(50 * time.Millisecond)

	// Free the worker: the queued Selection starts only now.
	h.src.packets <- initPacket(busy, authenticator.CTAPHIDCancel, 0, nil)
	got := map[uint32][]byte{}
	for range 2 {
		f := h.nextFrame(3 * time.Second)
		if f.cmd != authenticator.CTAPHIDCBOR {
			t.Fatalf("response cmd=0x%02x on cid=0x%08x, want CBOR", f.cmd, f.cid)
		}
		got[f.cid] = f.payload
	}
	for _, cid := range []uint32{busy, queued} {
		if !bytes.Equal(got[cid], []byte{authenticator.StatusKeepaliveCancel}) {
			t.Fatalf("Selection on cid=0x%08x answered % x, want 2d (KEEPALIVE_CANCEL)", cid, got[cid])
		}
	}
	h.stopAndWait()
}

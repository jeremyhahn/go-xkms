package cmd

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/uhid"
)

// CTAPHID and CTAP2 wire constants (CTAP 2.1 §11.2.9, §6).
const (
	elCIDBroadcast          = uint32(0xFFFFFFFF)
	elCTAPHIDInit           = byte(0x86)
	elCTAPHIDCBOR           = byte(0x90)
	elCTAPHIDCancel         = byte(0x91)
	elCmdGetInfo            = byte(0x04)
	elCmdSelection          = byte(0x0B)
	elStatusOK              = byte(0x00)
	elStatusKeepaliveCancel = byte(0x2D)
)

// elPresence blocks every presence request until its context ends.
type elPresence struct {
	started chan struct{}
}

func (p *elPresence) RequestUserPresence(ctx context.Context, _ *authenticator.UserPresenceRequest) (*authenticator.UserPresenceResult, error) {
	select {
	case p.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *elPresence) RequestUserVerification(context.Context, *authenticator.UserVerificationRequest) (*authenticator.UserVerificationResult, error) {
	return &authenticator.UserVerificationResult{}, nil
}

// elReader is a fake UHID output reader: it hands out queued host reports
// and times out like the real device when none is pending.
type elReader struct {
	reports chan []byte
}

func (r *elReader) ReadOutput() ([]byte, error) {
	select {
	case pkt := <-r.reports:
		return pkt, nil
	case <-time.After(5 * time.Millisecond):
		return nil, uhid.ErrTimeout
	}
}

// elOutbox collects the reports the authenticator sends to the host.
type elOutbox struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (o *elOutbox) add(pkt []byte) {
	cp := append([]byte(nil), pkt...)
	o.mu.Lock()
	o.pkts = append(o.pkts, cp)
	o.mu.Unlock()
}

// nth returns the payload of the n-th (0-based) init packet on cid with cmd.
func (o *elOutbox) nth(cid uint32, cmd byte, n int) ([]byte, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, pkt := range o.pkts {
		if binary.BigEndian.Uint32(pkt[0:4]) != cid || pkt[4] != cmd {
			continue
		}
		if n == 0 {
			l := int(binary.BigEndian.Uint16(pkt[5:7]))
			if l > len(pkt)-7 {
				l = len(pkt) - 7
			}
			return pkt[7 : 7+l], true
		}
		n--
	}
	return nil, false
}

func (o *elOutbox) await(t *testing.T, cid uint32, cmd byte, n int, within time.Duration, what string) []byte {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if p, ok := o.nth(cid, cmd, n); ok {
			return p
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: no answer within %s", what, within)
	return nil
}

func elPacket(cid uint32, cmd byte, payload []byte) []byte {
	pkt := make([]byte, authenticator.HIDPacketSize)
	binary.BigEndian.PutUint32(pkt[0:4], cid)
	pkt[4] = cmd
	binary.BigEndian.PutUint16(pkt[5:7], uint16(len(payload)))
	copy(pkt[7:], payload)
	return pkt
}

// TestFIDO2EventLoop_CancelReachesBlockingSelection covers the Codex P1 on
// #2271: the daemon's HID read loop must keep reading reports while a
// Selection waits for presence, so the host's CTAPHID_CANCEL ends it with
// CTAP2_ERR_KEEPALIVE_CANCEL well before the presence timeout, and the next
// request on the channel is served.
func TestFIDO2EventLoop_CancelReachesBlockingSelection(t *testing.T) {
	t.Parallel()

	up := &elPresence{started: make(chan struct{}, 1)}
	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		AAGUID:              authenticator.DefaultAAGUID,
		Storage:             authenticator.NewMemoryStorage(),
		UserPresenceHandler: up,
		UserPresenceTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	hid := authenticator.NewCTAPHIDHandler(auth)
	out := &elOutbox{}
	hid.SetResponseHandler(out.add)

	d := &fido2Device{logger: discardLogger(), hidHandler: hid}
	reader := &elReader{reports: make(chan []byte, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan error, 1)
	go func() { loopDone <- d.runHIDEventLoop(ctx, reader) }()
	t.Cleanup(func() {
		cancel()
		if err := <-loopDone; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("event loop: %v", err)
		}
		_ = hid.Close()
	})

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	reader.reports <- elPacket(elCIDBroadcast, elCTAPHIDInit, nonce)
	initResp := out.await(t, elCIDBroadcast, elCTAPHIDInit, 0, 2*time.Second, "INIT")
	cid := binary.BigEndian.Uint32(initResp[8:12])

	reader.reports <- elPacket(cid, elCTAPHIDCBOR, []byte{elCmdSelection})
	select {
	case <-up.started:
	case <-time.After(5 * time.Second):
		t.Fatal("Selection never asked for presence")
	}

	reader.reports <- elPacket(cid, elCTAPHIDCancel, nil)
	sel := out.await(t, cid, elCTAPHIDCBOR, 0, 2*time.Second, "Selection after CTAPHID_CANCEL")
	if len(sel) == 0 || sel[0] != elStatusKeepaliveCancel {
		t.Fatalf("Selection answered %x, want status 0x%02x", sel, elStatusKeepaliveCancel)
	}

	reader.reports <- elPacket(cid, elCTAPHIDCBOR, []byte{elCmdGetInfo})
	info := out.await(t, cid, elCTAPHIDCBOR, 1, 2*time.Second, "GetInfo after the cancelled Selection")
	if len(info) == 0 || info[0] != elStatusOK {
		t.Fatalf("GetInfo answered %x, want status OK", info)
	}
}

//go:build linux

package virtualdevice

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
)

// blockingPresence holds every presence request until its context ends.
type blockingPresence struct {
	started chan struct{}
}

func (p *blockingPresence) RequestUserPresence(ctx context.Context, _ *authenticator.UserPresenceRequest) (*authenticator.UserPresenceResult, error) {
	select {
	case p.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *blockingPresence) RequestUserVerification(context.Context, *authenticator.UserVerificationRequest) (*authenticator.UserVerificationResult, error) {
	return nil, authenticator.ErrUserVerificationDenied
}

func cancelTestPacket(cid uint32, cmd byte, payload []byte) []byte {
	pkt := make([]byte, authenticator.HIDPacketSize)
	binary.BigEndian.PutUint32(pkt[0:4], cid)
	pkt[4] = cmd
	binary.BigEndian.PutUint16(pkt[5:7], uint16(len(payload)))
	copy(pkt[7:], payload)
	return pkt
}

// writeWithin writes one report and fails if Write does not return in time:
// the GUI bridge writes from a single goroutine, so a Write that blocks for
// a whole command stops it from delivering the host's next report.
func writeWithin(t *testing.T, d *NativeVirtualDevice, pkt []byte, within time.Duration, what string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := d.Write(pkt)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: write: %v", what, err)
		}
	case <-time.After(within):
		t.Fatalf("%s: Write still blocked after %s", what, within)
	}
}

// readCBOR reads reports until the init packet of a CBOR answer on cid and
// returns its payload, skipping keepalives.
func readCBOR(t *testing.T, d *NativeVirtualDevice, cid uint32, within time.Duration, what string) []byte {
	t.Helper()
	type res struct {
		payload []byte
		err     error
	}
	out := make(chan res, 1)
	go func() {
		for {
			buf := make([]byte, authenticator.HIDPacketSize)
			n, err := d.Read(buf)
			if err != nil {
				out <- res{err: err}
				return
			}
			if n < 7 || binary.BigEndian.Uint32(buf[0:4]) != cid || buf[4] != authenticator.CTAPHIDCBOR {
				continue
			}
			l := int(binary.BigEndian.Uint16(buf[5:7]))
			if l > n-7 {
				l = n - 7
			}
			out <- res{payload: buf[7 : 7+l]}
			return
		}
	}()
	select {
	case r := <-out:
		if r.err != nil {
			t.Fatalf("%s: read: %v", what, r.err)
		}
		return r.payload
	case <-time.After(within):
		t.Fatalf("%s: no answer within %s", what, within)
		return nil
	}
}

// TestNativeVirtualDevice_CancelReachesBlockingSelection covers the Codex P1
// on #2271 for the GUI bridge: Write must not hold the device for a whole
// Selection, so the host's CTAPHID_CANCEL is delivered and ends it with
// CTAP2_ERR_KEEPALIVE_CANCEL, and the next request is served.
func TestNativeVirtualDevice_CancelReachesBlockingSelection(t *testing.T) {
	t.Parallel()
	up := &blockingPresence{started: make(chan struct{}, 1)}
	cfg := authenticator.DefaultConfig()
	cfg.Storage = authenticator.NewMemoryStorage()
	cfg.UserPresenceHandler = up
	cfg.UserPresenceTimeout = 10 * time.Second
	auth, err := authenticator.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	d, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{Authenticator: auth})
	if err != nil {
		t.Fatalf("new device: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	writeWithin(t, d, cancelTestPacket(authenticator.CIDBroadcast, authenticator.CTAPHIDInit, nonce), 2*time.Second, "INIT")
	buf := make([]byte, authenticator.HIDPacketSize)
	if _, err := d.Read(buf); err != nil {
		t.Fatalf("INIT read: %v", err)
	}
	cid := binary.BigEndian.Uint32(buf[15:19])

	writeWithin(t, d, cancelTestPacket(cid, authenticator.CTAPHIDCBOR, []byte{authenticator.CmdSelection}), time.Second, "Selection")
	select {
	case <-up.started:
	case <-time.After(5 * time.Second):
		t.Fatal("Selection never asked for presence")
	}

	writeWithin(t, d, cancelTestPacket(cid, authenticator.CTAPHIDCancel, nil), time.Second, "CTAPHID_CANCEL")
	sel := readCBOR(t, d, cid, 2*time.Second, "Selection after CTAPHID_CANCEL")
	if len(sel) == 0 || sel[0] != authenticator.StatusKeepaliveCancel {
		t.Fatalf("Selection answered %x, want status 0x%02x", sel, authenticator.StatusKeepaliveCancel)
	}

	writeWithin(t, d, cancelTestPacket(cid, authenticator.CTAPHIDCBOR, []byte{authenticator.CmdGetInfo}), time.Second, "GetInfo")
	info := readCBOR(t, d, cid, 2*time.Second, "GetInfo after the cancelled Selection")
	if len(info) == 0 || info[0] != authenticator.StatusOK {
		t.Fatalf("GetInfo answered %x, want status OK", info)
	}
}

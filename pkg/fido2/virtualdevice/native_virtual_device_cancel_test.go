package virtualdevice

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
	"github.com/stretchr/testify/require"
)

// blockingPresenceHandler blocks every presence request until its context ends.
type blockingPresenceHandler struct {
	started chan struct{}
}

func (h *blockingPresenceHandler) RequestUserPresence(ctx context.Context, _ *authenticator.UserPresenceRequest) (*authenticator.UserPresenceResult, error) {
	select {
	case h.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (h *blockingPresenceHandler) RequestUserVerification(ctx context.Context, _ *authenticator.UserVerificationRequest) (*authenticator.UserVerificationResult, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func nativeInitPacket(cid uint32, cmd byte, payload []byte) []byte {
	packet := make([]byte, authenticator.HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], cid)
	packet[4] = cmd
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(payload)))
	copy(packet[7:], payload)
	return packet
}

// A CTAPHID_CANCEL written while a Selection blocks on presence ends that
// Selection cancelled without waiting for presence.
func TestNativeVirtualDevice_CancelDuringSelection(t *testing.T) {
	h := &blockingPresenceHandler{started: make(chan struct{}, 1)}
	device, err := NewNativeVirtualDevice(&NativeVirtualDeviceConfig{UserPresenceHandler: h})
	require.NoError(t, err)
	t.Cleanup(func() { _ = device.Close() })

	cid := initializeChannel(t, device)

	selDone := make(chan error, 1)
	go func() {
		_, werr := device.Write(nativeInitPacket(cid, authenticator.CTAPHIDCBOR, []byte{authenticator.CmdSelection}))
		selDone <- werr
	}()

	select {
	case <-h.started:
	case <-time.After(2 * time.Second):
		t.Fatal("Selection never asked for presence")
	}

	cancelDone := make(chan error, 1)
	go func() {
		_, werr := device.Write(nativeInitPacket(cid, authenticator.CTAPHIDCancel, nil))
		cancelDone <- werr
	}()

	select {
	case werr := <-selDone:
		require.NoError(t, werr)
	case <-time.After(2 * time.Second):
		t.Fatal("CTAPHID_CANCEL did not end the blocked Selection")
	}
	select {
	case werr := <-cancelDone:
		require.NoError(t, werr)
	case <-time.After(2 * time.Second):
		t.Fatal("CTAPHID_CANCEL write did not return")
	}

	resp := readFullResponse(t, device, cid)
	require.NotEmpty(t, resp)
	require.Equal(t, byte(authenticator.StatusKeepaliveCancel), resp[0])
}

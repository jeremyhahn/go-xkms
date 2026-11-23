package authenticator

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// cborStatuses returns the status byte of every CTAPHID_CBOR response the
// device sent on its channel, in order.
func (d *selHIDDevice) cborStatuses() []byte {
	d.probe.mu.Lock()
	defer d.probe.mu.Unlock()
	var out []byte
	for _, pkt := range d.probe.pkts {
		if binary.BigEndian.Uint32(pkt[0:4]) == d.cid && pkt[4] == CTAPHIDCBOR &&
			binary.BigEndian.Uint16(pkt[5:7]) > 0 {
			out = append(out, pkt[7])
		}
	}
	return out
}

// sendCBOR sends one CTAP2 command over CTAPHID_CBOR, split into an
// initialisation packet and continuation packets, on its own goroutine
// (HandleMessage blocks for the whole command once the message is complete).
func (d *selHIDDevice) sendCBOR(cmd byte, data []byte) <-chan struct{} {
	payload := append([]byte{cmd}, data...)
	pkts := [][]byte{}
	first := min(len(payload), HIDPacketSize-7)
	init := selHIDPacket(d.cid, CTAPHIDCBOR, payload[:first])
	binary.BigEndian.PutUint16(init[5:7], uint16(len(payload)))
	pkts = append(pkts, init)
	for off, seq := first, byte(0); off < len(payload); seq++ {
		n := min(len(payload)-off, HIDPacketSize-5)
		pkt := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(pkt[0:4], d.cid)
		pkt[4] = seq
		copy(pkt[5:], payload[off:off+n])
		pkts = append(pkts, pkt)
		off += n
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, pkt := range pkts {
			d.hid.HandleMessage(pkt)
		}
	}()
	return done
}

// TestSelection_GrantDoesNotSurviveUnmatchedHIDGetAssertion covers the Codex
// P1 on #2271: the CTAPHID transport answers a GetAssertion with no matching
// credential itself (the multi-authenticator deferral in
// processCBORCommandLocked) and never enters ProcessCBORWithContext, so the
// grant cleanup there did not run. After an approved Selection, an unmatched
// GetAssertion that the host cancels is a credential operation: it ends the
// grant, and the next credential operation on the same channel asks for a
// fresh touch instead of inheriting UP from the old one.
func TestSelection_GrantDoesNotSurviveUnmatchedHIDGetAssertion(t *testing.T) {
	t.Parallel()
	d := newSelHIDDevice(t)
	d.up.auto.Store(true)

	<-d.sendSelection()
	require.Equal(t, []byte{StatusOK}, d.cborStatuses(), "Selection approved")
	require.Equal(t, int32(1), d.up.calls.Load())

	clientDataHash := sha256.Sum256([]byte("unmatched"))
	ga, err := cbor.Marshal(map[int]interface{}{
		0x01: "no.example",
		0x02: clientDataHash[:],
	})
	require.NoError(t, err)
	gaDone := d.sendCBOR(CmdGetAssertion, ga)
	require.Eventually(t, func() bool { return len(d.probe.keepaliveStatuses(d.cid)) > 0 },
		3*time.Second, 5*time.Millisecond, "unmatched GetAssertion must enter the deferral")
	d.hid.HandleMessage(selHIDPacket(d.cid, CTAPHIDCancel, nil))
	select {
	case <-gaDone:
	case <-time.After(3 * time.Second):
		t.Fatal("GetAssertion deferral did not end on CTAPHID_CANCEL")
	}
	require.Equal(t, []byte{StatusOK, StatusKeepaliveCancel}, d.cborStatuses())
	require.Equal(t, int32(1), d.up.calls.Load(), "the deferral asks for no presence")

	mcDone := d.sendCBOR(CmdMakeCredential, selMakeCredentialData(t, false))
	select {
	case <-mcDone:
	case <-time.After(5 * time.Second):
		t.Fatal("MakeCredential did not complete")
	}
	statuses := d.cborStatuses()
	require.Len(t, statuses, 3)
	require.Equal(t, byte(StatusOK), statuses[2])
	require.Equal(t, int32(2), d.up.calls.Load(),
		"MakeCredential must ask for fresh presence: the unmatched GetAssertion ended the Selection grant")
}

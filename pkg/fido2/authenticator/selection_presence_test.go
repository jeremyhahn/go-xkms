package authenticator

// Tests for CTAP 2.1 §6.9 authenticatorSelection: the authenticator answers
// only after user presence (issue #2345). A browser sends Selection to every
// connected authenticator and uses the one the user touches, so an
// authenticator that answers without a touch always wins the choice.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// selDecision is one answer of selUPHandler to a presence request.
type selDecision struct {
	approve bool
	err     error
}

// selUPHandler records every presence request and answers each one with the
// next decision sent on decide, or with ctx.Err() when the command context
// ends first. With auto set it approves at once.
type selUPHandler struct {
	mu      sync.Mutex
	reqs    []UserPresenceRequest
	calls   atomic.Int32
	auto    atomic.Bool
	started chan struct{}
	decide  chan selDecision
}

func newSelUPHandler() *selUPHandler {
	return &selUPHandler{
		started: make(chan struct{}, 64),
		decide:  make(chan selDecision, 16),
	}
}

func (h *selUPHandler) RequestUserPresence(ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error) {
	h.mu.Lock()
	h.reqs = append(h.reqs, *req)
	h.mu.Unlock()
	h.calls.Add(1)
	select {
	case h.started <- struct{}{}:
	default:
	}
	if h.auto.Load() {
		return &UserPresenceResult{Approved: true}, nil
	}
	select {
	case d := <-h.decide:
		if d.err != nil {
			return nil, d.err
		}
		return &UserPresenceResult{Approved: d.approve}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *selUPHandler) RequestUserVerification(context.Context, *UserVerificationRequest) (*UserVerificationResult, error) {
	return nil, ErrUserVerificationDenied
}

func (h *selUPHandler) lastRequest(t *testing.T) UserPresenceRequest {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	require.NotEmpty(t, h.reqs, "no presence request was made")
	return h.reqs[len(h.reqs)-1]
}

func (h *selUPHandler) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-h.started:
	case <-time.After(5 * time.Second):
		t.Fatal("presence was never requested")
	}
}

func newSelectionTestAuthenticator(t *testing.T, h *selUPHandler, mutate func(*Config)) *Authenticator {
	t.Helper()
	config := DefaultConfig()
	config.Storage = NewMemoryStorage()
	config.UserPresenceHandler = h
	if mutate != nil {
		mutate(config)
	}
	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })
	return auth
}

type selResult struct {
	resp []byte
	err  error
}

// runAsync runs one CTAP command on its own goroutine.
func runAsync(ctx context.Context, a *Authenticator, cmd byte, data []byte) <-chan selResult {
	out := make(chan selResult, 1)
	go func() {
		resp, err := a.ProcessCBORWithContext(ctx, cmd, data)
		out <- selResult{resp: resp, err: err}
	}()
	return out
}

func awaitStatus(t *testing.T, ch <-chan selResult) byte {
	t.Helper()
	select {
	case r := <-ch:
		require.NotEmpty(t, r.resp)
		return r.resp[0]
	case <-time.After(5 * time.Second):
		t.Fatal("command did not answer")
		return 0
	}
}

func requireNoAnswer(t *testing.T, ch <-chan selResult, msg string) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("%s: answered early with %x (err %v)", msg, r.resp, r.err)
	case <-time.After(100 * time.Millisecond):
	}
}

// selMakeCredentialData builds a MakeCredential request. emptyPinAuth adds
// the zero-length pinUvAuthParam of the CTAP 2.0 selection idiom.
func selMakeCredentialData(t *testing.T, emptyPinAuth bool) []byte {
	t.Helper()
	clientDataHash := sha256.Sum256([]byte("selection"))
	params := map[int]interface{}{
		0x01: clientDataHash[:],
		0x02: map[string]interface{}{"id": "test.example.com", "name": "Test RP"},
		0x03: map[string]interface{}{"id": []byte{0x01, 0x02, 0x03}, "name": "testuser"},
		0x04: []map[string]interface{}{{"type": "public-key", "alg": -7}},
	}
	if emptyPinAuth {
		params[0x08] = []byte{}
		params[0x09] = 1
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)
	return data
}

// Step 1: Selection blocks until the user answers.
func TestSelection_BlocksUntilPresence(t *testing.T) {
	t.Parallel()
	h := newSelUPHandler()
	auth := newSelectionTestAuthenticator(t, h, nil)

	ch := runAsync(context.Background(), auth, CmdSelection, nil)
	h.waitStarted(t)
	requireNoAnswer(t, ch, "Selection before presence")

	h.decide <- selDecision{approve: true}
	require.Equal(t, byte(StatusOK), awaitStatus(t, ch))
}

// Step 1: approve, decline, timeout and cancel map to the §6.9 statuses.
func TestSelection_PresenceStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout time.Duration
		answer  func(h *selUPHandler, cancel context.CancelFunc)
		want    byte
	}{
		{"Approve", 0, func(h *selUPHandler, _ context.CancelFunc) { h.decide <- selDecision{approve: true} }, StatusOK},
		{"DeclineResult", 0, func(h *selUPHandler, _ context.CancelFunc) { h.decide <- selDecision{approve: false} }, StatusOperationDenied},
		{"DeclineError", 0, func(h *selUPHandler, _ context.CancelFunc) {
			h.decide <- selDecision{err: ErrUserPresenceDenied}
		}, StatusOperationDenied},
		{"HandlerTimeout", 0, func(h *selUPHandler, _ context.CancelFunc) {
			h.decide <- selDecision{err: ErrUserPresenceTimeout}
		}, StatusUserActionTimeout},
		{"NoAnswer", 50 * time.Millisecond, func(*selUPHandler, context.CancelFunc) {}, StatusUserActionTimeout},
		{"Cancel", 0, func(_ *selUPHandler, cancel context.CancelFunc) { cancel() }, StatusKeepaliveCancel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newSelUPHandler()
			auth := newSelectionTestAuthenticator(t, h, func(c *Config) {
				if tt.timeout > 0 {
					c.UserPresenceTimeout = tt.timeout
				}
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			ch := runAsync(ctx, auth, CmdSelection, nil)
			h.waitStarted(t)
			tt.answer(h, cancel)
			require.Equal(t, tt.want, awaitStatus(t, ch))
		})
	}
}

// Step 2: the CTAP 2.0 selection idiom (MakeCredential with a zero-length
// pinUvAuthParam) answers neither success nor a PIN error before presence.
func TestMakeCredential_EmptyPinUvAuthParam_WaitsForPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pinSet   bool
		decision selDecision
		want     byte
	}{
		{"PINNotSetApproved", false, selDecision{approve: true}, StatusPINNotSet},
		{"PINSetApproved", true, selDecision{approve: true}, StatusPINInvalid},
		{"Declined", true, selDecision{approve: false}, StatusOperationDenied},
		{"Timeout", false, selDecision{err: ErrUserPresenceTimeout}, StatusUserActionTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newSelUPHandler()
			auth := newSelectionTestAuthenticator(t, h, func(c *Config) { c.EnablePIN = true })
			if tt.pinSet {
				sum := sha256.Sum256([]byte("123456"))
				auth.SetFIDO2PINHash(sum[:16])
			}

			ch := runAsync(context.Background(), auth, CmdMakeCredential, selMakeCredentialData(t, true))
			h.waitStarted(t)
			requireNoAnswer(t, ch, "MakeCredential selection idiom before presence")

			h.decide <- tt.decision
			require.Equal(t, tt.want, awaitStatus(t, ch))
		})
	}
}

// Step 3: the prompt names the authenticator, and the relying party when
// the command carries one.
func TestSelection_PromptNamesAuthenticatorAndRP(t *testing.T) {
	t.Parallel()
	h := newSelUPHandler()
	h.auto.Store(true)
	auth := newSelectionTestAuthenticator(t, h, func(c *Config) {
		c.EnablePIN = true
		c.DisplayName = "xkey test key"
	})

	resp, err := auth.ProcessCBOR(CmdSelection, nil)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])
	sel := h.lastRequest(t)
	require.Equal(t, PresenceOperationSelect, sel.Operation)
	require.Empty(t, sel.RPID, "Selection carries no relying party")
	require.Equal(t, "xkey test key", sel.AuthenticatorName)

	resp, _ = auth.ProcessCBOR(CmdMakeCredential, selMakeCredentialData(t, true))
	require.Equal(t, byte(StatusPINNotSet), resp[0])
	mc := h.lastRequest(t)
	require.Equal(t, "test.example.com", mc.RPID)
	require.Equal(t, "Test RP", mc.RPName)
	require.Equal(t, "xkey test key", mc.AuthenticatorName)
}

// Step 3: without a configured display name the prompt still names xkey.
func TestSelection_PromptDefaultAuthenticatorName(t *testing.T) {
	t.Parallel()
	h := newSelUPHandler()
	h.auto.Store(true)
	auth := newSelectionTestAuthenticator(t, h, nil)

	_, err := auth.ProcessCBOR(CmdSelection, nil)
	require.NoError(t, err)
	require.Equal(t, DefaultAuthenticatorDisplayName, h.lastRequest(t).AuthenticatorName)
}

// Step 4: one approved touch at Selection satisfies the next MakeCredential
// on the same CTAPHID channel within the window, once.
func TestSelection_GrantSatisfiesNextMakeCredential(t *testing.T) {
	t.Parallel()
	const ch1, ch2 = uint32(0x01000001), uint32(0x01000002)

	tests := []struct {
		name      string
		between   func(a *Authenticator, now *atomic.Int64)
		mcChannel uint32
		wantCalls int32 // presence prompts after Selection + MakeCredential
	}{
		{"SameChannel", nil, ch1, 1},
		{"OtherChannel", nil, ch2, 2},
		{"AfterWindow", func(_ *Authenticator, now *atomic.Int64) {
			now.Add(int64(SelectionPresenceWindow + time.Second))
		}, ch1, 2},
		{"OtherChannelCommandClears", func(a *Authenticator, _ *atomic.Int64) {
			_, _ = a.ProcessCBORWithContext(WithCTAPHIDChannel(context.Background(), ch2), CmdGetInfo, nil)
		}, ch1, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newSelUPHandler()
			h.auto.Store(true)
			auth := newSelectionTestAuthenticator(t, h, nil)
			var now atomic.Int64
			now.Store(time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC).UnixNano())
			auth.grantClock = func() time.Time { return time.Unix(0, now.Load()) }

			resp, err := auth.ProcessCBORWithContext(WithCTAPHIDChannel(context.Background(), ch1), CmdSelection, nil)
			require.NoError(t, err)
			require.Equal(t, byte(StatusOK), resp[0])

			if tt.between != nil {
				tt.between(auth, &now)
			}

			resp, err = auth.ProcessCBORWithContext(WithCTAPHIDChannel(context.Background(), tt.mcChannel),
				CmdMakeCredential, selMakeCredentialData(t, false))
			require.NoError(t, err)
			require.Equal(t, byte(StatusOK), resp[0])
			require.Equal(t, tt.wantCalls, h.calls.Load())
		})
	}

	t.Run("ConsumedOnce", func(t *testing.T) {
		t.Parallel()
		h := newSelUPHandler()
		h.auto.Store(true)
		auth := newSelectionTestAuthenticator(t, h, nil)
		ctx := WithCTAPHIDChannel(context.Background(), ch1)

		_, err := auth.ProcessCBORWithContext(ctx, CmdSelection, nil)
		require.NoError(t, err)
		for range 2 {
			resp, err := auth.ProcessCBORWithContext(ctx, CmdMakeCredential, selMakeCredentialData(t, false))
			require.NoError(t, err)
			require.Equal(t, byte(StatusOK), resp[0])
		}
		require.Equal(t, int32(2), h.calls.Load(), "the second MakeCredential must ask again")
	})

	t.Run("CancelClears", func(t *testing.T) {
		t.Parallel()
		h := newSelUPHandler()
		h.auto.Store(true)
		auth := newSelectionTestAuthenticator(t, h, nil)

		_, err := auth.ProcessCBORWithContext(WithCTAPHIDChannel(context.Background(), ch1), CmdSelection, nil)
		require.NoError(t, err)

		// A second Selection on the same channel is cancelled by the host.
		h.auto.Store(false)
		ctx, cancel := context.WithCancel(WithCTAPHIDChannel(context.Background(), ch1))
		res := runAsync(ctx, auth, CmdSelection, nil)
		h.waitStarted(t)
		h.waitStarted(t)
		cancel()
		require.Equal(t, byte(StatusKeepaliveCancel), awaitStatus(t, res))

		h.auto.Store(true)
		resp, err := auth.ProcessCBORWithContext(WithCTAPHIDChannel(context.Background(), ch1),
			CmdMakeCredential, selMakeCredentialData(t, false))
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])
		require.Equal(t, int32(3), h.calls.Load(), "a cancelled Selection leaves no grant")
	})

}

// selNoCredentialAssertion is a GetAssertion for an RP the authenticator holds
// no credential for: the HID transport defers it (multi-authenticator
// coexistence) instead of answering.
func selNoCredentialAssertion(t *testing.T) []byte {
	t.Helper()
	clientDataHash := sha256.Sum256([]byte("deferred"))
	data, err := cbor.Marshal(map[int]interface{}{
		0x01: "nocred.example.com",
		0x02: clientDataHash[:],
	})
	require.NoError(t, err)
	return append([]byte{CmdGetAssertion}, data...)
}

// selGrantSurvivesDeferral approves a Selection on the device's channel, runs
// a deferred GetAssertion on the same channel to its end (end performs the
// cancel or waits for the safety timeout), and reports whether a following
// MakeCredential on that channel asked for presence again.
func selGrantSurvivesDeferral(t *testing.T, end func(d *selHIDDevice)) {
	t.Helper()
	d := newSelHIDDevice(t)
	d.up.auto.Store(true)
	d.hid.HandleMessage(selHIDPacket(d.cid, CTAPHIDCBOR, []byte{CmdSelection}))
	status, ok := d.cborStatus()
	require.True(t, ok, "no Selection response")
	require.Equal(t, byte(StatusOK), status)
	before := d.up.calls.Load()

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.hid.HandleMessage(selHIDPacket(d.cid, CTAPHIDCBOR, selNoCredentialAssertion(t)))
	}()
	require.Eventually(t, func() bool {
		return bytes.IndexByte(d.probe.keepaliveStatuses(d.cid), KeepaliveStatusProcessing) >= 0
	}, 3*time.Second, 5*time.Millisecond, "the GetAssertion was not deferred")
	end(d)
	select {
	case <-done:
	case <-time.After(2 * noCredentialsSafetyTimeout):
		t.Fatal("the deferred GetAssertion never ended")
	}

	resp, err := d.hid.Authenticator().ProcessCBORWithContext(WithCTAPHIDChannel(context.Background(), d.cid),
		CmdMakeCredential, selMakeCredentialData(t, false))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])
	require.Equal(t, before+1, d.up.calls.Load(),
		"the MakeCredential after a deferred GetAssertion must ask for presence again")
}

func TestSelection_GrantRevokedWhenDeferredAssertionCancelled(t *testing.T) {
	t.Parallel()
	selGrantSurvivesDeferral(t, func(d *selHIDDevice) {
		d.hid.HandleMessage(selHIDPacket(d.cid, CTAPHIDCancel, nil))
	})
}

func TestSelection_GrantRevokedWhenDeferredAssertionTimesOut(t *testing.T) {
	t.Parallel()
	selGrantSurvivesDeferral(t, func(*selHIDDevice) {})
}

// selCancelOnApprove approves presence after the host has cancelled the command.
type selCancelOnApprove struct {
	selUPHandler
	cancel context.CancelFunc
}

func (h *selCancelOnApprove) RequestUserPresence(context.Context, *UserPresenceRequest) (*UserPresenceResult, error) {
	h.calls.Add(1)
	h.cancel()
	return &UserPresenceResult{Approved: true}, nil
}

func TestSelection_ApprovalRacingCancelLeavesNoGrant(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(WithCTAPHIDChannel(context.Background(), 0x01000001))
	defer cancel()
	h := &selCancelOnApprove{cancel: cancel}
	config := DefaultConfig()
	config.Storage = NewMemoryStorage()
	config.UserPresenceHandler = h
	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })

	resp, _ := auth.ProcessCBORWithContext(ctx, CmdSelection, nil)
	require.NotEmpty(t, resp)
	require.Equal(t, byte(StatusKeepaliveCancel), resp[0], "a cancelled Selection must report the cancel")

	auth.grantMu.Lock()
	grant := auth.presenceGrant
	auth.grantMu.Unlock()
	require.Nil(t, grant, "a cancelled Selection must leave no presence grant")
}

// --- CTAPHID transport helpers -------------------------------------------

// selProbe collects the HID packets an authenticator sends.
type selProbe struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (p *selProbe) add(pkt []byte) {
	cp := append([]byte(nil), pkt...)
	p.mu.Lock()
	p.pkts = append(p.pkts, cp)
	p.mu.Unlock()
}

// first returns the payload of the first packet on cid with command cmd.
func (p *selProbe) first(cid uint32, cmd byte) ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pkt := range p.pkts {
		if binary.BigEndian.Uint32(pkt[0:4]) == cid && pkt[4] == cmd {
			n := int(binary.BigEndian.Uint16(pkt[5:7]))
			return pkt[7 : 7+n], true
		}
	}
	return nil, false
}

func (p *selProbe) keepaliveStatuses(cid uint32) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []byte
	for _, pkt := range p.pkts {
		if binary.BigEndian.Uint32(pkt[0:4]) == cid && pkt[4] == CTAPHIDKeepalive {
			out = append(out, pkt[7])
		}
	}
	return out
}

func selHIDPacket(cid uint32, cmd byte, payload []byte) []byte {
	pkt := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(pkt[0:4], cid)
	pkt[4] = cmd
	binary.BigEndian.PutUint16(pkt[5:7], uint16(len(payload)))
	copy(pkt[7:], payload)
	return pkt
}

// selHIDDevice is one virtual authenticator behind the CTAPHID transport.
type selHIDDevice struct {
	up    *selUPHandler
	hid   *CTAPHIDHandler
	probe *selProbe
	cid   uint32
}

func newSelHIDDevice(t *testing.T) *selHIDDevice {
	t.Helper()
	d := &selHIDDevice{up: newSelUPHandler(), probe: &selProbe{}}
	auth := newSelectionTestAuthenticator(t, d.up, nil)
	d.hid = NewCTAPHIDHandler(auth)
	d.hid.SetResponseHandler(d.probe.add)
	t.Cleanup(func() { _ = d.hid.Close() })

	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	d.hid.HandleMessage(selHIDPacket(CIDBroadcast, CTAPHIDInit, nonce))
	resp, ok := d.probe.first(CIDBroadcast, CTAPHIDInit)
	require.True(t, ok, "no INIT response")
	require.Equal(t, nonce, resp[0:8])
	d.cid = binary.BigEndian.Uint32(resp[8:12])
	return d
}

// sendSelection sends authenticatorSelection; HandleMessage blocks for the
// whole command, so it runs on its own goroutine.
func (d *selHIDDevice) sendSelection() <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.hid.HandleMessage(selHIDPacket(d.cid, CTAPHIDCBOR, []byte{CmdSelection}))
	}()
	return done
}

func (d *selHIDDevice) cborStatus() (byte, bool) {
	resp, ok := d.probe.first(d.cid, CTAPHIDCBOR)
	if !ok || len(resp) == 0 {
		return 0, false
	}
	return resp[0], true
}

// Step 1: while Selection waits, the transport sends UP_NEEDED keepalives.
func TestSelection_HIDSendsUpNeededKeepalives(t *testing.T) {
	t.Parallel()
	d := newSelHIDDevice(t)

	done := d.sendSelection()
	d.up.waitStarted(t)
	require.Eventually(t, func() bool { return len(d.probe.keepaliveStatuses(d.cid)) >= 2 },
		5*time.Second, 10*time.Millisecond)
	for _, s := range d.probe.keepaliveStatuses(d.cid) {
		require.Equal(t, byte(KeepaliveStatusUpNeeded), s)
	}
	_, answered := d.cborStatus()
	require.False(t, answered, "Selection answered before presence")

	d.up.decide <- selDecision{approve: true}
	<-done
	status, ok := d.cborStatus()
	require.True(t, ok)
	require.Equal(t, byte(StatusOK), status)
}

// Step 5: two virtual authenticators on one host. The client sends Selection
// to both; only the touched one answers; the client then cancels the other,
// which answers CTAP2_ERR_KEEPALIVE_CANCEL.
func TestSelection_TwoAuthenticatorsOneHost(t *testing.T) {
	t.Parallel()
	touched := newSelHIDDevice(t)
	untouched := newSelHIDDevice(t)

	doneTouched := touched.sendSelection()
	doneUntouched := untouched.sendSelection()
	touched.up.waitStarted(t)
	untouched.up.waitStarted(t)

	touched.up.decide <- selDecision{approve: true}
	<-doneTouched
	status, ok := touched.cborStatus()
	require.True(t, ok)
	require.Equal(t, byte(StatusOK), status)

	// The untouched authenticator is still waiting, sending keepalives only.
	select {
	case <-doneUntouched:
		t.Fatal("untouched authenticator answered Selection")
	case <-time.After(150 * time.Millisecond):
	}
	_, answered := untouched.cborStatus()
	require.False(t, answered, "untouched authenticator answered Selection")
	require.NotEmpty(t, untouched.probe.keepaliveStatuses(untouched.cid))

	untouched.hid.HandleMessage(selHIDPacket(untouched.cid, CTAPHIDCancel, nil))
	select {
	case <-doneUntouched:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not end the untouched authenticator's Selection")
	}
	status, ok = untouched.cborStatus()
	require.True(t, ok)
	require.Equal(t, byte(StatusKeepaliveCancel), status)
}

// A CANCEL on another or unknown channel leaves the active ceremony running.
func TestCTAPHIDCancel_ScopedToCommandChannel(t *testing.T) {
	t.Parallel()
	d := newSelHIDDevice(t)
	nonce := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	d.hid.HandleMessage(selHIDPacket(CIDBroadcast, CTAPHIDInit, nonce))
	var other uint32
	d.probe.mu.Lock()
	for _, pkt := range d.probe.pkts {
		if pkt[4] == CTAPHIDInit && bytes.Equal(pkt[7:15], nonce) {
			other = binary.BigEndian.Uint32(pkt[15:19])
		}
	}
	d.probe.mu.Unlock()
	require.NotZero(t, other, "no second channel")
	require.NotEqual(t, d.cid, other)

	done := d.sendSelection()
	d.up.waitStarted(t)

	for _, cid := range []uint32{other, 0x0BADBEEF} {
		d.hid.HandleMessage(selHIDPacket(cid, CTAPHIDCancel, nil))
	}
	select {
	case <-done:
		t.Fatal("a CANCEL on another channel ended the Selection")
	case <-time.After(150 * time.Millisecond):
	}

	d.hid.HandleMessage(selHIDPacket(d.cid, CTAPHIDCancel, nil))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a CANCEL on the command's channel did not end the Selection")
	}
	status, ok := d.cborStatus()
	require.True(t, ok)
	require.Equal(t, byte(StatusKeepaliveCancel), status)
}

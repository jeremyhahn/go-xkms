// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package avr

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	aggeneric "github.com/jeremyhahn/arduino-generic/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// types.KeyProvider requires a thread-safe implementation and one AVR device is
// a single conversation over one link. These tests are the seam between the
// two.

// TestConcurrentCallsDoNotConsumeEachOthersReplies drives every command the
// backend issues from several goroutines at once.
//
// aggeneric.Device is a strict request/response client: Do takes the next
// sequence number, writes, and reads until a frame with that sequence arrives,
// dropping replies to other sequences on the way. Two goroutines inside Do at
// once therefore eat each other's answers, and AttestCert -- several Do calls
// that must stay contiguous, against a device that regenerates its pages for
// every nonce and keeps no copy -- can splice two certificates into one buffer.
//
// Run under -race, which the suite is, this also reports the unsynchronised
// reads and writes of the device's sequence counter, receive buffer and event
// list directly.
func TestConcurrentCallsDoNotConsumeEachOthersReplies(t *testing.T) {
	device := newAliasDevice(t)
	nonce := bytes.Repeat([]byte{0x5A}, aggeneric.AliasNonceLen)
	certificate := device.mint(t, nonce)

	point, _ := testPoint(t)
	link := secureElementLink().
		answer(aggeneric.CmdSysInfo, sysInfoPayload(90*time.Second, 512, aggeneric.ResetPowerOn)).
		answer(aggeneric.CmdProvInfo, provInfoPayload(bytes.Repeat([]byte{0x11}, 9), true, true)).
		answer(aggeneric.CmdProvPubKey, point).
		answerAttestCertRepeating(certificate)

	b := newTestBackend(t, link)
	attrs := &types.KeyAttributes{CN: DefaultKeyCN}

	// Each call is a different command, so a crossed reply is not merely a
	// wrong value: the SDK decodes the payload of whatever frame it kept, and
	// every one of these returns an error or the wrong answer when that
	// happens.
	calls := []struct {
		name string
		run  func() error
	}{
		{"health", func() error {
			health, err := b.Health(context.Background())
			if err == nil && health.FreeRAM != 512 {
				return &testMismatch{what: "free ram"}
			}
			return err
		}},
		{"identity", func() error {
			identity, err := b.Identity(context.Background())
			if err == nil && !identity.DataLocked {
				return &testMismatch{what: "data zone lock state"}
			}
			return err
		}},
		{"key", func() error {
			_, err := b.GetKey(context.Background(), attrs)
			return err
		}},
		{"attest", func() error {
			result, err := b.AttestKey(context.Background(), attrs, nonce)
			if err == nil && !bytes.Equal(result.(*Attestation).CertificateDER, certificate) {
				return &testMismatch{what: "alias certificate"}
			}
			return err
		}},
	}

	const rounds = 12
	errs := make(chan error, len(calls)*rounds)
	var wg sync.WaitGroup
	for _, call := range calls {
		for round := 0; round < rounds; round++ {
			wg.Add(1)
			go func(run func() error) {
				defer wg.Done()
				errs <- run()
			}(call.run)
		}
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err, "a concurrent caller was answered with someone else's reply")
	}
}

// TestRequestTimeoutExcludesQueueing pins what Backend's per-call deadline
// bounds: the call's OWN exchange with the device, not the time it spent
// waiting for another caller to finish with the wire first.
//
// The link here costs perCall on every write, and enough callers are fired at
// once that the LAST one to reach the wire waits longer than RequestTimeout
// before its own exchange even starts -- while perCall itself, the only thing
// RequestTimeout is supposed to bound, comfortably fits inside it. A backend
// that started the deadline before Lock would fail every caller the queue
// delayed past RequestTimeout; this asserts every one still succeeds.
func TestRequestTimeoutExcludesQueueing(t *testing.T) {
	const (
		perCall        = 15 * time.Millisecond
		callers        = 6
		requestTimeout = 25 * time.Millisecond
	)
	// The queue a caller can be made to wait behind is longer than
	// requestTimeout, but no single exchange is: that gap is exactly what a
	// deadline started before the wire is acquired would collapse.
	require.Greater(t, time.Duration(callers-1)*perCall, requestTimeout)
	require.Less(t, perCall, requestTimeout)

	link := &delayedLink{
		fakeLink: secureElementLink().
			answer(aggeneric.CmdSysInfo, sysInfoPayload(90*time.Second, 512, aggeneric.ResetPowerOn)),
		delay: perCall,
	}

	config := testConfig()
	config.RequestTimeout = requestTimeout

	b, err := NewBackend(context.Background(), config, aggeneric.New(link))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.Health(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err, "queueing behind other callers must not count against RequestTimeout")
	}
}

// testMismatch reports a call that returned the wrong device's answer.
type testMismatch struct{ what string }

func (e *testMismatch) Error() string {
	return "avr test: the reply carried another command's " + e.what
}

// TestRequestTimeoutBoundsTheDeviceRead is Config.RequestTimeout meaning what
// it says.
//
// Device.Do computes its read deadline from the device's own timeout and only
// notices a context BETWEEN reads, so a read that blocks runs to that deadline
// however short the context is. The link here blocks exactly like a serial
// port does: until the deadline the SDK set on it. With the configured timeout
// never reaching the device the read waits out the SDK's ten-second default,
// which is what this measures.
func TestRequestTimeoutBoundsTheDeviceRead(t *testing.T) {
	link := newStallingLink(capsPayload(
		aggeneric.CryptoSecureElement,
		aggeneric.FeatureGPIO|aggeneric.FeatureAttest,
		aggeneric.AlgECDSAP256SHA256,
	))

	// Built the way a caller who knows nothing of this backend's configuration
	// builds it: with the SDK's default deadline.
	config := testConfig()
	config.RequestTimeout = 100 * time.Millisecond

	b, err := NewBackend(context.Background(), config, aggeneric.New(link))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	link.stall()

	start := time.Now()
	_, err = b.Health(context.Background())
	elapsed := time.Since(start)

	require.Error(t, err, "a device that never answered was reported healthy")
	assert.Less(t, elapsed, 2*time.Second,
		"the read ran to the SDK's own deadline: Config.RequestTimeout never reached the device")
}

// stallingLink answers one command and then goes quiet, blocking each read
// until the deadline the SDK sets on it -- which is what a serial port does,
// and what makes the device's own timeout, rather than the caller's context,
// the thing that ends the wait.
type stallingLink struct {
	mu       sync.Mutex
	rx       bytes.Buffer
	caps     []byte
	quiet    bool
	deadline time.Time
}

func newStallingLink(caps []byte) *stallingLink {
	return &stallingLink{caps: caps}
}

// stall stops the link answering anything further.
func (l *stallingLink) stall() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.quiet = true
}

func (l *stallingLink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.quiet {
		return len(p), nil
	}
	frame, _, err := aggeneric.Decode(p)
	if err != nil {
		return 0, err
	}
	response, err := aggeneric.EncodeResponse(frame.Seq, frame.Cmd(), 0, l.caps)
	if err != nil {
		return 0, err
	}
	l.rx.Write(response)
	return len(p), nil
}

func (l *stallingLink) SetReadDeadline(deadline time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.deadline = deadline
	return nil
}

func (l *stallingLink) Read(p []byte) (int, error) {
	l.mu.Lock()
	buffered := l.rx.Len() > 0
	deadline := l.deadline
	l.mu.Unlock()

	if buffered {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.rx.Read(p)
	}
	if deadline.IsZero() {
		return 0, io.EOF
	}
	if wait := time.Until(deadline); wait > 0 {
		time.Sleep(wait)
	}
	return 0, errReadDeadline
}

// readDeadlineError is what a port reports when the read deadline passes. It
// is deliberately not io.EOF: the link is still there, it just said nothing,
// and the SDK treats the two differently.
type readDeadlineError struct{}

func (e *readDeadlineError) Error() string { return "avr test: read deadline exceeded" }

func (e *readDeadlineError) Timeout() bool { return true }

var errReadDeadline = &readDeadlineError{}

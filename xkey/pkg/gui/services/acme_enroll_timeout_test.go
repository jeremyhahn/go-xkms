package services

import (
	"context"
	"errors"
	"testing"
	"time"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// TestACMEService_EnrollDevice_EndsAtTimeout covers Codex finding 4 on PR
// #2126: x/crypto acme polls a pending order until its context ends, so the
// requested timeout must bound the whole enrollment, or the GUI holds the TPM
// accessor for as long as the server keeps the order pending. The fake client
// blocks until its context ends; with a 1 s timeout the service must return a
// deadline error within seconds, release the TPM, and a second TPM call must
// then succeed.
func TestACMEService_EnrollDevice_EndsAtTimeout(t *testing.T) {
	fx := newACMEFixture(t)
	released := fx.withTPMSource()
	fx.fake.blockEnroll = true
	req := ACMEEnrollRequest{
		Challenge:      sdkacme.ACMEChallengeTypeEnroll01,
		IPAddress:      "192.0.2.10",
		TimeoutSeconds: 1,
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := fx.svc.EnrollDevice(fx.conn, req)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("enroll err = %v, want a deadline error", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("enroll took %s with a 1 s timeout", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("enroll did not end at its timeout")
	}
	if *released != 1 {
		t.Fatalf("TPM released %d times after the timed-out enrollment, want 1", *released)
	}

	fx.fake.blockEnroll = false
	fx.fake.enrolled = &sdkacme.ACMEEnrollmentResult{IDevIDCertificate: fx.cert}
	if _, err := fx.svc.EnrollDevice(fx.conn, req); err != nil {
		t.Fatalf("second TPM call after the timeout: %v", err)
	}
	if *released != 2 {
		t.Fatalf("TPM released %d times after the second call, want 2", *released)
	}
}

// TestACMEService_EndorseDevice_EndsAtTimeout: a CA that keeps the
// endorse-01 authorization pending must not hold the shared TPM past
// TimeoutSeconds.
func TestACMEService_EndorseDevice_EndsAtTimeout(t *testing.T) {
	fx := newACMEFixture(t)
	released := fx.withTPMSource()
	fx.fake.blockEnroll = true
	req := ACMEEnrollRequest{IPAddress: "192.0.2.10", TimeoutSeconds: 1}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := fx.svc.EndorseDevice(fx.conn, req)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("endorse err = %v, want a deadline error", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("endorse took %s with a 1 s timeout", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("endorse did not end at its timeout")
	}
	if *released != 1 {
		t.Fatalf("TPM released %d times after the timed-out endorsement, want 1", *released)
	}
}

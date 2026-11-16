package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// TestACMEEnrollEndsAtTimeout covers Codex finding 4 on PR #2126: x/crypto
// acme polls a pending order until its context ends, so --timeout must bound
// the whole enrollment. The fake client blocks until its context ends; with
// --timeout 1s the command must return a deadline error within seconds and
// release the TPM module.
func TestACMEEnrollEndsAtTimeout(t *testing.T) {
	env := newACMETestEnv(t)
	tpm := stubACMETPMModule(t)
	env.fake.blockEnroll = true
	args := append([]string{"enroll", "--challenge", sdkacme.ACMEChallengeTypeEnroll01, "--ip", "192.0.2.7",
		"--timeout", "1s", "--tpm-simulator"}, env.common()...)
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := env.run(t, args...)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("enroll err = %v, want a deadline error", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("enroll took %s with --timeout 1s", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("enroll did not end at its --timeout")
	}
	if !tpm.released {
		t.Fatal("TPM module not released after the timed-out enrollment")
	}
}

// TestACMEEndorseEndsAtTimeout: a CA that keeps the endorse-01
// authorization pending must not hold `xkey acme endorse` past --timeout.
func TestACMEEndorseEndsAtTimeout(t *testing.T) {
	env := newACMETestEnv(t)
	tpm := stubACMETPMModule(t)
	env.fake.blockEnroll = true
	args := append([]string{"endorse", "--ip", "192.0.2.7", "--timeout", "1s", "--tpm-simulator"}, env.common()...)
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := env.run(t, args...)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("endorse err = %v, want a deadline error", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("endorse took %s with --timeout 1s", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("endorse did not end at its --timeout")
	}
	if !tpm.released {
		t.Fatal("TPM module not released after the timed-out endorsement")
	}
}
